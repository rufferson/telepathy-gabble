/*
 * vcard-manager.c - Source for Gabble vCard lookup helper
 *
 * Copyright (C) 2007 Collabora Ltd.
 * Copyright (C) 2006 Nokia Corporation
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "config.h"
#include "vcard-manager.h"

#include <string.h>

#include <telepathy-glib/dbus.h>
#include <telepathy-glib/heap.h>

#define DEBUG_FLAG GABBLE_DEBUG_VCARD

#include "base64.h"
#include "conn-aliasing.h"
#include "connection.h"
#include "debug.h"
#include "namespaces.h"
#include "request-pipeline.h"
#include "util.h"

static guint default_request_timeout = 180;
#define VCARD_CACHE_ENTRY_TTL 60

/* When the server reply with XMPP_ERROR_RESOURCE_CONSTRAINT, wait
 * request_wait_delay seconds before allowing a vCard request to be sent to
 * the same recipient */
static guint request_wait_delay = 5 * 60;

static const gchar *NO_ALIAS = "none";

/* signal enum */
enum
{
    NICKNAME_UPDATE,
    VCARD_UPDATE,
    GOT_SELF_INITIAL_AVATAR,
    LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = {0};

/* Properties */
enum
{
  PROP_CONNECTION = 1,
  PROP_HAVE_SELF_AVATAR,
  LAST_PROPERTY
};

G_DEFINE_TYPE(GabbleVCardManager, gabble_vcard_manager, G_TYPE_OBJECT);

typedef struct _GabbleVCardCacheEntry GabbleVCardCacheEntry;
struct _GabbleVCardManagerPrivate
{
  gboolean dispose_has_run;
  GabbleConnection *connection;

  /* TpHandle borrowed from the entry => owned (GabbleVCardCacheEntry *) */
  GHashTable *cache;

  /* Those (GabbleVCardCacheEntry *) s that have not expired, ordered by
   * increasing expiry time; borrowed from @cache */
  TpHeap *timed_cache;

  /* Timer which runs out when the first item in the @timed_cache expires */
  guint cache_timer;

  /* Things to do with my own vCard, which is somewhat special - mainly because
   * we can edit it. There's only one self_handle, so there's no point
   * bloating every cache entry with these fields. */

  gboolean have_self_avatar;

  /* Contains all the vCard fields that should be changed, using field
   * names as keys. (Maps gchar* -> gchar *). */
  GSList *edits;

  /* Used by ContactInfo.SetContactInfo in order to replace the current vcard.
   * This is needed cause there is no way to know which fields to update when
   * there are multiple fields with the same name. */
  gboolean replace_vcard;

  /* Contains RequestPipelineItem for our SET vCard request, or NULL if we
   * don't have SET request in the pipeline already. At most one SET request
   * can be in pipeline at any given time. */
  GabbleRequestPipelineItem *edit_pipeline_item;

  /* List of all pending edit requests that we got. */
  GList *edit_requests;

  /* Patched vCard that we sent to the server to update, but haven't
   * got confirmation yet. We don't want to store it in cache (visible
   * to others) before we're sure the server accepts it. */
  LmMessageNode *patched_vcard;
};

struct _GabbleVCardManagerRequest
{
  GabbleVCardManager *manager;
  GabbleVCardCacheEntry *entry;
  guint timer_id;
  guint timeout;

  GabbleVCardManagerCb callback;
  gpointer user_data;
  GObject *bound_object;
};

struct _GabbleVCardManagerEditRequest
{
  GabbleVCardManager *manager;
  GabbleVCardManagerEditCb callback;
  gpointer user_data;
  GObject *bound_object;

  /* Set if we have already patched vCard with data from this request,
   * and sent a SET request to the server to replace the vCard. */
  gboolean set_in_pipeline;
};

/* An entry in the vCard cache. These exist only as long as:
 *
 * 1) the cached message which has not yet expired; and/or
 * 2) a network request is in the pipeline; and/or
 * 3) there are requests pending.
 */
struct _GabbleVCardCacheEntry
{
  /* Parent object */
  GabbleVCardManager *manager;

  /* Referenced handle */
  TpHandle handle;

  /* Pipeline item for our <iq type="get"> if one is in progress */
  GabbleRequestPipelineItem *pipeline_item;

  /* List of (GabbleVCardManagerRequest *) borrowed from priv->requests */
  GSList *pending_requests;

  /* When requests for this entry receive an error of type "wait", we suspend
   * further requests and retry again after request_wait_delay seconds.
   * 0 if not suspended.
   */
  guint suspended_timer_id;

  /* VCard node for this entry (owned reference), or NULL if there's no node */
  LmMessageNode *vcard_node;

  /* If @vcard_node is not NULL, the time the message will expire */
  time_t expires;
};

GQuark
gabble_vcard_manager_error_quark (void)
{
  static GQuark quark = 0;
  if (!quark)
    quark = g_quark_from_static_string ("gabble-vcard-manager-error");
  return quark;
}

GQuark
gabble_vcard_manager_cache_quark (void)
{
  static GQuark quark = 0;
  if (!quark)
    quark = g_quark_from_static_string ("gabble-vcard-manager-cache");
  return quark;
}

static void cache_entry_free (void *data);
static gint cache_entry_compare (gconstpointer a, gconstpointer b);
static void manager_patch_vcard (
    GabbleVCardManager *self, LmMessageNode *vcard_node);
static void request_send (GabbleVCardManagerRequest *request,
    guint timeout);

static void
gabble_vcard_manager_init (GabbleVCardManager *obj)
{
  GabbleVCardManagerPrivate *priv =
     G_TYPE_INSTANCE_GET_PRIVATE (obj, GABBLE_TYPE_VCARD_MANAGER,
         GabbleVCardManagerPrivate);
  obj->priv = priv;

  priv->cache = g_hash_table_new_full (g_direct_hash, g_direct_equal, NULL,
      cache_entry_free);
  /* no destructor here - the hash table is responsible for freeing it */
  priv->timed_cache = tp_heap_new (cache_entry_compare, NULL);
  priv->cache_timer = 0;

  priv->have_self_avatar = FALSE;
  priv->edits = NULL;
}

static void gabble_vcard_manager_set_property (GObject *object,
    guint property_id, const GValue *value, GParamSpec *pspec);
static void gabble_vcard_manager_get_property (GObject *object,
    guint property_id, GValue *value, GParamSpec *pspec);
static void gabble_vcard_manager_dispose (GObject *object);
static void gabble_vcard_manager_finalize (GObject *object);

static void
gabble_vcard_manager_class_init (GabbleVCardManagerClass *cls)
{
  GObjectClass *object_class = G_OBJECT_CLASS (cls);
  GParamSpec *param_spec;

  g_type_class_add_private (cls, sizeof (GabbleVCardManagerPrivate));

  object_class->get_property = gabble_vcard_manager_get_property;
  object_class->set_property = gabble_vcard_manager_set_property;

  object_class->dispose = gabble_vcard_manager_dispose;
  object_class->finalize = gabble_vcard_manager_finalize;

  param_spec = g_param_spec_object ("connection", "GabbleConnection object",
      "Gabble connection object that owns this vCard lookup helper object.",
      GABBLE_TYPE_CONNECTION,
      G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS);
  g_object_class_install_property (object_class, PROP_CONNECTION, param_spec);

  param_spec = g_param_spec_boolean ("have-self-avatar", "Have our own avatar",
      "TRUE after the local user's own vCard has been retrieved in order to "
      "get their initial avatar.", FALSE,
      G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
  g_object_class_install_property (object_class, PROP_HAVE_SELF_AVATAR,
      param_spec);

  /* signal definitions */

  signals[NICKNAME_UPDATE] = g_signal_new ("nickname-update",
        G_TYPE_FROM_CLASS (cls), G_SIGNAL_RUN_LAST,
        0, NULL, NULL, g_cclosure_marshal_VOID__UINT,
        G_TYPE_NONE, 1, G_TYPE_UINT);

  signals[VCARD_UPDATE] = g_signal_new ("vcard-update",
        G_TYPE_FROM_CLASS (cls), G_SIGNAL_RUN_LAST,
        0, NULL, NULL, g_cclosure_marshal_VOID__UINT,
        G_TYPE_NONE, 1, G_TYPE_UINT);

  signals[GOT_SELF_INITIAL_AVATAR] = g_signal_new ("got-self-initial-avatar",
        G_TYPE_FROM_CLASS (cls), G_SIGNAL_RUN_LAST,
        0, NULL, NULL, g_cclosure_marshal_VOID__STRING,
        G_TYPE_NONE, 1, G_TYPE_STRING);
}

static void
gabble_vcard_manager_get_property (GObject *object,
                                   guint property_id,
                                   GValue *value,
                                   GParamSpec *pspec)
{
  GabbleVCardManager *self = GABBLE_VCARD_MANAGER (object);
  GabbleVCardManagerPrivate *priv = self->priv;

  switch (property_id) {
    case PROP_CONNECTION:
      g_value_set_object (value, priv->connection);
      break;
    case PROP_HAVE_SELF_AVATAR:
      g_value_set_boolean (value, priv->have_self_avatar);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
      break;
  }
}

static void
gabble_vcard_manager_set_property (GObject *object,
                                   guint property_id,
                                   const GValue *value,
                                   GParamSpec *pspec)
{
  GabbleVCardManager *self = GABBLE_VCARD_MANAGER (object);
  GabbleVCardManagerPrivate *priv = self->priv;

  switch (property_id) {
    case PROP_CONNECTION:
      priv->connection = g_value_get_object (value);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
      break;
  }
}

static void delete_request (GabbleVCardManagerRequest *request);
static void cancel_request (GabbleVCardManagerRequest *request);
static void cancel_all_edit_requests (GabbleVCardManager *manager);

static gint
cache_entry_compare (gconstpointer a, gconstpointer b)
{
  const GabbleVCardCacheEntry *foo = a;
  const GabbleVCardCacheEntry *bar = b;
  return foo->expires - bar->expires;
}

static void
cache_entry_free (gpointer data)
{
  GabbleVCardCacheEntry *entry = data;
  GabbleVCardManagerPrivate *priv = entry->manager->priv;
  TpHandleRepoIface *contact_repo = tp_base_connection_get_handles
      ((TpBaseConnection *) priv->connection, TP_HANDLE_TYPE_CONTACT);

  g_assert (entry != NULL);

  while (entry->pending_requests)
    {
      cancel_request (entry->pending_requests->data);
    }

  if (entry->pipeline_item)
    {
      gabble_request_pipeline_item_cancel (entry->pipeline_item);
    }

  if (entry->vcard_node)
      lm_message_node_unref (entry->vcard_node);

  tp_handle_unref (contact_repo, entry->handle);

  g_slice_free (GabbleVCardCacheEntry, entry);
}

static GabbleVCardCacheEntry *
cache_entry_get (GabbleVCardManager *manager, TpHandle handle)
{
  GabbleVCardManagerPrivate *priv = manager->priv;
  TpHandleRepoIface *contact_repo = tp_base_connection_get_handles (
      (TpBaseConnection *) priv->connection, TP_HANDLE_TYPE_CONTACT);
  GabbleVCardCacheEntry *entry;

  entry = g_hash_table_lookup (priv->cache, GUINT_TO_POINTER (handle));
  if (entry)
     return entry;

  entry  = g_slice_new0 (GabbleVCardCacheEntry);

  entry->manager = manager;
  entry->handle = handle;
  tp_handle_ref (contact_repo, handle);
  g_hash_table_insert (priv->cache, GUINT_TO_POINTER (handle), entry);

  return entry;
}

static gboolean
cache_entry_timeout (gpointer data)
{
  GabbleVCardManager *manager = data;
  GabbleVCardManagerPrivate *priv = manager->priv;
  GabbleVCardCacheEntry *entry;

  time_t now = time (NULL);

  while (NULL != (entry = tp_heap_peek_first (priv->timed_cache)))
    {
      if (entry->expires > now)
          break;

      /* shouldn't have in-flight request nor any pending requests */
      g_assert (entry->pipeline_item == NULL);

      gabble_vcard_manager_invalidate_cache (manager, entry->handle);
    }

  priv->cache_timer = 0;

  if (entry)
    {
      priv->cache_timer = g_timeout_add_seconds (
          entry->expires - time (NULL), cache_entry_timeout, manager);
    }

  return FALSE;
}


static void
cache_entry_attempt_to_free (GabbleVCardCacheEntry *entry)
{
  GabbleVCardManagerPrivate *priv = entry->manager->priv;
  TpBaseConnection *base = (TpBaseConnection *) priv->connection;

  if (entry->vcard_node != NULL)
    {
      DEBUG ("Not freeing vCard cache entry %p: it has a cached vCard %p",
          entry, entry->vcard_node);
      return;
    }

  if (entry->pipeline_item != NULL)
    {
      DEBUG ("Not freeing vCard cache entry %p: it has a pipeline_item %p",
          entry, entry->pipeline_item);
      return;
    }

  if (entry->pending_requests != NULL)
    {
      DEBUG ("Not freeing vCard cache entry %p: it has pending requests",
          entry);
      return;
    }

  /* If there is a suspended request, it must be in entry-> pending_requests
   */
  g_assert (entry->suspended_timer_id == 0);

  if (entry->handle == base->self_handle)
    {
      /* if we do have some pending edits, we should also have
       * some pipeline items or pending requests */
      g_assert (priv->edit_pipeline_item || priv->edits == NULL);
    }

  tp_heap_remove (priv->timed_cache, entry);

  g_hash_table_remove (priv->cache, GUINT_TO_POINTER (entry->handle));
}

void
gabble_vcard_manager_invalidate_cache (GabbleVCardManager *manager,
                                       TpHandle handle)
{
  GabbleVCardManagerPrivate *priv = manager->priv;
  GabbleVCardCacheEntry *entry = g_hash_table_lookup (priv->cache,
      GUINT_TO_POINTER (handle));
  TpHandleRepoIface *contact_repo = tp_base_connection_get_handles (
      (TpBaseConnection *) priv->connection, TP_HANDLE_TYPE_CONTACT);

  g_return_if_fail (tp_handle_is_valid (contact_repo, handle, NULL));

  if (!entry)
      return;

  tp_heap_remove (priv->timed_cache, entry);

  if (entry->vcard_node)
    {
      lm_message_node_unref (entry->vcard_node);
      entry->vcard_node = NULL;
    }

  cache_entry_attempt_to_free (entry);
}

static void complete_one_request (GabbleVCardManagerRequest *request,
    LmMessageNode *vcard_node, GError *error);

static void
cache_entry_complete_requests (GabbleVCardCacheEntry *entry, GError *error)
{
  GSList *cur, *tmp;

  tmp = g_slist_copy (entry->pending_requests);

  for (cur = tmp; cur != NULL; cur = cur->next)
    {
      GabbleVCardManagerRequest *request = cur->data;

      complete_one_request (request, error ? NULL : entry->vcard_node, error);
    }

  g_slist_free (tmp);
}

static void
complete_one_request (GabbleVCardManagerRequest *request,
                      LmMessageNode *vcard_node,
                      GError *error)
{
  if (request->callback)
    {
      (request->callback) (request->manager, request, request->entry->handle,
          vcard_node, error, request->user_data);
    }

  delete_request (request);
}

static void
disconnect_entry_foreach (gpointer handle, gpointer value, gpointer unused)
{
  GError err = { TP_ERRORS, TP_ERROR_DISCONNECTED, "Connection closed" };
  GabbleVCardCacheEntry *entry = value;

  if (entry->suspended_timer_id)
    {
      g_source_remove (entry->suspended_timer_id);
      entry->suspended_timer_id = 0;
    }

  cache_entry_complete_requests (entry, &err);

  if (entry->pipeline_item)
    {
      gabble_request_pipeline_item_cancel (entry->pipeline_item);
      entry->pipeline_item = NULL;
    }
}

static void
gabble_vcard_manager_dispose (GObject *object)
{
  GabbleVCardManager *self = GABBLE_VCARD_MANAGER (object);
  GabbleVCardManagerPrivate *priv = self->priv;

  if (priv->dispose_has_run)
    return;

  priv->dispose_has_run = TRUE;
  DEBUG ("%p", object);

  if (priv->edits != NULL) {
      g_slist_foreach (priv->edits, (GFunc) gabble_vcard_manager_edit_info_free,
          NULL);
      g_slist_free (priv->edits);
  }
  priv->edits = NULL;

  if (priv->cache_timer)
      g_source_remove (priv->cache_timer);

  g_hash_table_foreach (priv->cache, disconnect_entry_foreach, NULL);

  tp_heap_destroy (priv->timed_cache);
  g_hash_table_destroy (priv->cache);

  if (priv->edit_pipeline_item)
      gabble_request_pipeline_item_cancel (priv->edit_pipeline_item);

  cancel_all_edit_requests (self);

  if (G_OBJECT_CLASS (gabble_vcard_manager_parent_class)->dispose)
    G_OBJECT_CLASS (gabble_vcard_manager_parent_class)->dispose (object);
}

static void
gabble_vcard_manager_finalize (GObject *object)
{
  DEBUG ("%p", object);
  G_OBJECT_CLASS (gabble_vcard_manager_parent_class)->finalize (object);
}

gchar *
vcard_get_avatar_sha1 (LmMessageNode *vcard)
{
  gchar *sha1;
  const gchar *binval_value;
  GString *avatar;
  LmMessageNode *node;
  LmMessageNode *binval;

  node = lm_message_node_get_child (vcard, "PHOTO");

  if (!node)
    return g_strdup ("");

  DEBUG ("Our vCard has a PHOTO %p", node);
  binval = lm_message_node_get_child (node, "BINVAL");

  if (!binval)
    return g_strdup ("");

  binval_value = lm_message_node_get_value (binval);

  if (!binval_value)
    return g_strdup ("");

  avatar = base64_decode (binval_value);

  if (avatar)
    {
      sha1 = sha1_hex (avatar->str, avatar->len);
      g_string_free (avatar, TRUE);
      DEBUG ("Successfully decoded PHOTO.BINVAL, SHA-1 %s", sha1);
    }
  else
    {
      DEBUG ("Avatar is in garbled Base64, ignoring it!");
      sha1 = g_strdup ("");
    }

  return sha1;
}

/* Called during connection. */
static void
initial_request_cb (GabbleVCardManager *self,
                    GabbleVCardManagerRequest *request,
                    TpHandle handle,
                    LmMessageNode *vcard,
                    GError *error,
                    gpointer user_data)
{
  GabbleVCardManagerPrivate *priv = self->priv;
  gchar *alias = user_data;
  gchar *sha1;

  if (vcard)
    {
      /* We now have our own avatar (or lack thereof) so can answer
       * GetAvatarTokens([self_handle])
       */
      priv->have_self_avatar = TRUE;

      /* Do we have an avatar already? If so, the presence cache ought to be
       * told (anyone else's avatar SHA-1 we'd get from their presence,
       * but unless we have another XEP-0153 resource connected, we never
       * see our own presence)
       */
      sha1 = vcard_get_avatar_sha1 (vcard);
      g_signal_emit (self, signals[GOT_SELF_INITIAL_AVATAR], 0, sha1);
      g_free (sha1);
    }

  g_free (alias);
}

static void
status_changed_cb (GObject *object,
                   guint status,
                   guint reason,
                   gpointer user_data)
{
  GabbleVCardManager *self = GABBLE_VCARD_MANAGER (user_data);
  GabbleVCardManagerPrivate *priv = self->priv;
  GabbleConnection *conn = GABBLE_CONNECTION (object);
  TpBaseConnection *base = (TpBaseConnection *) conn;

  if (status == TP_CONNECTION_STATUS_CONNECTED)
    {
      gchar *alias;
      GabbleConnectionAliasSource alias_src;

      /* if we have a better alias, patch it into our vCard on the server */
      alias_src = _gabble_connection_get_cached_alias (conn,
                                                       base->self_handle,
                                                       &alias);
      if (alias_src >= GABBLE_CONNECTION_ALIAS_FROM_VCARD)
        priv->edits = g_slist_append (priv->edits,
            gabble_vcard_manager_edit_info_new ("NICKNAME", alias,
                FALSE, FALSE, NULL));

      g_free (alias);

      /* FIXME: we happen to know that synchronous errors can't happen */
      gabble_vcard_manager_request (self, base->self_handle, 0,
          initial_request_cb, NULL, (GObject *) self);
    }
}

/**
 * gabble_vcard_manager_new:
 * @conn: The #GabbleConnection to use for vCard lookup
 *
 * Creates an object to use for Jabber vCard lookup (JEP 0054).
 * There should be one of these per connection
 */
GabbleVCardManager *
gabble_vcard_manager_new (GabbleConnection *conn)
{
  GabbleVCardManager *self;

  g_return_val_if_fail (GABBLE_IS_CONNECTION (conn), NULL);

  self = GABBLE_VCARD_MANAGER (g_object_new (GABBLE_TYPE_VCARD_MANAGER,
        "connection", conn, NULL));
  g_signal_connect (conn, "status-changed",
                    G_CALLBACK (status_changed_cb), self);
  return self;
}

static void notify_delete_request (gpointer data, GObject *obj);
static void notify_delete_edit_request (gpointer data, GObject *obj);

static void
delete_request (GabbleVCardManagerRequest *request)
{
  GabbleVCardManager *manager = request->manager;

  DEBUG ("Discarding request %p", request);

  g_assert (NULL != request);
  g_assert (NULL != manager);
  g_assert (NULL != request->entry);
  g_assert (GABBLE_IS_VCARD_MANAGER (manager));

  /* poison the request, so assertions about it will fail if there's a
   * dangling reference */
  request->manager = NULL;

  request->entry->pending_requests = g_slist_remove
      (request->entry->pending_requests, request);
  cache_entry_attempt_to_free (request->entry);

  if (NULL != request->bound_object)
    {
      g_object_weak_unref (request->bound_object, notify_delete_request,
          request);
    }

  if (0 != request->timer_id)
    {
      g_source_remove (request->timer_id);
    }

  g_slice_free (GabbleVCardManagerRequest, request);
}

static gboolean
timeout_request (gpointer data)
{
  GabbleVCardManagerRequest *request = (GabbleVCardManagerRequest *) data;

  g_return_val_if_fail (data != NULL, FALSE);
  DEBUG ("Request %p timed out, notifying callback %p",
         request, request->callback);

  request->timer_id = 0;

  /* The pipeline machinery will call our callback with the error "canceled"
   */
  gabble_request_pipeline_item_cancel (request->entry->pipeline_item);

  return FALSE;
}

static void
cancel_request (GabbleVCardManagerRequest *request)
{
  GError err = { GABBLE_VCARD_MANAGER_ERROR,
      GABBLE_VCARD_MANAGER_ERROR_CANCELLED, "Request cancelled" };

  g_assert (request != NULL);

  DEBUG ("Request %p cancelled, notifying callback %p",
         request, request->callback);

  complete_one_request (request, NULL, &err);
}

static gchar *
extract_nickname (LmMessageNode *vcard_node)
{
  LmMessageNode *node;
  const gchar *nick;
  gchar **bits;
  gchar *ret;

  node = lm_message_node_get_child (vcard_node, "NICKNAME");

  if (node == NULL)
    return NULL;

  nick = lm_message_node_get_value (node);

  /* nick is comma-separated, we want the first one. rule out corner cases of
   * the entire string or the first value being empty before we g_strsplit */
  if (nick == NULL || *nick == '\0' || *nick == ',')
    return NULL;

  bits = g_strsplit (nick, ",", 2);

  ret = g_strdup (bits[0]);

  g_strfreev (bits);

  return ret;
}

static void
observe_vcard (GabbleConnection *conn,
               GabbleVCardManager *manager,
               TpHandle handle,
               LmMessageNode *vcard_node)
{
  TpHandleRepoIface *contact_repo = tp_base_connection_get_handles (
      (TpBaseConnection *) conn, TP_HANDLE_TYPE_CONTACT);
  const gchar *field = "<NICKNAME>";
  gchar *alias;
  const gchar *old_alias;

  alias = extract_nickname (vcard_node);

  if (alias == NULL)
    {
      LmMessageNode *fn_node = lm_message_node_get_child (vcard_node, "FN");

      if (fn_node != NULL)
        {
          const gchar *fn = lm_message_node_get_value (fn_node);

          if (fn != NULL && *fn != '\0')
            {
              field = "<FN>";
              alias = g_strdup (fn);
            }
        }
    }

  old_alias = gabble_vcard_manager_get_cached_alias (manager, handle);

  if (old_alias != NULL && !tp_strdiff (old_alias, alias))
    {
      DEBUG ("no change to vCard alias \"%s\" for handle %u", alias, handle);

      g_free (alias);
      return;
    }

  if (alias != NULL)
    {
      DEBUG ("got vCard alias \"%s\" for handle %u from %s", alias,
          handle, field);

      /* takes ownership of alias */
      tp_handle_set_qdata (contact_repo, handle,
          gabble_vcard_manager_cache_quark (), alias, g_free);
    }
  else
    {
      DEBUG ("got no vCard alias for handle %u", handle);

      tp_handle_set_qdata (contact_repo, handle,
          gabble_vcard_manager_cache_quark (), (gchar *) NO_ALIAS, NULL);
    }

  if ((old_alias != NULL) || (alias != NULL))
      g_signal_emit (G_OBJECT (manager), signals[NICKNAME_UPDATE], 0, handle);

  g_signal_emit (G_OBJECT (manager), signals[VCARD_UPDATE], 0, handle);
}

/* Called when a pre-set get request failed, or when a set request succeeded
 * or failed.
 */
static void
replace_reply_cb (GabbleConnection *conn,
                  LmMessage *reply_msg,
                  gpointer user_data,
                  GError *error)
{
  GabbleVCardManager *self = GABBLE_VCARD_MANAGER (user_data);
  GabbleVCardManagerPrivate *priv = self->priv;
  TpBaseConnection *base = (TpBaseConnection *) conn;
  GList *li;
  LmMessageNode *node = NULL;

  /* If we sent a SET request, it's dead now. */
  priv->edit_pipeline_item = NULL;

  DEBUG ("called: %s error", (error) ? "some" : "no");

  if (error)
    {
      /* We won't need our patched vcard after all */
      if (priv->patched_vcard != NULL)
          lm_message_node_unref (priv->patched_vcard);

      priv->patched_vcard = NULL;
    }
  else
    {
      GabbleVCardCacheEntry *entry = cache_entry_get (self, base->self_handle);

      /* We must have patched vcard by now */
      g_assert (priv->patched_vcard != NULL);

      /* Finally we may put the new vcard in the cache. */
      if (entry->vcard_node)
          lm_message_node_unref (entry->vcard_node);

      entry->vcard_node = priv->patched_vcard;
      priv->patched_vcard = NULL;

      /* observe it so we pick up alias updates */
      observe_vcard (conn, self, base->self_handle, entry->vcard_node);

      node = entry->vcard_node;
    }

  /* Scan all edit requests, call and remove ones whose data made it
   * into SET request that just returned. */
  li = priv->edit_requests;
  while (li)
    {
      GabbleVCardManagerEditRequest *req = li->data;
      li = g_list_next (li);
      if (req->set_in_pipeline || error)
        {
          if (req->callback)
            {
              (req->callback) (req->manager, req, node, error, req->user_data);
            }

          gabble_vcard_manager_remove_edit_request (req);
        }
    }

  if (error != NULL)
    {
      if (priv->edits != NULL)
        {
          /* All the requests for these edits have just been cancelled. */
          g_slist_foreach (priv->edits,
              (GFunc) gabble_vcard_manager_edit_info_free, NULL);
          g_slist_free (priv->edits);
          priv->edits = NULL;
        }
    }
  else
    {
      /* If we've received more edit requests in the meantime, send them off.
       */
      manager_patch_vcard (self, node);
    }
}

static void
patch_vcard_node_foreach (gpointer k, gpointer v, gpointer user_data)
{
  gchar *key = k;
  gchar *value = v;
  LmMessageNode *node = user_data;
  LmMessageNode *child_node;

  child_node = lm_message_node_get_child (node, key);
  if (child_node)
    lm_message_node_set_value (child_node, value);
  else
    lm_message_node_add_child (node, key, value);
}

static void
patch_vcard_foreach (gpointer data, gpointer user_data)
{
  GabbleVCardManagerEditInfo *info = data;
  LmMessageNode *vcard_node = user_data;
  LmMessageNode *node;

  node = lm_message_node_get_child (vcard_node, info->element_name);
  if (info->to_del)
    {
      while (node)
        {
          if (node)
            {
              lm_message_node_unlink (node, vcard_node);
              lm_message_node_unref (node);
            }
          node = lm_message_node_get_child (vcard_node, info->element_name);
        }
      return;
    }

  if (node && !info->accept_multiple)
    lm_message_node_set_value (node, info->element_value);
  else
    node = lm_message_node_add_child (vcard_node,
        info->element_name, info->element_value);

  if (info->to_edit)
    g_hash_table_foreach (info->to_edit, patch_vcard_node_foreach, node);
}

/* Loudmouth hates me. The feelings are mutual.
 *
 * Note that this function doesn't copy any attributes other than
 * xmlns, because LM provides no way to iterate over attributes. Thanks, LM. */
static LmMessageNode *
vcard_copy (LmMessageNode *parent, LmMessageNode *src)
{
    LmMessageNode *new = lm_message_node_add_child (parent, src->name,
        lm_message_node_get_value (src));
    const gchar *xmlns;
    NodeIter i;

    xmlns = lm_message_node_get_attribute (src, "xmlns");
    if (xmlns != NULL)
      lm_message_node_set_attribute (new, "xmlns", xmlns);

    for (i = node_iter (src); i; i = node_iter_next (i))
      vcard_copy (new, node_iter_data (i));

    return new;
}

static void
manager_patch_vcard (GabbleVCardManager *self,
                     LmMessageNode *vcard_node)
{
  GabbleVCardManagerPrivate *priv = self->priv;
  LmMessage *msg;
  LmMessageNode *patched_vcard;
  GList *li;

  /* Bail out if we don't have outstanding edits to make, or if we already
   * have a set request in progress.
   */
  if (priv->edits == NULL || priv->edit_pipeline_item != NULL)
      return;

  DEBUG("patching vcard");

  msg = lm_message_new_with_sub_type (NULL, LM_MESSAGE_TYPE_IQ,
      LM_MESSAGE_SUB_TYPE_SET);

  if (priv->replace_vcard)
    {
      LmMessageNode *node;

      patched_vcard = lm_message_node_add_child (msg->node, "vCard", "");
      lm_message_node_set_attribute (patched_vcard, "xmlns", "vcard-temp");

      /* let's special case PHOTO here, as we don't parse PHOTO in contact-info,
       * so replacing the PHOTO here wouldn't be correct */
      node = lm_message_node_get_child (vcard_node, "PHOTO");
      if (node)
        vcard_copy (patched_vcard, node);
    }
  else
    patched_vcard = vcard_copy (msg->node, vcard_node);

  /* Apply any unsent edits to the patched vCard */
  g_slist_foreach (priv->edits, patch_vcard_foreach, patched_vcard);

  /* We'll save the patched vcard, and if the server says
   * we're ok, put it into the cache. But we want to leave the
   * original vcard in the cache until that happens. */
  priv->patched_vcard = lm_message_node_ref (patched_vcard);

  priv->edit_pipeline_item = gabble_request_pipeline_enqueue (
      priv->connection->req_pipeline, msg, default_request_timeout,
      replace_reply_cb, self);

  lm_message_unref (msg);

  /* We've applied those, forget about them */
  g_slist_foreach (priv->edits, (GFunc) gabble_vcard_manager_edit_info_free,
      NULL);
  g_slist_free (priv->edits);
  priv->edits = NULL;
  priv->replace_vcard = FALSE;

  /* Current edit requests are in the pipeline, remember it so we
   * know which ones we may complete when the SET returns */
  for (li = priv->edit_requests; li; li = g_list_next (li))
    {
      GabbleVCardManagerEditRequest *edit = (GabbleVCardManagerEditRequest *) li->data;
      edit->set_in_pipeline = TRUE;
    }
}

static gboolean
suspended_request_timeout_cb (gpointer data)
{
  GabbleVCardManagerRequest *request = data;

  /* Send the request again */
  request->entry->suspended_timer_id = 0;
  request_send (request, request->timeout);

  return FALSE;
}

/* Called when a GET request in the pipeline has either succeeded or failed. */
static void
pipeline_reply_cb (GabbleConnection *conn,
                   LmMessage *reply_msg,
                   gpointer user_data,
                   GError *error)
{
  GabbleVCardManagerRequest *request = user_data;
  GabbleVCardCacheEntry *entry = request->entry;
  GabbleVCardManager *self = GABBLE_VCARD_MANAGER (entry->manager);
  GabbleVCardManagerPrivate *priv = self->priv;
  TpBaseConnection *base = (TpBaseConnection *) conn;
  TpHandleRepoIface *contact_repo =
      tp_base_connection_get_handles (base, TP_HANDLE_TYPE_CONTACT);
  LmMessageNode *vcard_node = NULL;

  DEBUG("called for entry %p", entry);

  g_assert (tp_handle_is_valid (contact_repo, entry->handle, NULL));

  g_assert (entry->pipeline_item != NULL);
  g_assert (entry->suspended_timer_id == 0);

  entry->pipeline_item = NULL;

  if (error)
    {
      /* First, handle the error "wait": suspend the request and replay it
       * later */
      LmMessageNode *error_node = NULL;
      GabbleXmppError xmpp_error = XMPP_ERROR_UNDEFINED_CONDITION;
      GabbleXmppErrorType error_type = XMPP_ERROR_UNDEFINED_CONDITION;

      /* FIXME: add a helper in error.c to extract the type, error, and message
       *        from an XMPP stanza.
       */
      if (reply_msg != NULL)
        error_node = lm_message_node_get_child (reply_msg->node, "error");

      if (error_node != NULL)
        xmpp_error = gabble_xmpp_error_from_node (error_node, &error_type);

      if (error_type == XMPP_ERROR_TYPE_WAIT)
        {
          DEBUG ("Retrieving %u's vCard returned a temporary <%s/> error; "
              "trying againg in %u seconds", entry->handle,
              gabble_xmpp_error_string (xmpp_error), request_wait_delay);

          g_source_remove (request->timer_id);
          request->timer_id = 0;

          entry->suspended_timer_id = g_timeout_add_seconds (
              request_wait_delay, suspended_request_timeout_cb, request);

          return;
        }

      /* If request for our own vCard failed, and we do have
       * pending edits to make, cancel those and return error
       * to the user */
      if (entry->handle == base->self_handle && priv->edits != NULL)
        {
          /* We won't have a chance to apply those, might as well forget them */
          g_slist_foreach (priv->edits,
              (GFunc) gabble_vcard_manager_edit_info_free, NULL);
          g_slist_free (priv->edits);
          priv->edits = NULL;

          replace_reply_cb (conn, reply_msg, self, error);
        }

      /* Complete pending GET requests */
      cache_entry_complete_requests (entry, error);
      return;
    }

  g_assert (reply_msg != NULL);

  vcard_node = lm_message_node_get_child (reply_msg->node, "vCard");

  if (NULL == vcard_node)
    {
      /* We need a vCard node for the current API */
      DEBUG ("successful lookup response contained no <vCard> node, "
          "creating an empty one");

      vcard_node = lm_message_node_add_child (reply_msg->node, "vCard",
          NULL);
      lm_message_node_set_attribute (vcard_node, "xmlns", NS_VCARD_TEMP);
    }

  /* Put the message in the cache */
  entry->vcard_node = lm_message_node_ref (vcard_node);

  entry->expires = time (NULL) + VCARD_CACHE_ENTRY_TTL;
  tp_heap_add (priv->timed_cache, entry);
  if (priv->cache_timer == 0)
    {
      GabbleVCardCacheEntry *first =
          tp_heap_peek_first (priv->timed_cache);

      priv->cache_timer = g_timeout_add_seconds (
          first->expires - time (NULL), cache_entry_timeout, self);
    }

  /* We have freshly updated cache for our vCard, edit it if
   * there are any pending edits and no outstanding set request.
   */
  if (entry->handle == base->self_handle)
    {
      manager_patch_vcard (self, vcard_node);
    }

  /* Observe the vCard as it goes past */
  observe_vcard (priv->connection, self, entry->handle, vcard_node);

  /* Complete all pending requests successfully */
  cache_entry_complete_requests (entry, NULL);
}

static void
notify_delete_request (gpointer data, GObject *obj)
{
  GabbleVCardManagerRequest *request = data;

  request->bound_object = NULL;
  delete_request (request);
}

static void
request_send (GabbleVCardManagerRequest *request, guint timeout)
{
  GabbleVCardCacheEntry *entry = request->entry;
  GabbleConnection *conn = entry->manager->priv->connection;
  TpBaseConnection *base = (TpBaseConnection *) conn;
  TpHandleRepoIface *contact_repo = tp_base_connection_get_handles (base,
      TP_HANDLE_TYPE_CONTACT);

  g_assert (request->timer_id == 0);

  if (entry->pipeline_item)
    {
      DEBUG ("adding to cache entry %p with <iq> already pending", entry);
    }
  else if (entry->suspended_timer_id != 0)
    {
      DEBUG ("adding to cache entry %p with <iq> suspended", entry);
    }
  else
    {
      const char *jid;
      LmMessage *msg;

      request->timer_id =
          g_timeout_add_seconds (request->timeout, timeout_request, request);

      if (entry->handle == base->self_handle)
        {
          DEBUG ("Cache entry %p is my own, not setting @to", entry);
          jid = NULL;
        }
      else
        {
          jid = tp_handle_inspect (contact_repo, entry->handle);
          DEBUG ("Cache entry %p is not mine, @to = %s", entry, jid);
        }

      msg = lm_message_build_with_sub_type (jid,
          LM_MESSAGE_TYPE_IQ, LM_MESSAGE_SUB_TYPE_GET,
          '(', "vCard", "",
              '@', "xmlns", NS_VCARD_TEMP,
          ')',
          NULL);

      entry->pipeline_item = gabble_request_pipeline_enqueue (
          conn->req_pipeline, msg, timeout, pipeline_reply_cb, request);

      lm_message_unref (msg);

      DEBUG ("adding request to cache entry %p and queueing the <iq>", entry);
    }
}

/* Request the vCard for the given handle. When it arrives, call the given
 * callback.
 *
 * The callback may be NULL if you just want the side-effect of this
 * operation, which is to update the cached alias.
 *
 * FIXME: the timeout is not always obeyed when there is already a request
 *        on the same handle. It should perhaps be removed.
 */
GabbleVCardManagerRequest *
gabble_vcard_manager_request (GabbleVCardManager *self,
                              TpHandle handle,
                              guint timeout,
                              GabbleVCardManagerCb callback,
                              gpointer user_data,
                              GObject *object)
{
  GabbleVCardManagerPrivate *priv = self->priv;
  TpBaseConnection *connection = (TpBaseConnection *) priv->connection;
  TpHandleRepoIface *contact_repo = tp_base_connection_get_handles (
      connection, TP_HANDLE_TYPE_CONTACT);
  GabbleVCardManagerRequest *request;
  GabbleVCardCacheEntry *entry = cache_entry_get (self, handle);

  g_return_val_if_fail (tp_handle_is_valid (contact_repo, handle, NULL), NULL);
  g_assert (entry->vcard_node == NULL);

  if (timeout == 0)
    timeout = default_request_timeout;

  request = g_slice_new0 (GabbleVCardManagerRequest);
  DEBUG ("Created request %p to retrieve <%u>'s vCard", request, handle);
  request->timeout = timeout;
  request->manager = self;
  request->entry = entry;
  request->callback = callback;
  request->user_data = user_data;
  request->bound_object = object;

  if (NULL != object)
    g_object_weak_ref (object, notify_delete_request, request);

  request->entry->pending_requests = g_slist_prepend
      (request->entry->pending_requests, request);

  request_send (request, timeout);
  return request;
}

GabbleVCardManagerEditRequest *
gabble_vcard_manager_edit (GabbleVCardManager *self,
                           guint timeout,
                           GabbleVCardManagerEditCb callback,
                           gpointer user_data,
                           GObject *object,
                           size_t n_pairs,
                           ...)
{
  va_list ap;
  size_t i;
  GSList *edits = NULL;

  va_start (ap, n_pairs);
  for (i = 0; i < n_pairs; i++)
    {
      GabbleVCardManagerEditInfo *info = gabble_vcard_manager_edit_info_new (
          va_arg (ap, const gchar *),
          va_arg (ap, const gchar *),
          FALSE, FALSE, NULL);

      if (info->element_value)
        DEBUG ("%s => value of length %ld starting %.30s", info->element_name,
            (long) strlen (info->element_value), info->element_value);
      else
        DEBUG ("%s => null value", info->element_name);
      edits = g_slist_append (edits, info);
    }
  va_end (ap);

  return gabble_vcard_manager_edit_extended (self, timeout, callback,
      user_data, object, edits, FALSE);
}

GabbleVCardManagerEditRequest *
gabble_vcard_manager_edit_extended (GabbleVCardManager *self,
                                    guint timeout,
                                    GabbleVCardManagerEditCb callback,
                                    gpointer user_data,
                                    GObject *object,
                                    GSList *edits,
                                    gboolean replace_vcard)
{
  GabbleVCardManagerPrivate *priv = self->priv;
  TpBaseConnection *base = (TpBaseConnection *) priv->connection;
  GabbleVCardManagerEditRequest *req;
  GabbleVCardCacheEntry *entry;

  /* Invalidate our current vCard and ensure that we're going to get
   * it in the near future */
  DEBUG ("called; invalidating cache");
  gabble_vcard_manager_invalidate_cache (self, base->self_handle);
  DEBUG ("checking if we have pending requests already");
  entry = cache_entry_get (self, base->self_handle);
  if (!priv->edit_pipeline_item && !entry->pending_requests)
    {
      DEBUG ("we don't, create one");
      /* create dummy GET request if neccessary */
      gabble_vcard_manager_request (self, base->self_handle, 0, NULL,
          NULL, NULL);
    }

  /* set it to true and let manager_patch_vcard set it to FALSE when finished */
  if (replace_vcard)
    {
      priv->replace_vcard = TRUE;
      g_slist_foreach (priv->edits, (GFunc) gabble_vcard_manager_edit_info_free,
          NULL);
      g_slist_free (priv->edits);
      priv->edits = edits;
    }
  else
    priv->edits = g_slist_concat (priv->edits, edits);

  req = g_slice_new (GabbleVCardManagerEditRequest);
  req->manager = self;
  req->callback = callback;
  req->user_data = user_data;
  req->set_in_pipeline = FALSE;
  req->bound_object = object;

  if (NULL != object)
    g_object_weak_ref (object, notify_delete_edit_request, req);

  priv->edit_requests = g_list_append (priv->edit_requests, req);
  return req;
}

void
gabble_vcard_manager_remove_edit_request (GabbleVCardManagerEditRequest *request)
{
  GabbleVCardManagerPrivate *priv = request->manager->priv;

  DEBUG("request == %p", request);

  g_return_if_fail (request != NULL);
  g_assert (NULL != g_list_find (priv->edit_requests, request));

  if (request->bound_object)
      g_object_weak_unref (request->bound_object, notify_delete_edit_request,
          request);

  g_slice_free (GabbleVCardManagerEditRequest, request);
  priv->edit_requests = g_list_remove (priv->edit_requests, request);
}

static void
notify_delete_edit_request (gpointer data, GObject *obj)
{
  GabbleVCardManagerEditRequest *request = data;

  DEBUG("request == %p", request);

  request->bound_object = NULL;
  gabble_vcard_manager_remove_edit_request (request);
}

static void
cancel_all_edit_requests (GabbleVCardManager *self)
{
  GabbleVCardManagerPrivate *priv = self->priv;
  GError cancelled = { GABBLE_VCARD_MANAGER_ERROR,
      GABBLE_VCARD_MANAGER_ERROR_CANCELLED,
      "Request cancelled" };

  while (priv->edit_requests)
    {
      GabbleVCardManagerEditRequest *req = priv->edit_requests->data;
      if (req->callback)
        {
          (req->callback) (req->manager, req, NULL,
              &cancelled, req->user_data);
        }

      gabble_vcard_manager_remove_edit_request (req);
    }
}


void
gabble_vcard_manager_cancel_request (GabbleVCardManager *self,
                                     GabbleVCardManagerRequest *request)
{
  g_return_if_fail (GABBLE_IS_VCARD_MANAGER (self));
  g_return_if_fail (NULL != request);
  g_return_if_fail (self == request->manager);

  cancel_request (request);
}

/**
 * Return cached message for the handle's vCard if it's available.
 */
gboolean
gabble_vcard_manager_get_cached (GabbleVCardManager *self,
                                 TpHandle handle,
                                 LmMessageNode **node)
{
  GabbleVCardManagerPrivate *priv = self->priv;
  GabbleVCardCacheEntry *entry = g_hash_table_lookup (priv->cache,
      GUINT_TO_POINTER (handle));
  TpHandleRepoIface *contact_repo = tp_base_connection_get_handles (
      (TpBaseConnection *) priv->connection, TP_HANDLE_TYPE_CONTACT);

  g_return_val_if_fail (tp_handle_is_valid (contact_repo, handle, NULL),
      FALSE);

  if ((entry == NULL) || (entry->vcard_node == NULL))
      return FALSE;

  if (node != NULL)
      *node = entry->vcard_node;

  return TRUE;
}

/**
 * Return the cached alias derived from the vCard for the given handle,
 * if any. If there is no cached alias, return NULL.
 */
const gchar *
gabble_vcard_manager_get_cached_alias (GabbleVCardManager *self,
                                       TpHandle handle)
{
  GabbleVCardManagerPrivate *priv;
  TpHandleRepoIface *contact_repo;
  const gchar *s;

  g_return_val_if_fail (GABBLE_IS_VCARD_MANAGER (self), NULL);

  priv = self->priv;
  contact_repo = tp_base_connection_get_handles (
      (TpBaseConnection *) priv->connection, TP_HANDLE_TYPE_CONTACT);

  g_return_val_if_fail (tp_handle_is_valid (contact_repo, handle, NULL), NULL);

  s = tp_handle_get_qdata (contact_repo, handle,
      gabble_vcard_manager_cache_quark ());

  if (s == NO_ALIAS)
    s = NULL;

  return s;
}

/**
 * Return TRUE if we've tried looking up an alias for this handle before.
 */
gboolean
gabble_vcard_manager_has_cached_alias (GabbleVCardManager *self,
                                       TpHandle handle)
{
  GabbleVCardManagerPrivate *priv;
  TpHandleRepoIface *contact_repo;
  gpointer p;

  g_return_val_if_fail (GABBLE_IS_VCARD_MANAGER (self), FALSE);

  priv = self->priv;
  contact_repo = tp_base_connection_get_handles (
      (TpBaseConnection *) priv->connection, TP_HANDLE_TYPE_CONTACT);

  g_return_val_if_fail (tp_handle_is_valid (contact_repo, handle, NULL),
      FALSE);

  p = tp_handle_get_qdata (contact_repo, handle,
      gabble_vcard_manager_cache_quark ());

  return p != NULL;
}

/* For unit tests only */
void
gabble_vcard_manager_set_suspend_reply_timeout (guint timeout)
{
  request_wait_delay = timeout;
}

void
gabble_vcard_manager_set_default_request_timeout (guint timeout)
{
  default_request_timeout = timeout;
}

GabbleVCardManagerEditInfo *
gabble_vcard_manager_edit_info_new (const gchar *element_name,
                                    const gchar *element_value,
                                    gboolean accept_multiple,
                                    gboolean to_del,
                                    ...)
{
  GabbleVCardManagerEditInfo *info;
  va_list ap;
  const gchar *key;
  const gchar *value;

  info = g_slice_new (GabbleVCardManagerEditInfo);
  info->element_name = g_strdup (element_name);
  info->element_value = g_strdup (element_value);
  info->accept_multiple = accept_multiple;
  info->to_del = to_del;
  info->to_edit = NULL;

  va_start (ap, to_del);
  while ((key = va_arg (ap, const gchar *))) {
      value = va_arg (ap, const gchar *);

      if (!info->to_edit)
        info->to_edit = g_hash_table_new_full (g_str_hash, g_str_equal,
            g_free, g_free);

      g_hash_table_insert (info->to_edit, g_strdup (key),
          g_strdup (value));
  }
  va_end (ap);

  return info;
}

void
gabble_vcard_manager_edit_info_free (GabbleVCardManagerEditInfo *info)
{
  g_free (info->element_name);
  g_free (info->element_value);
  if (info->to_edit)
    g_hash_table_destroy (info->to_edit);
  g_slice_free (GabbleVCardManagerEditInfo, info);
}
