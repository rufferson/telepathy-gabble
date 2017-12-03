/*
 * jingle-ft-content.c - Source for GabbleJingleFT
 *
 * Copyright (c) 2017 Ruslan N. Marchenko
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

/* Jingle FileTransfer (FT) implements XEP-0234
 * - jingle application type for file transfers.
 * */

#include "config.h"
#include "jingle-ft-content.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>


#define DEBUG_FLAG GABBLE_DEBUG_FT

#include "connection.h"
#include "debug.h"
#include "namespaces.h"
#include "util.h"

/******************************************************************
 * Example description Node:
 * iq xmlns='jabber:client' type='set' id='randid1' to='kettle@ruff.mobi/gabble' from='pot@ruff.mobi/tablet'
    * jingle xmlns='urn:xmpp:jingle:1' action='session-initiate' sid='n0qqcnq6s0' initiator='pot@ruff.mobi/tablet'
        * content creator='initiator' name='4kfh3t6fsk'
            * description xmlns='urn:xmpp:jingle:apps:file-transfer:3'
                * offer
                    * file
                        * size
                            "291419"
                        * name
                            "SirensOfTheSeaCD.jpg"
                        * desc
            * transport xmlns='urn:xmpp:jingle:transports:s5b:1' sid='gvc4u3vmrj'
 *
 *******************************************************************/

enum
{
  PROP_MEDIA_TYPE = 1,
  LAST_PROPERTY
};

G_DEFINE_TYPE (GabbleJingleFT,
    gabble_jingle_ft, WOCKY_TYPE_JINGLE_CONTENT);

static void
del_channel (GabbleJingleFT * self, GabbleFileTransferChannel *channel);

struct _GabbleJingleFTPrivate
{
  gboolean dispose_has_run;

  GabbleJingleFTContent *desc;

  WockyJingleTransportIface *transport;
  GabbleFileTransferChannel *channel;
};

static void
free_desc (GabbleJingleFT *self)
{
  if (self->priv->desc)
    {
      if (self->priv->desc->file)
        {
          GabbleJingleFTFileEntry *f = self->priv->desc->file;

          g_free (f->name);
          g_free (f->type);
          g_free (f->desc);
          g_free (f->hash);
          g_slice_free (GabbleJingleFTFileEntry, f);
        }
      g_slice_free (GabbleJingleFTContent, self->priv->desc);
      self->priv->desc = NULL;
    }
}

static void
ensure_desc (GabbleJingleFT *self)
{
  if (self->priv->desc == NULL)
    {
      self->priv->desc = g_slice_new0 (GabbleJingleFTContent);
    }
}

static void
gabble_jingle_ft_init (GabbleJingleFT *obj)
{
  GabbleJingleFTPrivate *priv =
     G_TYPE_INSTANCE_GET_PRIVATE (obj, GABBLE_TYPE_JINGLE_FT,
         GabbleJingleFTPrivate);

  DEBUG ("jingle ft init called for %p:%p", obj, priv);
  obj->priv = priv;

  priv->dispose_has_run = FALSE;
}


static void
gabble_jingle_ft_dispose (GObject *object)
{
  GabbleJingleFT *self = GABBLE_JINGLE_FT (object);
  GabbleJingleFTPrivate *priv = self->priv;

  if (priv->dispose_has_run)
    return;

  DEBUG ("dispose called for %p", object);
  priv->dispose_has_run = TRUE;

  if (self->priv->channel != NULL)
    del_channel(self, NULL);

  free_desc (self);

  if (G_OBJECT_CLASS (gabble_jingle_ft_parent_class)->dispose)
    G_OBJECT_CLASS (gabble_jingle_ft_parent_class)->dispose (object);
}

static WockyJingleContentSenders
get_default_senders (WockyJingleContent *c)
{
  return WOCKY_JINGLE_CONTENT_SENDERS_INITIATOR;
}

/* FIXME: or rather fix wocky-session to do this */
static gboolean
check_session_terminate (WockyJingleSession *sess, WockyJingleReason reason,
                GabbleJingleFT *self)
{
  GList *i, *cs = wocky_jingle_session_get_contents (sess);

  for (i = cs; i; i = cs->next)
    {
      WockyJingleContent *c;
      GabbleJingleFT *ftc;
      WockyJingleContentState state;
      c = WOCKY_JINGLE_CONTENT (i->data);

      /* non-existing content or ourself - not active */
      if (c == NULL || c == WOCKY_JINGLE_CONTENT (self))
        continue;

      /* ft content without channel - not active */
      ftc = GABBLE_JINGLE_FT (c);
      if (ftc != NULL && ftc->priv->channel == NULL)
        continue;

      g_object_get (c, "state", &state, NULL);

      /* some content in active state - ok, cancel termination */
      if (state > WOCKY_JINGLE_CONTENT_STATE_EMPTY &&
          state < WOCKY_JINGLE_CONTENT_STATE_REMOVING)
        {
          g_list_free (cs);
          return FALSE;
        }
    }
  g_list_free (cs);
  DEBUG ("No active content, terminating session %p from %p reason %d",
                  sess, self, reason);
  return wocky_jingle_session_terminate (sess, reason, NULL, NULL);
}

static void
bytestream_error_cb (GabbleBytestreamIface *bs, gpointer user_data)
{
  GabbleJingleFT *self = GABBLE_JINGLE_FT (user_data);

  DEBUG ("Bytestream[%p] connection error at %p", bs, self);

  /* this should actually be handled by channel itself, let's ignore
  if (self->priv->channel)
    tp_base_channel_close (TP_BASE_CHANNEL(self->priv->channel));
  */
}

static void
bytestream_state_changed (GObject *obj, guint state, gpointer data)
{
  GabbleBytestreamIface *bs = GABBLE_BYTESTREAM_IFACE (obj);
  GabbleJingleFT *self = data;
  guint cstate;

  DEBUG ("Bytestream %p state changed to %u on %p", bs, state, self);

  if (state != GABBLE_BYTESTREAM_STATE_CLOSED || self->priv->channel == NULL)
    return;

  g_object_get (self->priv->channel, "state", &cstate, NULL);
  if (cstate == TP_FILE_TRANSFER_STATE_COMPLETED)
    {
      if (!check_session_terminate (WOCKY_JINGLE_CONTENT (self)->session,
                              WOCKY_JINGLE_REASON_SUCCESS, self))
        DEBUG ("Cannot terminate the session yet, active content pending");
      /* we don't need it anymore, up to handler to deal with it */
      //del_channel(self, NULL);
    }
  else
  if (cstate == TP_FILE_TRANSFER_STATE_CANCELLED)
    {
      if (!check_session_terminate (WOCKY_JINGLE_CONTENT (self)->session,
                  WOCKY_JINGLE_REASON_CANCEL, self))
        wocky_jingle_content_remove (WOCKY_JINGLE_CONTENT (self), TRUE);
    }
  else
    DEBUG ("Unexpected channel state %u for closed stream", cstate);
}

static inline gboolean
channel_exists (GabbleJingleFT * self, GabbleFileTransferChannel *channel)
{
  return self->priv->channel == channel;
}

static void
channel_accepted (GObject *object, GObject *argument, gpointer data)
{
  GabbleBytestreamIface *bs = GABBLE_BYTESTREAM_IFACE (object);
  GabbleFileTransferChannel *channel = GABBLE_FILE_TRANSFER_CHANNEL (argument);
  GabbleJingleFT *self = GABBLE_JINGLE_FT (data);
  int state;

  DEBUG ("channel %p was accepted via %p for content %p", channel, bs, self);

  g_return_if_fail (channel_exists (self, channel));

  /* any content acceptance also accepts pending session */
  g_object_get (WOCKY_JINGLE_CONTENT (self)->session, "state", &state, NULL);
  if (state < WOCKY_JINGLE_STATE_PENDING_ACCEPT_SENT)
    wocky_jingle_session_accept (WOCKY_JINGLE_CONTENT (self)->session);

  wocky_jingle_content_set_transport_state (WOCKY_JINGLE_CONTENT (self),
                  WOCKY_JINGLE_TRANSPORT_STATE_CONNECTED);
}

static void
channel_rejected (GObject *object, gpointer data)
{
  GabbleBytestreamIface *bs = GABBLE_BYTESTREAM_IFACE (object);
  GabbleJingleFT *self = GABBLE_JINGLE_FT (data);

  DEBUG ("channel was rejected via %p for %p", bs, self);

  /* we don't need it anymore, up to handler to deal with it */
  del_channel(self, NULL);

  if (!check_session_terminate (WOCKY_JINGLE_CONTENT (self)->session,
                  WOCKY_JINGLE_REASON_DECLINE, self))
    wocky_jingle_content_reject (WOCKY_JINGLE_CONTENT (self),
                  WOCKY_JINGLE_REASON_DECLINE);
}

static void
channel_disposed (gpointer data, GObject *object)
{
  GabbleJingleFT *self = data;
  GabbleFileTransferChannel *channel = (GabbleFileTransferChannel *) object;

  DEBUG ("channel %p got destroyed", channel);

  g_return_if_fail (channel_exists (self, channel));

  del_channel (self, channel);

  /* FIXME: if content disposition is session - cancel the session
   * Although before that some other event should be fired and actioned
   * Let's keep a track on this event.
   */
}

static void
del_channel (GabbleJingleFT * self, GabbleFileTransferChannel *channel)
{
  if (channel != NULL && channel != self->priv->channel)
    return;

  g_object_weak_unref (G_OBJECT (self->priv->channel), channel_disposed, self);
  self->priv->channel =  NULL;
}

static void
set_channel (GabbleJingleFT *self, GabbleFileTransferChannel *channel)
{
  self->priv->channel = channel;

  if (channel == NULL)
    return;

  g_object_weak_ref (G_OBJECT (channel), channel_disposed, self);
}

static void
session_terminated (WockyJingleSession *session,
                    gboolean local_terminator,
                    WockyJingleReason reason,
                    const gchar *text,
                    gpointer user_data)
{
  GabbleJingleFT *self = GABBLE_JINGLE_FT (user_data);
  GabbleFileTransferChannel *chan = self->priv->channel;
  DEBUG ("session %p got terminated", session);

  if (self->priv->channel == NULL)
          return;
  chan = self->priv->channel;
  del_channel(self, NULL);

  /* State should be consistent for complete transfer */
  if (reason != WOCKY_JINGLE_REASON_SUCCESS)
    {
      /* here we'd need to adjust actual state */
      gabble_file_transfer_channel_transfer_state_changed (chan,
               TP_FILE_TRANSFER_STATE_CANCELLED,
               local_terminator ?
               TP_FILE_TRANSFER_STATE_CHANGE_REASON_LOCAL_STOPPED :
               TP_FILE_TRANSFER_STATE_CHANGE_REASON_REMOTE_STOPPED);
    }
  tp_base_channel_close (TP_BASE_CHANNEL(chan));
}

static void
content_state_changed (WockyJingleContent *c,
                       GParamSpec *arg1,
                       GabbleJingleFT *self)
{
  WockyJingleContentState state;

  DEBUG ("called for %p by %p", self, c);

  g_object_get (c, "state", &state, NULL);

  switch (state)
    {
      case WOCKY_JINGLE_CONTENT_STATE_EMPTY:
      case WOCKY_JINGLE_CONTENT_STATE_NEW:
        break;
      case WOCKY_JINGLE_CONTENT_STATE_SENT:
        /* this state is never notified actually */
        if (self->priv->channel)
          {
            gabble_file_transfer_channel_transfer_state_changed (
                    self->priv->channel,
                    TP_FILE_TRANSFER_STATE_PENDING,
                    TP_FILE_TRANSFER_STATE_CHANGE_REASON_NONE);
          }
        break;
      case WOCKY_JINGLE_CONTENT_STATE_ACKNOWLEDGED:
        /* Do not set the channels to OPEN unless we're ready to send/receive
           data from them */
        if (self->priv->channel)
          {
            gabble_file_transfer_channel_transfer_state_changed (
                    self->priv->channel,
                    TP_FILE_TRANSFER_STATE_ACCEPTED,
                    TP_FILE_TRANSFER_STATE_CHANGE_REASON_NONE);
          }
        break;
      case WOCKY_JINGLE_CONTENT_STATE_REMOVING:
        /* Do nothing, let the terminated signal set the correct state
           depending on the termination reason */
      default:
        break;
    }
}

GabbleFileTransferChannel *
gabble_jingle_ft_new_channel (GabbleJingleFT *self, GabbleConnection *conn)
{
  GabbleBytestreamIface *bytestream;
  GabbleBytestreamFactory *factory;
  GabbleFileTransferChannel *chan;
  WockyJingleSession *session;
  GabbleJingleFTContent *meta;
  TpHandleRepoIface *contacts;
  TpHandle peer;
  gchar *method, *sid;

  g_assert (self != NULL);
  g_assert (conn != NULL);

  meta = self->priv->desc;
  factory = conn->bytestream_factory;
  session = WOCKY_JINGLE_CONTENT (self)->session;

  /* below conditions are programming errors */
  g_assert (factory != NULL);
  g_assert (session != NULL);

  /* these though are based on jingle xml input */
  if (self->priv->transport == NULL || meta == NULL)
    return NULL;

  contacts = tp_base_connection_get_handles ( TP_BASE_CONNECTION (conn),
              TP_HANDLE_TYPE_CONTACT);
  peer = tp_handle_ensure (contacts,
              wocky_jingle_session_get_peer_jid (session), NULL, NULL);

  g_object_get (self->priv->transport, "bytestream", &method, NULL);
  g_object_get (self->priv->transport, "stream-id", &sid, NULL);

  bytestream = gabble_bytestream_factory_create_from_method (factory, method,
              peer, sid, NULL,
              wocky_jingle_session_get_peer_resource (session),
              NULL, GABBLE_BYTESTREAM_STATE_LOCAL_PENDING);
  g_free (sid);
  g_free (method);

  if (bytestream == NULL)
    goto TransportException;

  DEBUG("Creating TP FT Channel for %p:%p:%p", self, meta, meta->file);
  chan = gabble_file_transfer_channel_new (conn, peer, peer,
              TP_FILE_TRANSFER_STATE_PENDING,
              meta->file->type,
              meta->file->name,
              meta->file->size,
              meta->file->hash_algo,
              meta->file->hash,
              meta->file->desc,
              meta->file->date,
              meta->file->range_off,
              ((meta->file->range_len > 0) ? TRUE : FALSE),
              bytestream, NULL, NULL, NULL, NULL, NULL);

  DEBUG ("called %p <-[%p:%p]-> %p on %p:%p:%p",
              chan, factory, bytestream, self->priv->transport,
              session, self, conn);

  if (chan == NULL)
    goto TransportException;

  /* Good to Go - patch them all together */
  set_channel (self, chan);

  gabble_signal_connect_weak (bytestream, "accepted",
              (GCallback) channel_accepted, G_OBJECT (self));

  gabble_signal_connect_weak (bytestream, "rejected",
              (GCallback) channel_rejected, G_OBJECT (self));

  gabble_signal_connect_weak (bytestream, "connection-error",
              (GCallback) bytestream_error_cb, G_OBJECT (self));

  gabble_signal_connect_weak (bytestream, "state-changed",
              (GCallback) bytestream_state_changed, G_OBJECT (self));

  return chan;

TransportException:
  DEBUG ("Channel[%p] is set but other prereqs are missing (%p, %p)",
              chan, factory, self->priv->transport);
  wocky_jingle_content_reject (WOCKY_JINGLE_CONTENT (self),
              WOCKY_JINGLE_REASON_FAILED_TRANSPORT);
  if (chan != NULL)
    g_object_unref (chan);
  return NULL;
}

void
gabble_jingle_ft_set_channel (GabbleJingleFT *self,
    GabbleFileTransferChannel *channel)
{
  set_channel (self, channel);
}

static void
transport_disposed (gpointer data, GObject *object)
{
  GabbleJingleFT *self = data;
  WockyJingleTransportIface *t = WOCKY_JINGLE_TRANSPORT_IFACE (object);

  DEBUG ("transport %p got destroyed", t);

  g_return_if_fail ( t == self->priv->transport );

  self->priv->transport = NULL;

  /* FIXME: do some mop up? */
}

static void
transport_created (WockyJingleContent *c, WockyJingleTransportIface *t)
{
  GabbleJingleFT *self = GABBLE_JINGLE_FT (c);
  GabbleJingleFTPrivate *priv = self->priv;

  priv->transport = t;

  /* Initialisation complete, setup callbacks */
  g_signal_connect (self, "notify::state",
      (GCallback) content_state_changed, G_OBJECT (self));

  gabble_signal_connect_weak (c->session, "terminated",
      (GCallback) session_terminated, G_OBJECT (self));

  g_object_weak_ref (G_OBJECT (t), transport_disposed, self);

  DEBUG ("Transport set[%p]", t);
}

static void
parse_description (WockyJingleContent *content,
    WockyNode *desc_node, GError **error)
{
  GabbleJingleFT *self = GABBLE_JINGLE_FT (content);
  GabbleJingleFTPrivate *priv = self->priv;
  WockyNode *sess_node = NULL;
  WockyNode *node;
  WockyNodeIter i;

  DEBUG ("parse description called");

  if (priv->desc != NULL)
    {
      DEBUG ("Not parsing description, we already have a session");
      return;
    }

  if (wocky_node_has_ns (desc_node, NS_JINGLE_FT3))
    {
      DEBUG ("FT:3 namespace uses nested file container");
      sess_node = wocky_node_get_child(desc_node, "offer");
      if (sess_node == NULL)
        {
          gchar *dump = wocky_node_to_string (desc_node);
          DEBUG ("No offer, reqest is deprecated, bailing for %s", dump);
          g_free(dump);
          g_set_error (error, WOCKY_XMPP_ERROR, WOCKY_XMPP_ERROR_BAD_REQUEST,
              "description is missing offer node, request is deprecated");
          return;
        }
    }
  else
      sess_node = desc_node;

  priv->desc = g_slice_new0 (GabbleJingleFTContent);

  /* Build the file */
  wocky_node_iter_init (&i, sess_node, NULL, NULL);
  while (wocky_node_iter_next (&i, &node))
    {
      GabbleJingleFTFileEntry *f = NULL;
      WockyNode *n;

      DEBUG ("Iterating through %s", node->name);
      if (wocky_strdiff (node->name, "file"))
        continue;

      n = wocky_node_get_child (node, "name");
      if (n == NULL)
        continue;

      if (priv->desc->file)
        {
          DEBUG ("We don't want to support deprecated multi-file transfer.");
          g_set_error (error, WOCKY_XMPP_ERROR, WOCKY_XMPP_ERROR_BAD_REQUEST,
                  "Multi-file transfers not supported");
          return;
        }

      f = g_slice_new0 (GabbleJingleFTFileEntry);
      f->name = g_strdup (n->content);

      n = wocky_node_get_child (node, "date");
      if (n)
        {
          GTimeVal val;
          if (g_time_val_from_iso8601 (n->content, &val))
              f->date = val.tv_sec;
        }

      n = wocky_node_get_child (node, "desc");
      if (n)
          f->desc = g_strdup (n->content);

      n = wocky_node_get_child (node, "size");
      if (n)
        f->size = g_ascii_strtoull (n->content, NULL, 10);

      n = wocky_node_get_child_ns (node, "hash", NS_HASHES);
      if (n)
        {
          const gchar *algo = wocky_node_get_attribute (n, "algo");
          if (!g_strcmp0(algo,"md5"))
              f->hash_algo = TP_FILE_HASH_TYPE_MD5;
          else
          if (!g_strcmp0(algo,"sha-1"))
              f->hash_algo = TP_FILE_HASH_TYPE_SHA1;
          else
          if (!g_strcmp0(algo,"sha-256"))
              f->hash_algo = TP_FILE_HASH_TYPE_SHA256;

          if (f->hash_algo != TP_FILE_HASH_TYPE_NONE)
              f->hash = g_strdup (n->content);
        }

      n = wocky_node_get_child (node, "range");
      if (n)
        {
          const gchar *att = wocky_node_get_attribute (n, "offset");

          if (att)
            f->range_off = g_ascii_strtoull (att, NULL, 10);

          att = wocky_node_get_attribute (n, "length");
          if (att)
            f->range_len = g_ascii_strtoull (att, NULL, 10);
          else
            f->range_len = f->size;
        }
      priv->desc->file = f;
    }
  DEBUG ("parse description set chain: %p:%p:%p:%p", self, priv, priv->desc, priv->desc->file);

  _wocky_jingle_content_set_media_ready (content);
}

static void
produce_description (WockyJingleContent *content, WockyNode *content_node)
{
  GabbleJingleFT *self = GABBLE_JINGLE_FT (content);
  GabbleJingleFTPrivate *priv = self->priv;

  WockyNode *desc_node;
  WockyNode *sess_node;

  DEBUG ("produce description called");

  ensure_desc (self);

  desc_node = wocky_node_add_child_ns (content_node, "description",
      NS_JINGLE_FT3);

  sess_node = wocky_node_add_child (desc_node, "offer");

  if (priv->desc->file)
    {
      GabbleJingleFTFileEntry *f = priv->desc->file;
      WockyNode *file_node;
      gchar *tmp_str;

      file_node = wocky_node_add_child (sess_node, "file");

      if (f->name && f->name[0])
          wocky_node_add_child_with_content (file_node, "name", f->name);

      if (f->desc && f->desc[0])
          wocky_node_add_child_with_content (file_node, "desc", f->desc);

      if (f->date)
        {
          GTimeVal tv = {f->date,0};
          tmp_str = g_time_val_to_iso8601 (&tv);
          wocky_node_add_child_with_content (file_node, "date", tmp_str);
          g_free (tmp_str);
        }

      if (f->size > 0)
        {
          tmp_str = g_strdup_printf ("%" G_GUINT64_FORMAT, f->size);
          wocky_node_add_child_with_content (file_node, "size", tmp_str);
          g_free (tmp_str);
        }

      if (f->hash && f->hash[0])
        {
          WockyNode *hash_node = wocky_node_add_child_ns (file_node, "hash",
                                                                NS_HASHES);
          switch (f->hash_algo)
            {
              case TP_FILE_HASH_TYPE_SHA256:
                tmp_str = "sha-256";
                break;
              case TP_FILE_HASH_TYPE_SHA1:
                tmp_str = "sha-1";
                break;
              default:
                tmp_str = "md5";
            }
          wocky_node_set_attribute (hash_node, "algo", tmp_str);
        }
      if (f->range_off > 0 || f->range_len > 0)
        {
          WockyNode *range = wocky_node_add_child (file_node, "range");

          if (f->range_off > 0)
            {
              tmp_str = g_strdup_printf ("%" G_GUINT64_FORMAT, f->range_off);
              wocky_node_set_attribute (range, "offset", tmp_str);
              g_free (tmp_str);
            }
          if (f->range_len > 0)
            {
              tmp_str = g_strdup_printf ("%" G_GUINT64_FORMAT, f->range_len);
              wocky_node_set_attribute (range, "length", tmp_str);
              g_free (tmp_str);
            }
        }
    }
}

static void
get_property (GObject *object, guint property_id, GValue *value,
    GParamSpec *pspec)
{
  //GabbleJingleFT *self = GABBLE_JINGLE_FT (object);

  switch (property_id) {
    case PROP_MEDIA_TYPE:
      g_value_set_uint (value, WOCKY_JINGLE_MEDIA_TYPE_NONE);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

static void
set_property (GObject *object, guint property_id, const GValue *value,
    GParamSpec *pspec)
{
  //GabbleJingleFT *self = GABBLE_JINGLE_FT (object);

  switch (property_id) {
    case PROP_MEDIA_TYPE:
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

static void
gabble_jingle_ft_class_init (GabbleJingleFTClass *cls)
{
  GObjectClass *object_class = G_OBJECT_CLASS (cls);
  WockyJingleContentClass *content_class = WOCKY_JINGLE_CONTENT_CLASS (cls);

  g_type_class_add_private (cls, sizeof (GabbleJingleFTPrivate));

  object_class->dispose = gabble_jingle_ft_dispose;

  content_class->parse_description = parse_description;
  content_class->produce_description = produce_description;
  content_class->get_default_senders = get_default_senders;
  content_class->transport_created = transport_created;

  /* FIXME: remove-me once wocky-jingle-session FIXME is mitigated */
  object_class->get_property = get_property;
  object_class->set_property = set_property;
  g_object_class_install_property (object_class, PROP_MEDIA_TYPE,
      g_param_spec_uint ("media-type", "media type",
          "Used for MediaRTP only, ignored otherwise.",
          WOCKY_JINGLE_MEDIA_TYPE_NONE, WOCKY_JINGLE_MEDIA_TYPE_NONE,
          WOCKY_JINGLE_MEDIA_TYPE_NONE,
          G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));
}

GabbleJingleFTContent *
gabble_jingle_ft_get_content (GabbleJingleFT *self)
{
  DEBUG ("retrieving content descriptor for %p:%p:%p", self, self->priv, self->priv->desc);
  ensure_desc (self);
  return self->priv->desc;
}

void
jingle_ft_content_register (WockyJingleFactory *factory)
{
  wocky_jingle_factory_register_content_type (factory,
      NS_JINGLE_FT3, GABBLE_TYPE_JINGLE_FT);
}
