/*
 * jingle-transport-s5b.c - Source for JingleTransportS5B
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

#include "config.h"
#include "jingle-transport-s5b.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>

#define DEBUG_FLAG GABBLE_DEBUG_FT

#include "connection.h"
#include "debug.h"
#include "namespaces.h"
#include "util.h"

#include "jingle-ft-content.h"

static void
transport_iface_init (gpointer g_iface, gpointer iface_data);

G_DEFINE_TYPE_WITH_CODE (JingleTransportS5B, jingle_transport_s5b,
    G_TYPE_OBJECT,
    G_IMPLEMENT_INTERFACE (WOCKY_TYPE_JINGLE_TRANSPORT_IFACE,
        transport_iface_init));

/* signal enum */
enum
{
  NEW_CANDIDATES,
  LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = {0};

/* properties */
enum
{
  PROP_CONTENT = 1,
  PROP_TRANSPORT_NS,
  PROP_STATE,
  PROP_BYTESTREAM,
  PROP_STREAM_ID,
  PROP_USED_CID,
  LAST_PROPERTY
};

struct _JingleTransportS5BPrivate
{
  WockyJingleContent *content;
  WockyJingleTransportState state;
  gchar *transport_ns;
  gchar *sid;
  gchar *cid;
  gchar *daddr;

  GList *local_candidates;
  /* points to last sent candidate */
  GList *local_marker;
  GList *remote_candidates;

  gboolean dispose_has_run;
};

static void
jingle_bytestream_candidate_free (gpointer data)
{
  JingleBytestreamCandidate *c = data;
  g_free (c->px.host);
  g_free (c->px.jid);
  g_free (c->id);
  g_slice_free (JingleBytestreamCandidate, c);
}

static void
jingle_transport_s5b_init (JingleTransportS5B *obj)
{
  JingleTransportS5BPrivate *priv =
     G_TYPE_INSTANCE_GET_PRIVATE (obj, GABBLE_TYPE_JINGLE_TRANSPORT_S5B,
         JingleTransportS5BPrivate);
  obj->priv = priv;

  priv->dispose_has_run = FALSE;
}

static void
jingle_transport_s5b_dispose (GObject *obj)
{
  JingleTransportS5B *t = GABBLE_JINGLE_TRANSPORT_S5B (obj);
  JingleTransportS5BPrivate *priv = t->priv;

  if (priv->dispose_has_run)
    return;

  DEBUG ("dispose called");
  priv->dispose_has_run = TRUE;

  g_free (priv->transport_ns);
  priv->transport_ns = NULL;

  g_free (priv->daddr);
  priv->daddr = NULL;

  g_free (priv->sid);
  priv->sid = NULL;

  g_free (priv->cid);
  priv->cid = NULL;

  g_list_free_full (priv->remote_candidates,
		     jingle_bytestream_candidate_free);
  priv->remote_candidates = NULL;

  g_list_free_full (priv->local_candidates,
		     jingle_bytestream_candidate_free);
  priv->local_candidates = NULL;
  priv->local_marker = NULL;

  if (G_OBJECT_CLASS (jingle_transport_s5b_parent_class)->dispose)
    G_OBJECT_CLASS (jingle_transport_s5b_parent_class)->dispose (obj);
}

static void
jingle_transport_s5b_get_property (GObject *obj,
    guint property_id, GValue *value, GParamSpec *pspec)
{
  JingleTransportS5B *t = GABBLE_JINGLE_TRANSPORT_S5B (obj);
  JingleTransportS5BPrivate *priv = t->priv;

  switch (property_id) {
    case PROP_CONTENT:
      g_value_set_object (value, priv->content);
      break;
    case PROP_TRANSPORT_NS:
      g_value_set_string (value, priv->transport_ns);
      break;
    case PROP_STATE:
      g_value_set_uint (value, priv->state);
      break;
    case PROP_BYTESTREAM:
      g_value_set_string (value, NS_BYTESTREAMS);
      break;
    case PROP_STREAM_ID:
      g_value_set_string (value, priv->sid);
      break;
    case PROP_USED_CID:
      g_value_set_string (value, priv->cid);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, property_id, pspec);
      break;
  }
}

static void
send_candidate_used (JingleTransportS5B *self)
{
  JingleTransportS5BPrivate *priv = self->priv;
  WockyNode *trans_node, *sess_node;
  WockyStanza *msg;

  msg = wocky_jingle_session_new_message (priv->content->session,
      WOCKY_JINGLE_ACTION_TRANSPORT_INFO, &sess_node);

  wocky_jingle_content_produce_node (priv->content, sess_node, FALSE,
      TRUE, &trans_node);

  if (priv->cid == NULL || priv->cid[0] == 0)
    {
      wocky_node_add_child (trans_node, "candidate-error");
    }
  else
    {
      WockyNode *n = wocky_node_add_child (trans_node, "candidate-used");
      wocky_node_set_attribute (n, "cid", priv->cid);
    }

  wocky_porter_send_iq_async (
      wocky_jingle_session_get_porter (priv->content->session), msg,
      NULL, NULL, NULL);
  g_object_unref (msg);
}

static void
jingle_transport_s5b_set_property (GObject *obj,
    guint property_id, const GValue *value, GParamSpec *pspec)
{
  JingleTransportS5B *t = GABBLE_JINGLE_TRANSPORT_S5B (obj);
  JingleTransportS5BPrivate *priv = t->priv;

  switch (property_id) {
    case PROP_CONTENT:
      priv->content = g_value_get_object (value);
      break;
    case PROP_TRANSPORT_NS:
      g_free (priv->transport_ns);
      priv->transport_ns = g_value_dup_string (value);
      break;
    case PROP_STATE:
      priv->state = g_value_get_uint (value);
      break;
    case PROP_STREAM_ID:
      priv->sid = g_value_dup_string (value);
      break;
    case PROP_USED_CID:
      priv->cid = g_value_dup_string (value);
      send_candidate_used (t);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, property_id, pspec);
      break;
  }
}

static void
jingle_transport_s5b_class_init (JingleTransportS5BClass *cls)
{
  GObjectClass *object_class = G_OBJECT_CLASS (cls);
  GParamSpec *param_spec;

  g_type_class_add_private (cls, sizeof (JingleTransportS5BPrivate));

  object_class->get_property = jingle_transport_s5b_get_property;
  object_class->set_property = jingle_transport_s5b_set_property;
  object_class->dispose = jingle_transport_s5b_dispose;

  /* property definitions */
  g_object_class_override_property (object_class, PROP_CONTENT,
		  					     "content");
  g_object_class_override_property (object_class, PROP_TRANSPORT_NS,
		  					"transport-ns");
  g_object_class_override_property (object_class, PROP_STATE,  "state");

  param_spec = g_param_spec_string ("bytestream", "Bytestream namespace",
                                    "Namespace identifying the bytestream type.",
                                    NULL,
                                    G_PARAM_READABLE |
                                    G_PARAM_STATIC_STRINGS);
  g_object_class_install_property (object_class, PROP_BYTESTREAM, param_spec);

  param_spec = g_param_spec_string ("stream-id", "stream ID",
                                    "sid identifying specific S5B bytestream.",
                                    NULL,
                                    G_PARAM_CONSTRUCT |
                                    G_PARAM_READWRITE |
                                    G_PARAM_STATIC_STRINGS);
  g_object_class_install_property (object_class, PROP_STREAM_ID, param_spec);

  param_spec = g_param_spec_string ("used-cid", "candidate-used",
                                    "when set emits candidate-used stanza",
                                    NULL,
                                    G_PARAM_READWRITE |
                                    G_PARAM_STATIC_STRINGS);
  g_object_class_install_property (object_class, PROP_USED_CID, param_spec);

  /* signal definitions */
  signals[NEW_CANDIDATES] = g_signal_new (
    "new-candidates", G_TYPE_FROM_CLASS (cls),
    G_SIGNAL_RUN_LAST,
    0, NULL, NULL,
    g_cclosure_marshal_VOID__POINTER, G_TYPE_NONE, 1, G_TYPE_POINTER);
}

static void
parse_candidates (WockyJingleTransportIface *obj, WockyNode *transport_node,
    GError **error)
{
  JingleTransportS5B *t = GABBLE_JINGLE_TRANSPORT_S5B (obj);
  JingleTransportS5BPrivate *priv = t->priv;
  gboolean node_contains_a_candidate = FALSE;
  WockyNodeIter i;
  WockyNode *node;
  const gchar *str;

  DEBUG ("called %p [%p], extracting attributes", priv, transport_node);

  /* It's really a programming error, must never be called */
  g_assert (!tp_strdiff (transport_node->name, "transport"));
  g_assert (!tp_strdiff (wocky_node_get_ns (transport_node),
		 		NS_JINGLE_TRANSPORT_S5B));

  str = wocky_node_get_attribute (transport_node, "sid");
  if (str == NULL || str[0] == 0)
    {
      DEBUG ("Empty or missing mandatory 'sid' attribute");
      g_set_error (error, WOCKY_XMPP_ERROR, WOCKY_XMPP_ERROR_BAD_REQUEST,
          "Missing mandatory SID attribute");
      return;
    }
  priv->sid = g_strdup (str);

  str = wocky_node_get_attribute (transport_node, "mode");
  if (str != NULL && str[0] == 'u')
    {
      DEBUG ("Current implementation does not support 'udp' mode");
      g_set_error (error, WOCKY_XMPP_ERROR, WOCKY_XMPP_ERROR_BAD_REQUEST,
          "Mode UDP not supported");
      return;
    }

  wocky_node_iter_init (&i, transport_node, NULL, NULL);
  while (wocky_node_iter_next (&i, &node))
    {
      const gchar *cid, *jid, *host;
      guint port, prio;
      WockyJingleCandidateType ctype;
      JingleBytestreamCandidate *c;

      node_contains_a_candidate = TRUE;

      cid = wocky_node_get_attribute (node, "cid");
      if (cid == NULL)
        {
          DEBUG ("candidate doesn't contain CID");
          continue;
        }

      jid = wocky_node_get_attribute (node, "jid");
      if (jid == NULL)
        {
          DEBUG ("candidate doesn't contain JID");
          continue;
        }

      host = wocky_node_get_attribute (node, "host");
      if (host == NULL)
        {
          DEBUG ("candidate doesn't contain host");
          continue;
        }

      str = wocky_node_get_attribute (node, "port");
      if (str == NULL)
        {
          DEBUG ("candidate doesn't contain port");
          continue;
        }
      port = atoi (str);

      str = wocky_node_get_attribute (node, "priority");
      if (str == NULL)
        {
          DEBUG ("candidate doesn't contain priority");
          continue;
        }
      prio = atoi (str);

      str = wocky_node_get_attribute (node, "type");
      if (str == NULL || 
	  !tp_strdiff (str, "direct") ||
	  !tp_strdiff (str, "tunnel"))
        {
          ctype = WOCKY_JINGLE_CANDIDATE_TYPE_LOCAL;
        }
      else if (!wocky_strdiff (str, "assisted"))
        {
          ctype = WOCKY_JINGLE_CANDIDATE_TYPE_STUN;
        }
      else if (!wocky_strdiff (str, "proxy"))
        {
          ctype = WOCKY_JINGLE_CANDIDATE_TYPE_RELAY;
        }
      else
        {
          /* unknown candidate type */
          DEBUG ("unknown candidate type: %s", str);
          continue;
        }
      c = g_slice_new0 (JingleBytestreamCandidate);
      c->px.host = g_strdup (host);
      c->px.port = port;
      c->px.jid = g_strdup (jid);
      c->type = ctype;
      c->prio = prio;
      c->id = g_strdup (cid);
      if (priv->remote_candidates == NULL ||
         ((JingleBytestreamCandidate*)(priv->remote_candidates->data))->prio >=
	      prio)
        {
          priv->remote_candidates = g_list_prepend (
              priv->remote_candidates, c);
	}
      else
        {
          priv->remote_candidates = g_list_append (
              priv->remote_candidates, c);
	}
    }

  if (priv->remote_candidates == priv->local_marker
      && node_contains_a_candidate)
    {
      DEBUG ("Malformed request, could not recognize a single candidate");
      g_set_error (error, WOCKY_XMPP_ERROR, WOCKY_XMPP_ERROR_BAD_REQUEST,
          "Missing mandatory candidate attributes");
      return;
    }

  priv->state = WOCKY_JINGLE_TRANSPORT_STATE_CONNECTING;
}

static void
inject_candidates (WockyJingleTransportIface *obj, WockyNode *transport_node)
{
  JingleTransportS5B *t = GABBLE_JINGLE_TRANSPORT_S5B (obj);
  JingleTransportS5BPrivate *priv = t->priv;
  GList *l;

  DEBUG ("called %p [%p]: %p >> %p", t, priv, priv->local_marker, priv->local_candidates);
  if (priv->sid != NULL)
    wocky_node_set_attribute (transport_node, "sid", priv->sid);

  if (priv->daddr != NULL)
    wocky_node_set_attribute (transport_node, "dstaddr", priv->daddr);

  for (l = priv->local_candidates; l != NULL && l != priv->local_marker; l = l->next)
    {
      JingleBytestreamCandidate *c = l->data;
      WockyNode *cnd = wocky_node_add_child (transport_node, "candidate");
      gchar *port = g_strdup_printf ("%hu", c->px.port),
	    *prio = g_strdup_printf ("%u", c->prio),
	    *type = (c->type == WOCKY_JINGLE_CANDIDATE_TYPE_LOCAL) ? "direct"
	    	  : (c->type == WOCKY_JINGLE_CANDIDATE_TYPE_RELAY) ? "proxy"
		  : (c->type == WOCKY_JINGLE_CANDIDATE_TYPE_STUN) ? "assisted"
		  : "tunnel";
      wocky_node_set_attributes (cnd,
          "cid",  c->id,
	  "jid",  c->px.jid,
          "host", c->px.host,
	  "port", port,
	  "priority", prio,
	  "type", type,
	  NULL);
      g_free (port);
      g_free (prio);
    }
  priv->local_marker = priv->local_candidates;
}

static void
send_candidates (WockyJingleTransportIface *iface, gboolean all)
{
  JingleTransportS5B *self = GABBLE_JINGLE_TRANSPORT_S5B (iface);
  JingleTransportS5BPrivate *priv = self->priv;
  WockyNode *trans_node, *sess_node;
  WockyStanza *msg;

  /* reset marker to NULL if requested to emit all candidates */
  if (all)
    priv->local_marker = NULL;

  if (priv->local_marker == priv->local_candidates)
    {
      DEBUG ("No pending candidates to send for %p", self);
      return;
    }

  msg = wocky_jingle_session_new_message (priv->content->session,
      WOCKY_JINGLE_ACTION_TRANSPORT_INFO, &sess_node);

  wocky_jingle_content_produce_node (priv->content, sess_node, FALSE,
      TRUE, &trans_node);

  inject_candidates (iface, trans_node);

  wocky_porter_send_iq_async (
      wocky_jingle_session_get_porter (priv->content->session), msg,
      NULL, NULL, NULL);
  g_object_unref (msg);

  DEBUG ("%p sent %s candidates", self, (all ? "all":"pending"));
}

static void
new_local_candidates (WockyJingleTransportIface *obj, GList *new_candidates)
{
  JingleTransportS5B *t = GABBLE_JINGLE_TRANSPORT_S5B (obj);
  JingleTransportS5BPrivate *priv = t->priv;

  DEBUG ("called %p [%p]: %p", t, priv, new_candidates);
  priv->local_candidates = g_list_concat (new_candidates,
      priv->local_candidates);
}

static GList *
get_remote_candidates (WockyJingleTransportIface *obj)
{
  JingleTransportS5B *t = GABBLE_JINGLE_TRANSPORT_S5B (obj);
  JingleTransportS5BPrivate *priv = t->priv;

  DEBUG ("called %p [%p]: %p", t, priv, priv->remote_candidates);
  return priv->remote_candidates;
}

static GList *
get_local_candidates (WockyJingleTransportIface *obj)
{
  JingleTransportS5B *t = GABBLE_JINGLE_TRANSPORT_S5B (obj);
  JingleTransportS5BPrivate *priv = t->priv;

  DEBUG ("called %p [%p]: %p", t, priv, priv->local_candidates);
  return priv->local_candidates;
}

static WockyJingleTransportType
get_transport_type (void)
{
  return JINGLE_TRANSPORT_UNKNOWN;
}


static void
transport_iface_init (gpointer g_iface, gpointer iface_data)
{
  WockyJingleTransportIfaceClass *klass = 
	  (WockyJingleTransportIfaceClass *) g_iface;

  /* Mandatory to implement */
  klass->parse_candidates = parse_candidates;
  klass->new_local_candidates = new_local_candidates;
  klass->get_remote_candidates = get_remote_candidates;
  klass->get_local_candidates = get_local_candidates;
  klass->get_transport_type = get_transport_type;

  /* this one is optional but is the one populating transport node */
  klass->inject_candidates = inject_candidates;
  /* is also optional but could be used to send candidates on event */
  klass->send_candidates = send_candidates;
  /* Optional calls
  klass->get_credentials = get_credentials;
  */
}

void
jingle_transport_s5b_register (WockyJingleFactory *factory)
{
  wocky_jingle_factory_register_transport (factory,
      NS_JINGLE_TRANSPORT_S5B, GABBLE_TYPE_JINGLE_TRANSPORT_S5B);
}

