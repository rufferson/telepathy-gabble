/*
 * jingle-transport-ibb.c - Source for JingleTransportIBB
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
#include "jingle-transport-ibb.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>

#define DEBUG_FLAG GABBLE_DEBUG_FT

#include "connection.h"
#include "debug.h"
#include "namespaces.h"
#include "util.h"

static void
transport_iface_init (gpointer g_iface, gpointer iface_data);

G_DEFINE_TYPE_WITH_CODE (JingleTransportIBB, jingle_transport_ibb,
    G_TYPE_OBJECT,
    G_IMPLEMENT_INTERFACE (WOCKY_TYPE_JINGLE_TRANSPORT_IFACE,
        transport_iface_init));

/* properties */
enum
{
  PROP_CONTENT = 1,
  PROP_TRANSPORT_NS,
  PROP_STATE,
  PROP_BYTESTREAM,
  PROP_STREAM_ID,
  PROP_BLOCK_SIZE,
  LAST_PROPERTY
};

struct _JingleTransportIBBPrivate
{
  WockyJingleContent *content;
  WockyJingleTransportState state;
  gchar *transport_ns;
  gchar *sid;

  guint block_size;

  gboolean dispose_has_run;
};

static void
jingle_transport_ibb_init (JingleTransportIBB *obj)
{
  JingleTransportIBBPrivate *priv =
     G_TYPE_INSTANCE_GET_PRIVATE (obj, GABBLE_TYPE_JINGLE_TRANSPORT_IBB,
         JingleTransportIBBPrivate);
  obj->priv = priv;

  priv->dispose_has_run = FALSE;
}

static void
jingle_transport_ibb_dispose (GObject *obj)
{
  JingleTransportIBB *t = GABBLE_JINGLE_TRANSPORT_IBB (obj);
  JingleTransportIBBPrivate *priv = t->priv;

  if (priv->dispose_has_run)
    return;

  DEBUG ("dispose called");
  priv->dispose_has_run = TRUE;

  g_free (priv->transport_ns);
  priv->transport_ns = NULL;

  g_free (priv->sid);
  priv->sid = NULL;

  if (G_OBJECT_CLASS (jingle_transport_ibb_parent_class)->dispose)
    G_OBJECT_CLASS (jingle_transport_ibb_parent_class)->dispose (obj);
}

static void
jingle_transport_ibb_get_property (GObject *obj,
    guint property_id, GValue *value, GParamSpec *pspec)
{
  JingleTransportIBB *t = GABBLE_JINGLE_TRANSPORT_IBB (obj);
  JingleTransportIBBPrivate *priv = t->priv;

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
      g_value_set_string (value, NS_IBB);
      break;
    case PROP_STREAM_ID:
      g_value_set_string (value, priv->sid);
      break;
    case PROP_BLOCK_SIZE:
      g_value_set_uint (value, priv->block_size);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, property_id, pspec);
      break;
  }
}

static void
jingle_transport_ibb_set_property (GObject *obj,
    guint property_id, const GValue *value, GParamSpec *pspec)
{
  JingleTransportIBB *t = GABBLE_JINGLE_TRANSPORT_IBB (obj);
  JingleTransportIBBPrivate *priv = t->priv;

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
    case PROP_BLOCK_SIZE:
      priv->block_size = g_value_get_uint (value);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, property_id, pspec);
      break;
  }
}

static void
jingle_transport_ibb_class_init (JingleTransportIBBClass *cls)
{
  GObjectClass *object_class = G_OBJECT_CLASS (cls);
  GParamSpec *param_spec;

  g_type_class_add_private (cls, sizeof (JingleTransportIBBPrivate));

  object_class->get_property = jingle_transport_ibb_get_property;
  object_class->set_property = jingle_transport_ibb_set_property;
  object_class->dispose = jingle_transport_ibb_dispose;

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
                                    "sid identifying specific IBB bytestream.",
                                    NULL,
                                    G_PARAM_CONSTRUCT |
                                    G_PARAM_READWRITE |
                                    G_PARAM_STATIC_STRINGS);
  g_object_class_install_property (object_class, PROP_STREAM_ID, param_spec);

  param_spec = g_param_spec_uint   ("block-size", "block size",
                                    "Block-size attribute for IBB's open IQ",
                                    64, 65535, 4096,
                                    G_PARAM_CONSTRUCT |
                                    G_PARAM_READWRITE |
                                    G_PARAM_STATIC_STRINGS);
  g_object_class_install_property (object_class, PROP_BLOCK_SIZE, param_spec);
}

static void
parse_candidates (WockyJingleTransportIface *obj, WockyNode *transport_node,
    GError **error)
{
  JingleTransportIBB *t = GABBLE_JINGLE_TRANSPORT_IBB (obj);
  JingleTransportIBBPrivate *priv = t->priv;
  const gchar *str;
  guint block_size = 0;

  DEBUG ("called %p [%p], extracting attributes", priv, transport_node);

  /* It's really a programming error, must never be called */
  g_assert (!tp_strdiff (transport_node->name, "transport"));
  g_assert (!tp_strdiff (wocky_node_get_ns (transport_node),
		 		NS_JINGLE_TRANSPORT_IBB));

  str = wocky_node_get_attribute (transport_node, "sid");
  if (str == NULL || str[0] == 0)
    {
      DEBUG ("Empty or missing mandatory 'sid' attribute");
      g_set_error (error, WOCKY_XMPP_ERROR, WOCKY_XMPP_ERROR_BAD_REQUEST,
          "Missing mandatory SID attribute");
      return;
    }
  priv->sid = g_strdup (str);

  str = wocky_node_get_attribute (transport_node, "block-size");
  if (str == NULL || str[0] == 0)
    {
      DEBUG ("Empty or missing mandatory 'block-size' attribute");
      g_set_error (error, WOCKY_XMPP_ERROR, WOCKY_XMPP_ERROR_BAD_REQUEST,
          "Missing mandatory 'block-size' attribute");
      return;
    }
  block_size = strtoul (str, NULL, 10);
  if (block_size == 0 || block_size > 65535)
    {
      DEBUG ("Invalid mandatory 'block-size' attribute: '%s'", str);
      g_set_error (error, WOCKY_XMPP_ERROR, WOCKY_XMPP_ERROR_BAD_REQUEST,
          "Invalid mandatory 'block-size' attribute");
      return;
    }
  priv->block_size = block_size;

  /* We don't really care about 'stanza' attribute, gabble implementation
   * would handle both for incoming and is IQ-only for outgoing.
   */

  /* for IBB valid transport element is the only prerequisite.
   * Connection (band) is already there.
   */
  //priv->state = WOCKY_JINGLE_TRANSPORT_STATE_CONNECTED;
  priv->state = WOCKY_JINGLE_TRANSPORT_STATE_CONNECTING;
}

static void
new_local_candidates (WockyJingleTransportIface *obj, GList *new_candidates)
{
  JingleTransportIBB *t = GABBLE_JINGLE_TRANSPORT_IBB (obj);
  JingleTransportIBBPrivate *priv = t->priv;

  DEBUG ("called %p [%p]. Why?", priv, new_candidates);
}

static GList *
get_remote_candidates (WockyJingleTransportIface *obj)
{
  JingleTransportIBB *t = GABBLE_JINGLE_TRANSPORT_IBB (obj);
  JingleTransportIBBPrivate *priv = t->priv;

  DEBUG ("called %p [%p] and nothing to offer.", t, priv);
  return NULL;
}

static GList *
get_local_candidates (WockyJingleTransportIface *obj)
{
  JingleTransportIBB *t = GABBLE_JINGLE_TRANSPORT_IBB (obj);
  JingleTransportIBBPrivate *priv = t->priv;

  DEBUG ("called %p [%p] but nothing to offer", t, priv);
  return NULL;
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
  /* Optional calls
  klass->inject_candidates = inject_candidates;
  klass->send_candidates = send_candidates;
  klass->get_credentials = get_credentials;
  */
}

void
jingle_transport_ibb_register (WockyJingleFactory *factory)
{
  wocky_jingle_factory_register_transport (factory,
      NS_JINGLE_TRANSPORT_IBB, GABBLE_TYPE_JINGLE_TRANSPORT_IBB);
}

