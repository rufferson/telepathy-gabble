/*
 * bytestream-socks5.c - Source for GabbleBytestreamSocks5
 * Copyright (C) 2006 Youness Alaoui <kakaroto@kakaroto.homelinux.net>
 * Copyright (C) 2007-2008 Collabora Ltd.
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
#include "bytestream-socks5.h"

#include <gibber/gibber-sockets.h>

#include <errno.h>

/* on Darwin, net/if.h requires sys/sockets.h, which is included by
 * gibber-sockets.h; so this must come after that header */
#ifdef HAVE_NET_IF_H
# include <net/if.h>
#endif

#include <string.h>
#include <sys/types.h>

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#ifdef HAVE_IFADDRS_H
 #include <ifaddrs.h>
#endif

#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>

#include <telepathy-glib/telepathy-glib.h>
#include <telepathy-glib/telepathy-glib-dbus.h>

#include <gibber/gibber-transport.h>
#include <gibber/gibber-tcp-transport.h>
#include <gibber/gibber-listener.h>

#define DEBUG_FLAG GABBLE_DEBUG_BYTESTREAM

#include "bytestream-factory.h"
#include "bytestream-iface.h"
#include "connection.h"
#include "conn-util.h"
#include "debug.h"
#include "disco.h"
#include "gabble-signals-marshal.h"
#include "namespaces.h"
#include "util.h"

static void
bytestream_iface_init (gpointer g_iface, gpointer iface_data);

G_DEFINE_TYPE_WITH_CODE (GabbleBytestreamSocks5, gabble_bytestream_socks5,
    G_TYPE_OBJECT,
    G_IMPLEMENT_INTERFACE (GABBLE_TYPE_BYTESTREAM_IFACE,
      bytestream_iface_init));

/* properties */
enum
{
  PROP_CONNECTION = 1,
  PROP_PEER_HANDLE,
  PROP_PEER_HANDLE_TYPE,
  PROP_STREAM_ID,
  PROP_STREAM_INIT_ID,
  PROP_PEER_JID,
  PROP_PEER_RESOURCE,
  PROP_STATE,
  PROP_PROTOCOL,
  PROP_SELF_JID,
  PROP_MANAGED,
  LAST_PROPERTY
};

enum _Socks5State
{
  SOCKS5_STATE_INVALID,
  SOCKS5_STATE_TARGET_TRYING_CONNECT,
  SOCKS5_STATE_TARGET_AUTH_REQUEST_SENT,
  SOCKS5_STATE_TARGET_CONNECT_REQUESTED,
  SOCKS5_STATE_CONNECTED,
  SOCKS5_STATE_INITIATOR_OFFER_SENT,
  SOCKS5_STATE_INITIATOR_AWAITING_AUTH_REQUEST,
  SOCKS5_STATE_INITIATOR_AWAITING_COMMAND,
  SOCKS5_STATE_INITIATOR_TRYING_CONNECT,
  SOCKS5_STATE_INITIATOR_AUTH_REQUEST_SENT,
  SOCKS5_STATE_INITIATOR_CONNECT_REQUESTED,
  SOCKS5_STATE_INITIATOR_ACTIVATION_SENT,
  SOCKS5_STATE_ERROR
};

typedef enum _Socks5State Socks5State;

/* SOCKS5 commands */
#define SOCKS5_VERSION     0x05
#define SOCKS5_CMD_CONNECT 0x01
#define SOCKS5_RESERVED    0x00
#define SOCKS5_ATYP_DOMAIN 0x03
#define SOCKS5_STATUS_OK   0x00
#define SOCKS5_AUTH_NONE   0x00

#define SHA1_LENGTH 40
#define SOCKS5_CONNECT_LENGTH (7 + SHA1_LENGTH)
/* VER + CMD/REP + RSV + ATYP + PORT (2) */
#define SOCKS5_MIN_LENGTH 6

#define CONNECT_REPLY_TIMEOUT 30
#define CONNECT_TIMEOUT 10

struct _Streamhost
{
  gchar *jid;
  gchar *host;
  guint16 port;
};
typedef struct _Streamhost Streamhost;

static Streamhost *
streamhost_new (const gchar *jid,
                const gchar *host,
                guint16 port)
{
  Streamhost *streamhost;

  g_return_val_if_fail (jid != NULL, NULL);
  g_return_val_if_fail (host != NULL, NULL);

  streamhost = g_slice_new0 (Streamhost);
  streamhost->jid = g_strdup (jid);
  streamhost->host = g_strdup (host);
  streamhost->port = port;

  return streamhost;
}

static void
streamhost_free (Streamhost *streamhost)
{
  if (streamhost == NULL)
    return;

  g_free (streamhost->jid);
  g_free (streamhost->host);

  g_slice_free (Streamhost, streamhost);
}

struct _GabbleBytestreamSocks5Private
{
  GabbleConnection *conn;
  TpHandle peer_handle;
  gchar *stream_id;
  gchar *stream_init_id;
  gchar *peer_resource;
  GabbleBytestreamState bytestream_state;
  guint managed;
  gchar *peer_jid;
  gchar *self_full_jid;
  gchar *proxy_jid;
  /* TRUE if the peer of this bytestream is a muc contact */
  gboolean muc_contact;

  /* List of Streamhost */
  GSList *streamhosts;

  /* Connections to streamhosts are async, so we keep the IQ set message
   * around */
  WockyStanza *msg_for_acknowledge_connection;

  Socks5State socks5_state;
  GibberTransport *transport;
  gboolean write_blocked;
  gboolean read_blocked;
  GibberListener *listener;
  guint timer_id;

  GString *read_buffer;

  gboolean dispose_has_run;
};

#define GABBLE_BYTESTREAM_SOCKS5_GET_PRIVATE(obj) ((obj)->priv)

static void socks5_connect (GabbleBytestreamSocks5 *self);

static void gabble_bytestream_socks5_close (GabbleBytestreamIface *iface,
    GError *error);

static void socks5_error (GabbleBytestreamSocks5 *self);

static void transport_handler (GibberTransport *transport,
    GibberBuffer *data, gpointer user_data);

static void
gabble_bytestream_socks5_init (GabbleBytestreamSocks5 *self)
{
  GabbleBytestreamSocks5Private *priv = G_TYPE_INSTANCE_GET_PRIVATE (self,
      GABBLE_TYPE_BYTESTREAM_SOCKS5, GabbleBytestreamSocks5Private);

  self->priv = priv;
}

static void
stop_timer (GabbleBytestreamSocks5 *self)
{
  GabbleBytestreamSocks5Private *priv = GABBLE_BYTESTREAM_SOCKS5_GET_PRIVATE (
      self);

  if (priv->timer_id == 0)
    return;

  g_source_remove (priv->timer_id);
  priv->timer_id = 0;
}

static void
gabble_bytestream_socks5_dispose (GObject *object)
{
  GabbleBytestreamSocks5 *self = GABBLE_BYTESTREAM_SOCKS5 (object);
  GabbleBytestreamSocks5Private *priv =
      GABBLE_BYTESTREAM_SOCKS5_GET_PRIVATE (self);

  if (priv->dispose_has_run)
    return;

  priv->dispose_has_run = TRUE;

  stop_timer (self);

  if (priv->bytestream_state != GABBLE_BYTESTREAM_STATE_CLOSED)
    {
      gabble_bytestream_iface_close (GABBLE_BYTESTREAM_IFACE (self), NULL);
    }

  tp_clear_object (&priv->transport);
  tp_clear_object (&priv->listener);

  G_OBJECT_CLASS (gabble_bytestream_socks5_parent_class)->dispose (object);
}

static void
gabble_bytestream_socks5_finalize (GObject *object)
{
  GabbleBytestreamSocks5 *self = GABBLE_BYTESTREAM_SOCKS5 (object);
  GabbleBytestreamSocks5Private *priv =
      GABBLE_BYTESTREAM_SOCKS5_GET_PRIVATE (self);

  g_free (priv->stream_id);
  g_free (priv->stream_init_id);
  g_free (priv->peer_resource);
  g_free (priv->peer_jid);
  g_free (priv->self_full_jid);
  g_free (priv->proxy_jid);

  g_slist_foreach (priv->streamhosts, (GFunc) streamhost_free, NULL);
  g_slist_free (priv->streamhosts);

  G_OBJECT_CLASS (gabble_bytestream_socks5_parent_class)->finalize (object);
}

static void
gabble_bytestream_socks5_get_property (GObject *object,
                                       guint property_id,
                                       GValue *value,
                                       GParamSpec *pspec)
{
  GabbleBytestreamSocks5 *self = GABBLE_BYTESTREAM_SOCKS5 (object);
  GabbleBytestreamSocks5Private *priv =
      GABBLE_BYTESTREAM_SOCKS5_GET_PRIVATE (self);

  switch (property_id)
    {
      case PROP_CONNECTION:
        g_value_set_object (value, priv->conn);
        break;
      case PROP_PEER_HANDLE:
        g_value_set_uint (value, priv->peer_handle);
        break;
      case PROP_PEER_HANDLE_TYPE:
        g_value_set_uint (value, TP_HANDLE_TYPE_CONTACT);
        break;
      case PROP_STREAM_ID:
        g_value_set_string (value, priv->stream_id);
        break;
      case PROP_STREAM_INIT_ID:
        g_value_set_string (value, priv->stream_init_id);
        break;
      case PROP_PEER_RESOURCE:
        g_value_set_string (value, priv->peer_resource);
        break;
      case PROP_PEER_JID:
        g_value_set_string (value, priv->peer_jid);
        break;
      case PROP_STATE:
        g_value_set_uint (value, priv->bytestream_state);
        break;
      case PROP_MANAGED:
        g_value_set_uint (value, priv->managed);
        break;
      case PROP_PROTOCOL:
        g_value_set_string (value, NS_BYTESTREAMS);
        break;
      case PROP_SELF_JID:
        g_value_set_string (value, priv->self_full_jid);
        break;
      default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
        break;
    }
}

static void
gabble_bytestream_socks5_set_property (GObject *object,
                                       guint property_id,
                                       const GValue *value,
                                       GParamSpec *pspec)
{
  GabbleBytestreamSocks5 *self = GABBLE_BYTESTREAM_SOCKS5 (object);
  GabbleBytestreamSocks5Private *priv =
      GABBLE_BYTESTREAM_SOCKS5_GET_PRIVATE (self);

  switch (property_id)
    {
      case PROP_CONNECTION:
        priv->conn = g_value_get_object (value);
        break;
      case PROP_PEER_HANDLE:
        priv->peer_handle = g_value_get_uint (value);
        break;
      case PROP_STREAM_ID:
        g_free (priv->stream_id);
        priv->stream_id = g_value_dup_string (value);
        break;
      case PROP_STREAM_INIT_ID:
        g_free (priv->stream_init_id);
        priv->stream_init_id = g_value_dup_string (value);
        break;
      case PROP_PEER_RESOURCE:
        g_free (priv->peer_resource);
        priv->peer_resource = g_value_dup_string (value);
        break;
      case PROP_STATE:
        if (priv->bytestream_state != g_value_get_uint (value))
            {
              priv->bytestream_state = g_value_get_uint (value);
              g_signal_emit_by_name (object, "state-changed",
                  priv->bytestream_state);
            }
        break;
      case PROP_MANAGED:
        priv->managed = g_value_get_uint (value);
        break;
      case PROP_SELF_JID:
        g_free (priv->self_full_jid);
        priv->self_full_jid = g_value_dup_string (value);
        break;
      default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
        break;
    }
}

static GObject *
gabble_bytestream_socks5_constructor (GType type,
                                      guint n_props,
                                      GObjectConstructParam *props)
{
  GObject *obj;
  GabbleBytestreamSocks5Private *priv;
  TpBaseConnection *base_conn;
  TpHandleRepoIface *contact_repo, *room_repo;
  const gchar *jid;

  obj = G_OBJECT_CLASS (gabble_bytestream_socks5_parent_class)->
           constructor (type, n_props, props);

  priv =
      GABBLE_BYTESTREAM_SOCKS5_GET_PRIVATE (GABBLE_BYTESTREAM_SOCKS5 (obj));

  g_assert (priv->conn != NULL);
  g_assert (priv->peer_handle != 0);
  g_assert (priv->stream_id != NULL);

  base_conn = TP_BASE_CONNECTION (priv->conn);
  contact_repo = tp_base_connection_get_handles (base_conn,
      TP_HANDLE_TYPE_CONTACT);
  room_repo = tp_base_connection_get_handles (base_conn,
      TP_HANDLE_TYPE_ROOM);

  jid = tp_handle_inspect (contact_repo, priv->peer_handle);

  if (priv->peer_resource != NULL)
    priv->peer_jid = g_strdup_printf ("%s/%s", jid, priv->peer_resource);
  else
    priv->peer_jid = g_strdup (jid);

  g_assert (priv->self_full_jid != NULL);

  priv->muc_contact = (gabble_get_room_handle_from_jid (room_repo,
        priv->peer_jid) != 0);

  return obj;
}

static void
gabble_bytestream_socks5_class_init (
    GabbleBytestreamSocks5Class *gabble_bytestream_socks5_class)
{
  GObjectClass *object_class =
      G_OBJECT_CLASS (gabble_bytestream_socks5_class);
  GParamSpec *param_spec;

  g_type_class_add_private (gabble_bytestream_socks5_class,
      sizeof (GabbleBytestreamSocks5Private));

  object_class->dispose = gabble_bytestream_socks5_dispose;
  object_class->finalize = gabble_bytestream_socks5_finalize;

  object_class->get_property = gabble_bytestream_socks5_get_property;
  object_class->set_property = gabble_bytestream_socks5_set_property;
  object_class->constructor = gabble_bytestream_socks5_constructor;

   g_object_class_override_property (object_class, PROP_CONNECTION,
      "connection");
   g_object_class_override_property (object_class, PROP_PEER_HANDLE,
       "peer-handle");
   g_object_class_override_property (object_class, PROP_PEER_HANDLE_TYPE,
       "peer-handle-type");
   g_object_class_override_property (object_class, PROP_STREAM_ID,
       "stream-id");
   g_object_class_override_property (object_class, PROP_PEER_JID,
       "peer-jid");
   g_object_class_override_property (object_class, PROP_STATE,
       "state");
   g_object_class_override_property (object_class, PROP_PROTOCOL,
       "protocol");
   g_object_class_override_property (object_class, PROP_MANAGED,
       "managed-state");

  param_spec = g_param_spec_string (
      "peer-resource",
      "Peer resource",
      "the resource used by the remote peer during the SI, if any",
      NULL,
      G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS);
  g_object_class_install_property (object_class, PROP_PEER_RESOURCE,
      param_spec);

  param_spec = g_param_spec_string (
      "stream-init-id",
      "stream init ID",
      "the iq ID of the SI request, if any",
      NULL,
      G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS);
  g_object_class_install_property (object_class, PROP_STREAM_INIT_ID,
      param_spec);

  param_spec = g_param_spec_string (
      "self-jid",
      "Our self jid",
      "Either a contact full jid or a muc jid",
      NULL,
      G_PARAM_CONSTRUCT_ONLY  | G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS);
  g_object_class_install_property (object_class, PROP_SELF_JID,
      param_spec);
}

static gboolean
write_to_transport (GabbleBytestreamSocks5 *self,
                    const gchar *data,
                    guint len,
                    GError **error)
{
  GabbleBytestreamSocks5Private *priv =
      GABBLE_BYTESTREAM_SOCKS5_GET_PRIVATE (self);

  if (!gibber_transport_send (priv->transport, (const guint8 *) data, len,
        error))
    {
      return FALSE;
    }

  return TRUE;
}

static void
transport_connected_cb (GibberTransport *transport,
                        GabbleBytestreamSocks5 *self)
{
  GabbleBytestreamSocks5Private *priv =
    GABBLE_BYTESTREAM_SOCKS5_GET_PRIVATE (self);

  stop_timer (self);

  if (priv->socks5_state == SOCKS5_STATE_TARGET_TRYING_CONNECT ||
      priv->socks5_state == SOCKS5_STATE_INITIATOR_TRYING_CONNECT)
    {
      gchar msg[3];

      DEBUG ("transport is connected. Sending auth request");

      msg[0] = SOCKS5_VERSION;
      /* Number of auth methods we are offering, we support just
       * SOCKS5_AUTH_NONE */
      msg[1] = 1;
      msg[2] = SOCKS5_AUTH_NONE;

      write_to_transport (self, msg, 3, NULL);

      if (priv->socks5_state == SOCKS5_STATE_TARGET_TRYING_CONNECT)
        priv->socks5_state = SOCKS5_STATE_TARGET_AUTH_REQUEST_SENT;
      else
        priv->socks5_state = SOCKS5_STATE_INITIATOR_AUTH_REQUEST_SENT;
    }
}

static void
transport_disconnected_cb (GibberTransport *transport,
                           GabbleBytestreamSocks5 *self)
{
  stop_timer (self);
  DEBUG ("Sock5 transport disconnected");
  socks5_error (self);
}

static void
change_write_blocked_state (GabbleBytestreamSocks5 *self,
                            gboolean blocked)
{
  GabbleBytestreamSocks5Private *priv =
      GABBLE_BYTESTREAM_SOCKS5_GET_PRIVATE (self);

  if (priv->write_blocked == blocked)
    return;

  priv->write_blocked = blocked;
  g_signal_emit_by_name (self, "write-blocked", blocked);
}

static void
socks5_close_transport (GabbleBytestreamSocks5 *self)
{
  GabbleBytestreamSocks5Private *priv =
    GABBLE_BYTESTREAM_SOCKS5_GET_PRIVATE (self);

  if (priv->read_buffer != NULL)
    {
      g_string_free (priv->read_buffer, TRUE);
      priv->read_buffer = NULL;
    }

  if (priv->transport == NULL)
    return;

  g_signal_handlers_disconnect_matched (priv->transport,
      G_SIGNAL_MATCH_DATA, 0, 0, NULL, NULL, self);

  tp_clear_object (&priv->transport);
}

static void
bytestream_closed (GabbleBytestreamSocks5 *self)
{
  socks5_close_transport (self);
  g_object_set (self, "state", GABBLE_BYTESTREAM_STATE_CLOSED, NULL);
}

static void
transport_buffer_empty_cb (GibberTransport *transport,
                           GabbleBytestreamSocks5 *self)
{
  GabbleBytestreamSocks5Private *priv = GABBLE_BYTESTREAM_SOCKS5_GET_PRIVATE
      (self);

  if (priv->bytestream_state == GABBLE_BYTESTREAM_STATE_CLOSING)
    {
      DEBUG ("buffer is now empty. Bytestream can be closed");
      bytestream_closed (self);
    }
  else if (priv->write_blocked)
    {
      change_write_blocked_state (self, FALSE);
    }
}

static void
set_transport (GabbleBytestreamSocks5 *self,
               GibberTransport *transport)
{
  GabbleBytestreamSocks5Private *priv =
      GABBLE_BYTESTREAM_SOCKS5_GET_PRIVATE (self);

  priv->transport = g_object_ref (transport);

  g_assert (priv->read_buffer == NULL);
  priv->read_buffer = g_string_sized_new (4096);

  gibber_transport_set_handler (transport, transport_handler, self);

  g_signal_connect (transport, "connected",
      G_CALLBACK (transport_connected_cb), self);
  g_signal_connect (transport, "disconnected",
      G_CALLBACK (transport_disconnected_cb), self);
  g_signal_connect (priv->transport, "buffer-empty",
      G_CALLBACK (transport_buffer_empty_cb), self);
}

static void
socks5_error (GabbleBytestreamSocks5 *self)
{
  GabbleBytestreamSocks5Private *priv =
      GABBLE_BYTESTREAM_SOCKS5_GET_PRIVATE (self);
  WockyPorter *porter = wocky_session_get_porter (priv->conn->session);
  Socks5State previous_state;

  stop_timer (self);

  previous_state = priv->socks5_state;
  priv->socks5_state = SOCKS5_STATE_ERROR;

  switch (previous_state)
    {
      case SOCKS5_STATE_TARGET_TRYING_CONNECT:
      case SOCKS5_STATE_TARGET_AUTH_REQUEST_SENT:
      case SOCKS5_STATE_TARGET_CONNECT_REQUESTED:
        /* The attempt for connect to the streamhost failed */
        socks5_close_transport (self);

        if (priv->streamhosts != NULL)
          {
            /* Remove the failed streamhost */
            streamhost_free (priv->streamhosts->data);
            priv->streamhosts = g_slist_delete_link (priv->streamhosts,
                priv->streamhosts);
          }

        if (priv->streamhosts != NULL)
          {
            DEBUG ("connection to streamhost failed, trying the next one");

            socks5_connect (self);
            return;
          }

        DEBUG ("no more streamhosts to try");

        g_signal_emit_by_name (self, "connection-error");

        if (priv->managed > 0)
	  break;

        g_assert (priv->msg_for_acknowledge_connection != NULL);
        wocky_porter_send_iq_error (porter,
            priv->msg_for_acknowledge_connection,
            WOCKY_XMPP_ERROR_ITEM_NOT_FOUND,
            "impossible to connect to any streamhost");

        g_object_unref (priv->msg_for_acknowledge_connection);
        priv->msg_for_acknowledge_connection = NULL;
        break;

      case SOCKS5_STATE_INITIATOR_AWAITING_AUTH_REQUEST:
      case SOCKS5_STATE_INITIATOR_AWAITING_COMMAND:
        DEBUG ("Something goes wrong during SOCKS5 negotiation. Don't close "
            "the bytestream yet as the target can still try other streamhosts");
        break;

      default:
        DEBUG ("error, closing the connection\n");
        gabble_bytestream_socks5_close (GABBLE_BYTESTREAM_IFACE (self), NULL);
    }
}

static gchar *
compute_domain (const gchar *sid,
                const gchar *initiator,
                const gchar *target)
{
  gchar *unhashed_domain;
  gchar *domain;

  unhashed_domain = g_strconcat (sid, initiator, target, NULL);
  domain = sha1_hex (unhashed_domain, strlen (unhashed_domain));

  g_free (unhashed_domain);
  return domain;
}

static gboolean
check_domain (const gchar *domain,
              guint8 len,
              const gchar *expected)
{
  if (len != SHA1_LENGTH || strncmp (domain, expected, SHA1_LENGTH) != 0)
    {
      DEBUG ("Wrong domain hash: %s (expected: %s)", domain, expected);
      return FALSE;
    }

  return TRUE;
}

static gboolean
socks5_timer_cb (gpointer data)
{
  GabbleBytestreamSocks5 *self = GABBLE_BYTESTREAM_SOCKS5 (data);

  DEBUG ("Timed out; closing SOCKS5 connection");

  socks5_error (self);
  return FALSE;
}

static void
start_timer (GabbleBytestreamSocks5 *self,
             guint seconds)
{
  GabbleBytestreamSocks5Private *priv = GABBLE_BYTESTREAM_SOCKS5_GET_PRIVATE (
      self);

  g_assert (priv->timer_id == 0);

  priv->timer_id = g_timeout_add_seconds (seconds, socks5_timer_cb, self);
}

static void
target_got_connect_reply (GabbleBytestreamSocks5 *self)
{
  GabbleBytestreamSocks5Private *priv = GABBLE_BYTESTREAM_SOCKS5_GET_PRIVATE (
      self);
  WockyPorter *porter = wocky_session_get_porter (priv->conn->session);
  Streamhost *current_streamhost;

  DEBUG ("Received CONNECT reply. Socks5 stream connected. "
      "Bytestream is now open");
  priv->socks5_state = SOCKS5_STATE_CONNECTED;
  g_object_set (self, "state", GABBLE_BYTESTREAM_STATE_OPEN, NULL);

  /* Acknowledge the connection */
  current_streamhost = priv->streamhosts->data;
  if (priv->managed > 0)
    {
      /* Streamhost is binary equivalent to GabbleSocks5Proxy so... */
      g_signal_emit_by_name (G_OBJECT (self), "streamhost-used",
	  current_streamhost);
    }
  else
    {
      wocky_porter_acknowledge_iq (porter, priv->msg_for_acknowledge_connection,
      '(', "query", ':', NS_BYTESTREAMS,
        /* streamhost-used informs the other end of the streamhost we
         * decided to use. In case of a direct connetion this is useless
         * but if we are using an external proxy we need to know which
         * one was selected */
        '(', "streamhost-used",
          '@', "jid", current_streamhost->jid,
        ')',
      ')', NULL);
    }

  if (priv->read_blocked)
    {
      DEBUG ("reading has been blocked. Blocking now as the socks5 "
          "negotiation is done");
      gibber_transport_block_receiving (priv->transport, TRUE);
    }
}

static void
socks5_activation_reply_cb (
    GObject *source,
    GAsyncResult *result,
    gpointer user_data)
{
  TpWeakRef *weak_ref = user_data;
  GabbleBytestreamSocks5 *self = tp_weak_ref_dup_object (weak_ref);
  GabbleBytestreamSocks5Private *priv;
  WockyStanza *reply_msg = NULL;

  tp_weak_ref_destroy (weak_ref);
  if (self == NULL)
    return;
  priv = self->priv;

  if (!conn_util_send_iq_finish (GABBLE_CONNECTION (source), result, &reply_msg, NULL))
    {
      DEBUG ("Activation failed");
      goto activation_failed;
    }

  if (priv->socks5_state != SOCKS5_STATE_INITIATOR_ACTIVATION_SENT)
    {
      DEBUG ("We are not waiting for an activation reply (state: %u)",
          priv->socks5_state);
      goto activation_failed;
    }

  DEBUG ("Proxy activated the bytestream. It's now open");

  priv->socks5_state = SOCKS5_STATE_CONNECTED;
  g_object_set (self, "state", GABBLE_BYTESTREAM_STATE_OPEN, NULL);
  /* We can read data from the sock5 socket now */
  gibber_transport_block_receiving (priv->transport, FALSE);
  goto out;

activation_failed:
  g_signal_emit_by_name (self, "connection-error");
  g_object_set (self, "state", GABBLE_BYTESTREAM_STATE_CLOSED, NULL);

out:
  g_clear_object (&reply_msg);
  g_object_unref (self);
}

static void
initiator_got_connect_reply (GabbleBytestreamSocks5 *self)
{
  GabbleBytestreamSocks5Private *priv = GABBLE_BYTESTREAM_SOCKS5_GET_PRIVATE (
      self);
  WockyStanza *iq;

  DEBUG ("Got CONNECT reply. SOCKS5 negotiation with proxy is done. "
      "Sending activation IQ");

  iq = wocky_stanza_build (WOCKY_STANZA_TYPE_IQ, WOCKY_STANZA_SUB_TYPE_SET,
      NULL, priv->proxy_jid,
      '(', "query",
        ':', NS_BYTESTREAMS,
        '@', "sid", priv->stream_id,
        '(', "activate", '$', priv->peer_jid, ')',
      ')', NULL);

  priv->socks5_state = SOCKS5_STATE_INITIATOR_ACTIVATION_SENT;

  /* Block reading while waiting for the activation reply */
  gibber_transport_block_receiving (priv->transport, TRUE);

  conn_util_send_iq_async (priv->conn, iq, NULL,
      socks5_activation_reply_cb, tp_weak_ref_new (self, NULL, NULL));
  g_object_unref (iq);
}

/* Process the received data and returns the number of bytes that have been
 * used */
static gssize
socks5_handle_received_data (GabbleBytestreamSocks5 *self,
                             GString *string)
{
  GabbleBytestreamSocks5Private *priv =
      GABBLE_BYTESTREAM_SOCKS5_GET_PRIVATE (self);
  gchar msg[SOCKS5_CONNECT_LENGTH];
  guint auth_len;
  guint i;
  gchar *domain;
  /* the length of the BND.ADDR field */
  guint8 addr_len;
  gsize len;

  switch (priv->socks5_state)
    {
      case SOCKS5_STATE_TARGET_AUTH_REQUEST_SENT:
      case SOCKS5_STATE_INITIATOR_AUTH_REQUEST_SENT:
        /* We sent an authorization request and we are awaiting for a
         * response, the response is 2 bytes-long */
        if (string->len < 2)
          return 0;

        if (string->str[0] != SOCKS5_VERSION ||
            string->str[1] != SOCKS5_STATUS_OK)
          {
            DEBUG ("Authentication failed");

            socks5_error (self);
            return -1;
          }

        /* We have been authorized, let's send a CONNECT command */

        DEBUG ("Received auth reply. Sending CONNECT command");

        if (priv->socks5_state == SOCKS5_STATE_TARGET_AUTH_REQUEST_SENT)
          {
            domain = compute_domain (priv->stream_id, priv->peer_jid,
                priv->self_full_jid);
          }
        else
          {
            /* SOCKS5_STATE_INITIATOR_AUTH_REQUEST_SENT */
            domain = compute_domain (priv->stream_id, priv->self_full_jid,
                priv->peer_jid);
          }

        msg[0] = SOCKS5_VERSION;
        msg[1] = SOCKS5_CMD_CONNECT;
        msg[2] = SOCKS5_RESERVED;
        msg[3] = SOCKS5_ATYP_DOMAIN;
        /* Length of a hex SHA1 */
        msg[4] = 40;
        /* Domain name: SHA-1(sid + initiator + target) */
        memcpy (&msg[5], domain, 40);
        /* Port: 0 */
        msg[45] = 0x00;
        msg[46] = 0x00;

        g_free (domain);

        write_to_transport (self, msg, SOCKS5_CONNECT_LENGTH, NULL);

        if (priv->socks5_state == SOCKS5_STATE_TARGET_AUTH_REQUEST_SENT)
          priv->socks5_state = SOCKS5_STATE_TARGET_CONNECT_REQUESTED;
        else
          /* SOCKS5_STATE_INITIATOR_AUTH_REQUEST_SENT */
          priv->socks5_state = SOCKS5_STATE_INITIATOR_CONNECT_REQUESTED;

        /* Older version of Gabble (pre 0.7.22) are bugged and just send 2
         * bytes as CONNECT reply. We set a timer to not wait the full reply
         * forever if we are connected to such Gabble.
         * Once timed out, the SOCKS5 negotiation will fail and Gabble
         * will switch to IBB as a fallback. */
        start_timer (self, CONNECT_REPLY_TIMEOUT);

        return 2;

      case SOCKS5_STATE_TARGET_CONNECT_REQUESTED:
      case SOCKS5_STATE_INITIATOR_CONNECT_REQUESTED:
        /* We sent a CONNECT request and are awaiting for the response */
        if (string->len < SOCKS5_MIN_LENGTH)
          return 0;

        if (string->str[0] != SOCKS5_VERSION ||
            string->str[1] != SOCKS5_STATUS_OK ||
            string->str[2] != SOCKS5_RESERVED)
          {
            DEBUG ("Connection refused");

            socks5_error (self);
            return -1;
          }

        if (string->str[3] == SOCKS5_ATYP_DOMAIN)
          {
            /* correct domain. The first byte of the domain contains its
             * length */
            addr_len = (guint8) string->str[4];
            addr_len += 1;
          }
        else if (string->str[3] == 0x00)
          {
            DEBUG ("Got 0x00 as domain. Pretend it's ok to be able to interop "
                "with ejabberd < 2.0.2");
            addr_len = 0;
          }
        else
          {
            DEBUG ("Wrong domain");

            socks5_error (self);
            return -1;
          }

        if ((guint8) string->len < SOCKS5_MIN_LENGTH + addr_len)
          /* We didn't receive the full packet yet */
          return 0;

        stop_timer (self);

        if (
            /* first half of the port number */
            string->str[4 + addr_len] != 0 ||
            /* second half of the port number */
            string->str[5 + addr_len] != 0)
          {
            DEBUG ("Connection refused");

            socks5_error (self);
            return -1;
          }

        if (priv->socks5_state == SOCKS5_STATE_TARGET_CONNECT_REQUESTED)
          {
            domain = compute_domain (priv->stream_id, priv->peer_jid,
                priv->self_full_jid);
          }
        else
          {
            /* SOCKS5_STATE_INITIATOR_CONNECT_REQUESTED */
            domain = compute_domain (priv->stream_id, priv->self_full_jid,
                priv->peer_jid);
          }

        if (addr_len > 0)
          {
            if (!check_domain (&string->str[5], addr_len - 1, domain))
              {
                /* Thanks Pidgin... */
                DEBUG ("Ignoring to interop with buggy implementations");
              }
          }

        g_free (domain);

        if (priv->socks5_state == SOCKS5_STATE_TARGET_CONNECT_REQUESTED)
          target_got_connect_reply (self);
        else
          /* SOCKS5_STATE_INITIATOR_CONNECT_REQUESTED */
          initiator_got_connect_reply (self);

        return SOCKS5_MIN_LENGTH + addr_len;

      case SOCKS5_STATE_INITIATOR_AWAITING_AUTH_REQUEST:
        /* A client connected to us and we are awaiting for the authorization
         * request (at least 2 bytes) */
        if (string->len < 2)
          return 0;

        if (string->str[0] != SOCKS5_VERSION)
          {
            DEBUG ("Authentication failed");

            socks5_error (self);
            return -1;
          }

        /* The auth request string is SOCKS5_VERSION + # of methods + methods */
        auth_len = string->str[1] + 2;
        if (string->len < auth_len)
          /* We are still receiving some auth method */
          return 0;

        for (i = 2; i < auth_len; i++)
          {
            if (string->str[i] == SOCKS5_AUTH_NONE)
              {
                /* Authorize the connection */
                msg[0] = SOCKS5_VERSION;
                msg[1] = SOCKS5_AUTH_NONE;

                DEBUG ("Received auth request. Sending auth reply");
                write_to_transport (self, msg, 2, NULL);

                priv->socks5_state = SOCKS5_STATE_INITIATOR_AWAITING_COMMAND;

                return auth_len;
              }
          }

        DEBUG ("Unauthenticated access is not supported by the streamhost");

        socks5_error (self);

        return -1;

      case SOCKS5_STATE_INITIATOR_AWAITING_COMMAND:
        /* The client has been authorized and we are waiting for a command,
         * the only one supported by the SOCKS5 bytestreams XEP is
         * CONNECT with:
         *  - ATYP = DOMAIN
         *  - PORT = 0
         *  - DOMAIN = SHA1(sid + initiator + target)
         */
        if (string->len < SOCKS5_MIN_LENGTH)
          return 0;

        addr_len = (guint8) string->str[4];
        /* the first byte is the length */
        addr_len += 1;

        if ((guint8) string->len < SOCKS5_MIN_LENGTH + addr_len)
          /* We didn't receive the full packet yet */
          return 0;

        if (string->str[0] != SOCKS5_VERSION ||
            string->str[1] != SOCKS5_CMD_CONNECT ||
            string->str[2] != SOCKS5_RESERVED ||
            string->str[3] != SOCKS5_ATYP_DOMAIN ||
            /* first half of the port number */
            string->str[4 + addr_len] != 0 ||
            /* second half of the port number */
            string->str[5 + addr_len] != 0)
          {
            DEBUG ("Invalid SOCKS5 connect message");

            socks5_error (self);
            return -1;
          }

        domain = compute_domain (priv->stream_id, priv->self_full_jid,
            priv->peer_jid);

        if (!check_domain (&string->str[5], addr_len - 1, domain))
          {
            DEBUG ("Reject connection to prevent spoofing");
            socks5_close_transport (self);
            socks5_error (self);
            g_free (domain);
            return -1;
          }

        msg[0] = SOCKS5_VERSION;
        msg[1] = SOCKS5_STATUS_OK;
        msg[2] = SOCKS5_RESERVED;
        msg[3] = SOCKS5_ATYP_DOMAIN;
        msg[4] = SHA1_LENGTH;
        /* Domain name: SHA-1(sid + initiator + target) */
        memcpy (&msg[5], domain, 40);
        /* Port: 0 */
        msg[45] = 0x00;
        msg[46] = 0x00;

        g_free (domain);

        DEBUG ("Received CONNECT cmd. Sending CONNECT reply");
        write_to_transport (self, msg, 47, NULL);

        priv->socks5_state = SOCKS5_STATE_CONNECTED;

        /* Sock5 is connected but the bytestream is not open yet as we need
         * to wait for the IQ reply. Stop reading until the bytestream
         * is open to avoid data loss. */
        gibber_transport_block_receiving (priv->transport, TRUE);

        DEBUG ("sock5 stream connected. Stop to listen for connections");
        g_assert (priv->listener != NULL);
        tp_clear_object (&priv->listener);

        return SOCKS5_MIN_LENGTH + addr_len;

      case SOCKS5_STATE_CONNECTED:
        /* We are connected, everything we receive now is data */

        /* store the buffer len because if something went wront in the
         * data-received callback, the bytestream could be freed and so the
         * priv->read_buffer */
        len = string->len;
        g_signal_emit_by_name (G_OBJECT (self), "data-received",
            priv->peer_handle, string);

        return len;

      case SOCKS5_STATE_ERROR:
        /* An error occurred and the channel will be closed in an idle
         * callback, so let's just throw away the data we receive */
        DEBUG ("An error occurred, throwing away received data");
        return string->len;

      case SOCKS5_STATE_TARGET_TRYING_CONNECT:
      case SOCKS5_STATE_INITIATOR_TRYING_CONNECT:
        DEBUG ("Impossible to receive data when not yet connected to the "
            "socket");
        break;

      case SOCKS5_STATE_INITIATOR_OFFER_SENT:
        DEBUG ("Shouldn't receive data when we just sent the offer");
        break;

      case SOCKS5_STATE_INITIATOR_ACTIVATION_SENT:
        DEBUG ("Shouldn't receive data before we received activation reply");
        break;

      case SOCKS5_STATE_INVALID:
        DEBUG ("Invalid SOCKS5 state");
        break;
    }

  g_assert_not_reached ();
  return string->len;
}

static void
transport_handler (GibberTransport *transport,
                   GibberBuffer *data,
                   gpointer user_data)

{
  GabbleBytestreamSocks5 *self = GABBLE_BYTESTREAM_SOCKS5 (user_data);
  GabbleBytestreamSocks5Private *priv =
      GABBLE_BYTESTREAM_SOCKS5_GET_PRIVATE (self);
  gssize used_bytes;

  g_assert (priv->read_buffer != NULL);
  g_string_append_len (priv->read_buffer, (const gchar *) data->data,
      data->length);

  /* If something goes wrong in socks5_handle_received_data, the bytestream
   * could be closed and disposed. Ref it to artificially keep this bytestream
   * object alive while we are in this function. */
  g_object_ref (self);

  do
    {
      /* socks5_handle_received_data() processes the data and returns the
       * number of bytes that have been used. 0 means that there is not enough
       * data to do anything, so we just wait for more data from the socket */
      used_bytes = socks5_handle_received_data (self, priv->read_buffer);

      if (priv->read_buffer == NULL)
        /* If something did wrong in socks5_handle_received_data, the
         * bytestream can be closed and so destroyed. */
        break;

      g_string_erase (priv->read_buffer, 0, used_bytes);
    }
  while (used_bytes > 0 && priv->read_buffer->len > 0);

  g_object_unref (self);
}

static void
socks5_connect (GabbleBytestreamSocks5 *self)
{
  GabbleBytestreamSocks5Private *priv =
      GABBLE_BYTESTREAM_SOCKS5_GET_PRIVATE (self);
  Streamhost* streamhost;
  GibberTCPTransport *transport;

  priv->socks5_state = SOCKS5_STATE_TARGET_TRYING_CONNECT;

  if (priv->streamhosts != NULL)
    {
      streamhost = priv->streamhosts->data;
    }
  else
    {
      DEBUG ("No more streamhosts to try, closing");

      socks5_error (self);
      return;
    }

  DEBUG ("Trying streamhost %s on port %d", streamhost->host,
      streamhost->port);

  transport = gibber_tcp_transport_new ();
  set_transport (self, GIBBER_TRANSPORT (transport));
  g_object_unref (transport);

  /* We don't wait to wait for the TCP timeout if the host is unreachable */
  start_timer (self, CONNECT_TIMEOUT);

  gibber_tcp_transport_connect (transport, streamhost->host,
      streamhost->port);

  /* We'll send the auth request once the transport is connected */
}

/**
 * gabble_bytestream_socks5_add_streamhost
 *
 * Adds the streamhost as a candidate for connection.
 */
void
gabble_bytestream_socks5_add_streamhost (GabbleBytestreamSocks5 *self,
                                         WockyNode *streamhost_node)
{
  GabbleBytestreamSocks5Private *priv =
      GABBLE_BYTESTREAM_SOCKS5_GET_PRIVATE (self);
  const gchar *zeroconf;
  const gchar *jid;
  const gchar *host;
  const gchar *portstr;
  gint64 port;

  g_return_if_fail (!tp_strdiff (streamhost_node->name, "streamhost"));

  zeroconf = wocky_node_get_attribute (streamhost_node, "zeroconf");
  if (zeroconf != NULL)
    {
      /* TODO: add suppport for zeroconf */
      DEBUG ("zeroconf streamhosts are not supported");
      return;
    }

  jid = wocky_node_get_attribute (streamhost_node, "jid");
  if (jid == NULL)
    {
      DEBUG ("streamhost doesn't contain a JID");
      return;
    }

  host = wocky_node_get_attribute (streamhost_node, "host");
  if (host == NULL)
    {
      DEBUG ("streamhost doesn't contain a host");
      return;
    }

  portstr = wocky_node_get_attribute (streamhost_node, "port");
  if (portstr == NULL)
    {
      DEBUG ("streamhost doesn't contain a port");
      return;
    }

  port = g_ascii_strtoll (portstr, NULL, 10);
  if (port <= 0 || port > G_MAXUINT16)
    {
      DEBUG ("Invalid port: %s", portstr);
      return;
    }

  if (tp_strdiff (jid, priv->peer_jid) && priv->muc_contact)
    {
      DEBUG ("skip streamhost %s (%s:%"G_GINT64_FORMAT
          "); we don't support relay with muc contact", jid, host, port);
      return;
    }
  gabble_bytestream_iface_add_streamhost (
	  GABBLE_BYTESTREAM_IFACE (self), jid, host, port);
}

static void
add_streamhost (GabbleBytestreamIface *obj,
               const gchar *jid, const gchar *host, guint port)
{
  GabbleBytestreamSocks5 *self = GABBLE_BYTESTREAM_SOCKS5 (obj);
  GabbleBytestreamSocks5Private *priv =
      GABBLE_BYTESTREAM_SOCKS5_GET_PRIVATE (self);
  Streamhost *streamhost;

  DEBUG ("streamhost with jid %s, host %s and port %"G_GUINT32_FORMAT" added",
      jid, host, port);

  streamhost = streamhost_new (jid, host, port);
  priv->streamhosts = g_slist_append (priv->streamhosts, streamhost);
}

/**
 * gabble_bytestream_socks5_connect_to_streamhost
 *
 * Try to connect to a streamhost.
 */
void
gabble_bytestream_socks5_connect_to_streamhost (GabbleBytestreamSocks5 *self,
                                                WockyStanza *msg)

{
  GabbleBytestreamSocks5Private *priv =
      GABBLE_BYTESTREAM_SOCKS5_GET_PRIVATE (self);

  priv->msg_for_acknowledge_connection = g_object_ref (msg);

  socks5_connect (self);
}

/*
 * gabble_bytestream_socks5_send
 *
 * Implements gabble_bytestream_iface_send on GabbleBytestreamIface
 */
static gboolean
gabble_bytestream_socks5_send (GabbleBytestreamIface *iface,
                               guint len,
                               const gchar *str)
{
  GabbleBytestreamSocks5 *self = GABBLE_BYTESTREAM_SOCKS5 (iface);
  GabbleBytestreamSocks5Private *priv =
      GABBLE_BYTESTREAM_SOCKS5_GET_PRIVATE (self);
  GError *error = NULL;

  if (priv->bytestream_state != GABBLE_BYTESTREAM_STATE_OPEN)
    {
      DEBUG ("can't send data through a not open bytestream (state: %d)",
          priv->bytestream_state);
      return FALSE;
    }

  /* if something goes wrong during the sending, the bytestream could be
   * closed and so disposed by the bytestream factory. Ref it to keep it
   * artifically alive if such case happen. */
  g_object_ref (self);

  if (!write_to_transport (self, str, len, &error))
    {
      DEBUG ("sending failed: %s", error->message);

      g_error_free (error);
      gabble_bytestream_iface_close (GABBLE_BYTESTREAM_IFACE (self), NULL);
      g_object_unref (self);
      return FALSE;
    }

  /* If something wennt wrong during the writting, the transport has been closed
   * and so set to NULL. */
  if (priv->transport == NULL)
    {
      g_object_unref (self);
      return FALSE;
    }

  /* At this point we know that the bytestream has not been closed */
  g_object_unref (self);

  if (!gibber_transport_buffer_is_empty (priv->transport))
    {
      /* We >don't want to send more data while the buffer isn't empty */
      change_write_blocked_state (self, TRUE);
    }

  return TRUE;
}

/*
 * gabble_bytestream_socks5_accept
 *
 * Implements gabble_bytestream_iface_accept on GabbleBytestreamIface
 */
static void
gabble_bytestream_socks5_accept (GabbleBytestreamIface *iface,
                                 GabbleBytestreamAugmentSiAcceptReply func,
                                 gpointer user_data)
{
  GabbleBytestreamSocks5 *self = GABBLE_BYTESTREAM_SOCKS5 (iface);
  GabbleBytestreamSocks5Private *priv =
      GABBLE_BYTESTREAM_SOCKS5_GET_PRIVATE (self);
  WockyStanza *msg;
  WockyNode *si;

  if (priv->bytestream_state != GABBLE_BYTESTREAM_STATE_LOCAL_PENDING)
    {
      /* The stream was previoulsy or automatically accepted */
      return;
    }

  if (priv->managed > 0)
    {
      DEBUG ("Channel[%p] accepted on %p, relaying upstream", user_data, self);
      g_signal_emit_by_name (self, "accepted", user_data);
      g_object_set (self, "state", GABBLE_BYTESTREAM_STATE_ACCEPTED, NULL);
      return;
    }

  msg = gabble_bytestream_factory_make_accept_iq (priv->peer_jid,
      priv->stream_init_id, NS_BYTESTREAMS);
  si = wocky_node_get_child_ns (
    wocky_stanza_get_top_node (msg), "si", NS_SI);
  g_assert (si != NULL);

  if (func != NULL)
    {
      /* let the caller add his profile specific data */
      func (si, user_data);
    }

  if (_gabble_connection_send (priv->conn, msg, NULL))
    {
      DEBUG ("stream %s with %s is now accepted", priv->stream_id,
          priv->peer_jid);
      g_object_set (self, "state", GABBLE_BYTESTREAM_STATE_ACCEPTED, NULL);
    }

  g_object_unref (msg);
}

static void
gabble_bytestream_socks5_decline (GabbleBytestreamSocks5 *self,
                                  GError *error)
{
  GabbleBytestreamSocks5Private *priv =
      GABBLE_BYTESTREAM_SOCKS5_GET_PRIVATE (self);
  WockyStanza *msg;

  g_return_if_fail (priv->bytestream_state ==
      GABBLE_BYTESTREAM_STATE_LOCAL_PENDING);

  if (priv->managed > 0)
    {
      DEBUG ("Channel rejected bytestreem %p, relaying upstream", self);
      g_signal_emit_by_name (self, "rejected");
      g_object_set (self, "state", GABBLE_BYTESTREAM_STATE_CLOSED, NULL);
      return;
    }

  msg = wocky_stanza_build (WOCKY_STANZA_TYPE_IQ, WOCKY_STANZA_SUB_TYPE_ERROR,
      NULL, priv->peer_jid,
      '@', "id", priv->stream_init_id,
      NULL);

  if (error != NULL)
    {
      wocky_stanza_error_to_node (error, wocky_stanza_get_top_node (msg));
    }
  else
    {
      GError fallback = { WOCKY_XMPP_ERROR, WOCKY_XMPP_ERROR_FORBIDDEN,
          "Offer Declined" };
      wocky_stanza_error_to_node (&fallback, wocky_stanza_get_top_node (msg));
    }

  _gabble_connection_send (priv->conn, msg, NULL);

  g_object_unref (msg);

  g_object_set (self, "state", GABBLE_BYTESTREAM_STATE_CLOSED, NULL);
}

/*
 * gabble_bytestream_socks5_close
 *
 * Implements gabble_bytestream_iface_close on GabbleBytestreamIface
 */
static void
gabble_bytestream_socks5_close (GabbleBytestreamIface *iface,
                                GError *error)
{
  GabbleBytestreamSocks5 *self = GABBLE_BYTESTREAM_SOCKS5 (iface);
  GabbleBytestreamSocks5Private *priv =
      GABBLE_BYTESTREAM_SOCKS5_GET_PRIVATE (self);

  if (priv->bytestream_state == GABBLE_BYTESTREAM_STATE_CLOSED)
     /* bytestream already closed, do nothing */
     return;

  if (priv->bytestream_state == GABBLE_BYTESTREAM_STATE_LOCAL_PENDING)
    {
      /* Stream was created using SI so we decline the request */
      gabble_bytestream_socks5_decline (self, error);
    }
  else
    {
      g_object_set (self, "state", GABBLE_BYTESTREAM_STATE_CLOSING, NULL);
      if (priv->transport != NULL &&
          !gibber_transport_buffer_is_empty (priv->transport))
        {
          DEBUG ("Wait transport buffer is empty before close the bytestream");
        }
      else
        {
          DEBUG ("Transport buffer is empty, we can close the bytestream");
          bytestream_closed (self);
        }
    }
}

static void
initiator_connected_to_proxy (GabbleBytestreamSocks5 *self)
{
  GabbleBytestreamSocks5Private *priv = GABBLE_BYTESTREAM_SOCKS5_GET_PRIVATE (
      self);
  GSList *proxies, *l;
  GabbleSocks5Proxy *proxy = NULL;
  GibberTCPTransport *transport;

  proxies = gabble_bytestream_factory_get_socks5_proxies (
      priv->conn->bytestream_factory);
  for (l = proxies; l != NULL; l = g_slist_next (l))
     {
       proxy = (GabbleSocks5Proxy *) l->data;

       if (!tp_strdiff (proxy->jid, priv->proxy_jid))
         break;

       proxy = NULL;
     }
  g_slist_free (proxies);

  if (proxy == NULL)
    {
      DEBUG ("Unknown proxy: %s. Closing the bytestream", priv->proxy_jid);
      g_signal_emit_by_name (self, "connection-error");
      g_object_set (self, "state", GABBLE_BYTESTREAM_STATE_CLOSED, NULL);
      return;
    }

  DEBUG ("connect to proxy: %s (%s:%d)", proxy->jid, proxy->host, proxy->port);
  priv->socks5_state = SOCKS5_STATE_INITIATOR_TRYING_CONNECT;

  transport = gibber_tcp_transport_new ();
  set_transport (self, GIBBER_TRANSPORT (transport));
  g_object_unref (transport);

  gibber_tcp_transport_connect (transport, proxy->host,
      proxy->port);
}

static gboolean
streamhost_used (GabbleBytestreamIface *obj, WockyNode *streamhost)
{
  GabbleBytestreamSocks5 *self = GABBLE_BYTESTREAM_SOCKS5 (obj);
  GabbleBytestreamSocks5Private *priv = self->priv;
  const gchar *jid;

  jid = wocky_node_get_attribute (streamhost, "jid");
  if (jid == NULL)
    {
      DEBUG ("no jid attribute in streamhost. Closing the bytestream");
      return FALSE;
    }

  if (tp_strdiff (jid, priv->self_full_jid))
    {
      DEBUG ("Target is connected to proxy: %s", jid);

      if (priv->socks5_state != SOCKS5_STATE_INITIATOR_OFFER_SENT)
        {
          DEBUG ("We are already in the negotiation process (state: %u). "
              "Closing the bytestream", priv->socks5_state);
          return FALSE;
        }

      priv->proxy_jid = g_strdup (jid);
      initiator_connected_to_proxy (self);
      return TRUE;
    }

  /* No proxy used */
  DEBUG ("Target is connected to us");

  if (priv->socks5_state != SOCKS5_STATE_CONNECTED)
    {
      DEBUG ("Target claims that the bytestream is open but SOCKS5 is not "
          "connected (state: %u). Closing the bytestream",
          priv->socks5_state);
      return FALSE;
    }

  /* yeah, stream initiated */
  DEBUG ("Socks5 stream initiated using stream: %s", jid);
  g_object_set (self, "state", GABBLE_BYTESTREAM_STATE_OPEN, NULL);
  /* We can read data from the sock5 socket now */
  gibber_transport_block_receiving (priv->transport, FALSE);
  return TRUE;
}

static void
socks5_init_reply_cb (
    GObject *source,
    GAsyncResult *result,
    gpointer user_data)
{
  TpWeakRef *weak_ref = user_data;
  GabbleBytestreamSocks5 *self = tp_weak_ref_dup_object (weak_ref);
  WockyStanza *reply_msg = NULL;

  tp_weak_ref_destroy (weak_ref);
  if (self == NULL)
    return;

  if (conn_util_send_iq_finish (GABBLE_CONNECTION (source), result, &reply_msg, NULL))
    {
      WockyNode *query, *streamhost = NULL;

      query = wocky_node_get_child_ns (
        wocky_stanza_get_top_node (reply_msg), "query", NS_BYTESTREAMS);

      if (query != NULL)
        streamhost = wocky_node_get_child (query, "streamhost-used");

      if (streamhost == NULL)
        {
          DEBUG ("no streamhost-used has been defined. Closing the bytestream");
          goto socks5_init_error;
        }

      if (gabble_bytestream_iface_streamhost_used (
	    GABBLE_BYTESTREAM_IFACE (self), streamhost))
        goto out;
    }

socks5_init_error:
  DEBUG ("error during Socks5 initiation");

  g_signal_emit_by_name (self, "connection-error");
  g_object_set (self, "state", GABBLE_BYTESTREAM_STATE_CLOSED, NULL);

out:
  g_clear_object (&reply_msg);
  g_object_unref (self);
}

#ifdef G_OS_WIN32

static GSList *
get_local_interfaces_ips (void)
{
  gint sockfd;
  INTERFACE_INFO *iflist = NULL;
  gsize size = 0;
  int ret;
  int error;
  gsize bytes;
  gsize num;
  gsize i;
  struct sockaddr_in *sa;
  GSList *ips = NULL;

  /* FIXME: add IPv6 addresses */
  if ((sockfd = socket (AF_INET, SOCK_DGRAM, IPPROTO_IP)) == (int) INVALID_SOCKET)
    {
      DEBUG ("Cannot open socket to retrieve interface list");
      return NULL;
    }

  /* Loop and get each interface the system has, one by one... */
  do
    {
      size += sizeof (INTERFACE_INFO);
      /* realloc buffer size until no overflow occurs  */
      if (NULL == (iflist = realloc (iflist, size)))
        {
          DEBUG ("Out of memory while allocation interface configuration"
              " structure");
          closesocket (sockfd);
          return NULL;
        }

        ret = WSAIoctl (sockfd, SIO_GET_INTERFACE_LIST, NULL, 0, iflist,
                        size, (LPDWORD) &bytes, NULL, NULL);
        error = WSAGetLastError ();

        if (ret == SOCKET_ERROR && error != WSAEFAULT)
          {
            DEBUG ("Cannot retrieve interface list");
            closesocket (sockfd);
            free (iflist);
            return NULL;
          }
    } while (ret == SOCKET_ERROR);

  num = bytes / sizeof (INTERFACE_INFO);

  /* Loop throught the interface list and get the IP address of each IF */
  for (i = 0; i < num; i++)
    {
      /* no ip address from interface that is down */
      if ((iflist[i].iiFlags & IFF_UP) == 0)
        continue;

      if ((iflist[i].iiFlags & IFF_LOOPBACK) == IFF_LOOPBACK)
        {
          DEBUG ("Ignoring loopback interface");
          continue;
        }

      sa = (struct sockaddr_in *) &(iflist[i].iiAddress);
      ips = g_slist_prepend (ips, g_strdup (inet_ntoa (sa->sin_addr)));
      DEBUG ("IP Address: %s", inet_ntoa (sa->sin_addr));
    }

  closesocket (sockfd);
  free (iflist);

  return ips;
}

#else

/* get_local_interfaces_ips original code from Farsight 2 (function
 * fs_interfaces_get_local_ips in /gst-libs/gst/farsight/fs-interfaces.c).
 *   Copyright (C) 2006 Youness Alaoui <kakaroto@kakaroto.homelinux.net>
 *   Copyright (C) 2007 Collabora
 */
#ifdef HAVE_GETIFADDRS

static GSList *
get_local_interfaces_ips (void)
{
  struct ifaddrs *ifa, *results;
  GSList *ips = NULL;

  if (getifaddrs (&results) < 0)
    return NULL;

  /* Loop through the interface list and get the IP address of each IF */
  for (ifa = results; ifa; ifa = ifa->ifa_next)
    {
      char straddr[INET6_ADDRSTRLEN];

      /* no ip address from interface that is down */
      if ((ifa->ifa_flags & IFF_UP) == 0)
        continue;

      if (ifa->ifa_addr == NULL)
        continue;

      if ((ifa->ifa_flags & IFF_LOOPBACK) == IFF_LOOPBACK)
        {
          DEBUG ("Ignoring loopback interface");
          continue;
        }

      if (ifa->ifa_addr->sa_family == AF_INET)
        {
          struct sockaddr_in *sa = (struct sockaddr_in *) ifa->ifa_addr;

          inet_ntop (AF_INET, &sa->sin_addr, straddr, sizeof (straddr));

          /* Add IPv4 addresses to the end of the list */
          ips = g_slist_append (ips, g_strdup (straddr));
        }
      else if (ifa->ifa_addr->sa_family == AF_INET6)
        {
          struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *) ifa->ifa_addr;

          inet_ntop (AF_INET6, &sa6->sin6_addr, straddr, sizeof (straddr));

          if (IN6_IS_ADDR_LINKLOCAL (&sa6->sin6_addr))
            {
              DEBUG ("Ignoring link-local address: %s", straddr);
              continue;
            }

          /* Add IPv6 addresss to the begin of the list */
          ips = g_slist_prepend (ips, g_strdup (straddr));
        }
      else
        {
          continue;
        }

      DEBUG ("Interface:  %s", ifa->ifa_name);
      DEBUG ("IP Address: %s", straddr);
    }

  freeifaddrs (results);

  return ips;
}

#else /* ! HAVE_GETIFADDRS */

static GSList *
get_local_interfaces_ips (void)
{
  gint sockfd;
  gint size = 0;
  struct ifreq *ifr;
  struct ifconf ifc;
  struct sockaddr_in *sa;
  GSList *ips = NULL;

  /* FIXME: add IPv6 addresses */
  if ((sockfd = socket (AF_INET, SOCK_DGRAM, IPPROTO_IP)) < 0)
    {
      DEBUG ("Cannot open socket to retreive interface list");
      return NULL;
    }

  ifc.ifc_len = 0;
  ifc.ifc_req = NULL;

  /* Loop and get each interface the system has, one by one... */
  do
    {
      size += sizeof (struct ifreq);
      /* realloc buffer size until no overflow occurs  */
      if (NULL == (ifc.ifc_req = realloc (ifc.ifc_req, size)))
        {
          DEBUG ("Out of memory while allocation interface configuration"
              " structure");
          close (sockfd);
          return NULL;
        }
      ifc.ifc_len = size;

      if (ioctl (sockfd, SIOCGIFCONF, &ifc))
        {
          DEBUG ("ioctl SIOCFIFCONF");
          close (sockfd);
          free (ifc.ifc_req);
          return NULL;
        }
    } while  (size <= ifc.ifc_len);

  /* Loop throught the interface list and get the IP address of each IF */
  for (ifr = ifc.ifc_req;
      (gchar *) ifr < (gchar *) ifc.ifc_req + ifc.ifc_len;
      ++ifr)
    {

      if (ioctl (sockfd, SIOCGIFFLAGS, ifr))
        {
          DEBUG ("Unable to get IP information for interface %s. Skipping...",
              ifr->ifr_name);
          continue;  /* failed to get flags, skip it */
        }
      sa = (struct sockaddr_in *) &ifr->ifr_addr;
      DEBUG ("Interface:  %s", ifr->ifr_name);
      DEBUG ("IP Address: %s", inet_ntoa (sa->sin_addr));
      if ((ifr->ifr_flags & IFF_LOOPBACK) == IFF_LOOPBACK)
        {
          DEBUG ("Ignoring loopback interface");
        }
      else
        {
          ips = g_slist_prepend (ips, g_strdup (inet_ntoa (sa->sin_addr)));
        }
    }

  close (sockfd);
  free (ifc.ifc_req);

  return ips;
}

#endif /* ! HAVE_GETIFADDRS */

#endif /* ! G_OS_WIN32 */

static void
new_connection_cb (GibberListener *listener,
                   GibberTransport *transport,
                   struct sockaddr *addr,
                   guint size,
                   gpointer user_data)
{
  GabbleBytestreamSocks5 *self = GABBLE_BYTESTREAM_SOCKS5 (user_data);
  GabbleBytestreamSocks5Private *priv =
    GABBLE_BYTESTREAM_SOCKS5_GET_PRIVATE (self);

  DEBUG ("New connection...");

  priv->socks5_state = SOCKS5_STATE_INITIATOR_AWAITING_AUTH_REQUEST;
  set_transport (self, transport);
}

/*
 * Consumes @ips.
 */
static void
send_streamhosts (
    GabbleBytestreamSocks5 *self,
    GSList *ips,
    gint port_num)
{
  GabbleBytestreamSocks5Private *priv = self->priv;
  gchar *port;
  WockyStanza *msg;
  WockyNode *query_node;

  if (priv->managed > 0)
    {
      GabbleSocks5Proxy *c;
      guint local = 0;
      GSList *proxies = gabble_bytestream_factory_get_socks5_proxies (
          priv->conn->bytestream_factory);

      for (; port_num != 0 && ips != NULL; ips = g_slist_delete_link (ips, ips))
        {
	  c = g_slice_new (GabbleSocks5Proxy);
	  c->jid = priv->self_full_jid;
	  c->host = ips->data;
	  c->port = port_num;
	  proxies = g_slist_prepend (proxies, c);
          local++;
        }
      g_slist_free (ips);

      if (proxies != NULL)
        g_signal_emit_by_name (G_OBJECT (self),
	    "send-streamhosts", local, proxies);
      g_slist_free (proxies);
      return;
    }

  port = g_strdup_printf ("%d", port_num);

  msg = wocky_stanza_build (WOCKY_STANZA_TYPE_IQ, WOCKY_STANZA_SUB_TYPE_SET,
      NULL, priv->peer_jid,
      '(', "query",
        ':', NS_BYTESTREAMS,
        '@', "sid", priv->stream_id,
        '@', "mode", "tcp",
        '*', &query_node,
      ')', NULL);

  for (; port_num != 0 && ips != NULL; ips = g_slist_delete_link (ips, ips))
    {
      WockyNode *node = wocky_node_add_child (query_node, "streamhost");

      wocky_node_set_attributes (node,
          "jid", priv->self_full_jid,
          "host", ips->data,
          "port", port,
          NULL);

      g_free (ips->data);
    }

  g_slist_free (ips);
  g_free (port);

  if (!priv->muc_contact)
    {
      GSList *proxies, *l;

      proxies = gabble_bytestream_factory_get_socks5_proxies (
          priv->conn->bytestream_factory);

      for (l = proxies; l != NULL; l = g_slist_next (l))
        {
          WockyNode *node = wocky_node_add_child (query_node, "streamhost");
          gchar *portstr;
          GabbleSocks5Proxy *proxy = (GabbleSocks5Proxy *) l->data;

          portstr = g_strdup_printf ("%d", proxy->port);

          wocky_node_set_attributes (node,
              "jid", proxy->jid,
              "host", proxy->host,
              "port", portstr,
              NULL);
          g_free (portstr);
        }
     g_slist_free (proxies);
    }
  else
    {
      DEBUG ("don't propose to use SOCKS5 relays as we are offering bytestream "
          "to a muc contact");
    }

  priv->socks5_state = SOCKS5_STATE_INITIATOR_OFFER_SENT;

  conn_util_send_iq_async (priv->conn, msg, NULL,
      socks5_init_reply_cb, tp_weak_ref_new (self, NULL, NULL));
  g_object_unref (msg);
}

/*
 * gabble_bytestream_socks5_initiate
 *
 * Implements gabble_bytestream_iface_initiate on GabbleBytestreamIface
 */
static gboolean
gabble_bytestream_socks5_initiate (GabbleBytestreamIface *iface)
{
  GabbleBytestreamSocks5 *self = GABBLE_BYTESTREAM_SOCKS5 (iface);
  GabbleBytestreamSocks5Private *priv =
      GABBLE_BYTESTREAM_SOCKS5_GET_PRIVATE (self);
  GSList *ips = NULL;
  guint port_num = 0;

  if (priv->managed > 0)
    DEBUG ("Ignoring current state %d while managed", priv->bytestream_state);
  else
  if (priv->bytestream_state != GABBLE_BYTESTREAM_STATE_INITIATING)
    {
      DEBUG ("bytestream is not in the initiating state (state %d)",
          priv->bytestream_state);
      return FALSE;
    }

  if (priv->managed == 0)
    ips = get_local_interfaces_ips ();
  if (ips == NULL)
    {
      DEBUG ("Can't get IP addresses; will send empty offer.");
    }
  else
    {
      g_assert (priv->listener == NULL);
      priv->listener = gibber_listener_new ();

      g_signal_connect (priv->listener, "new-connection",
          G_CALLBACK (new_connection_cb), self);

      if (!gibber_listener_listen_tcp (priv->listener, 0, NULL))
        {
          DEBUG ("can't listen for incoming connection; will send empty offer.");
          g_slist_foreach (ips, (GFunc) g_free, NULL);
          g_slist_free (ips);
          ips = NULL;
        }

      port_num = gibber_listener_get_port (priv->listener);
    }

  send_streamhosts (self, ips, port_num);
  return TRUE;
}

static void
gabble_bytestream_socks5_block_reading (GabbleBytestreamIface *iface,
                                        gboolean block)
{
  GabbleBytestreamSocks5 *self = GABBLE_BYTESTREAM_SOCKS5 (iface);
  GabbleBytestreamSocks5Private *priv =
      GABBLE_BYTESTREAM_SOCKS5_GET_PRIVATE (self);

  if (priv->read_blocked == block)
    return;

  priv->read_blocked = block;

  if (priv->transport != NULL)
    gibber_transport_block_receiving (priv->transport, block);
}

static void
bytestream_iface_init (gpointer g_iface,
                       gpointer iface_data)
{
  GabbleBytestreamIfaceClass *klass = (GabbleBytestreamIfaceClass *) g_iface;

  klass->initiate = gabble_bytestream_socks5_initiate;
  klass->send = gabble_bytestream_socks5_send;
  klass->close = gabble_bytestream_socks5_close;
  klass->accept = gabble_bytestream_socks5_accept;
  klass->block_reading = gabble_bytestream_socks5_block_reading;

  /* optional extended methods */
  klass->streamhost_used = streamhost_used;
  klass->add_streamhost = add_streamhost;
  klass->connect = (void(*)(GabbleBytestreamIface*))socks5_connect;
}
