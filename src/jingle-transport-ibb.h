/*
 * jingle-transport-ibb.h - Header for JingleTransportIBB
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

#ifndef __JINGLE_TRANSPORT_IBB_H__
#define __JINGLE_TRANSPORT_IBB_H__

#include <glib-object.h>
#include <wocky.h>

G_BEGIN_DECLS

typedef struct _JingleTransportIBBClass   JingleTransportIBBClass;
typedef struct _JingleTransportIBB 	  JingleTransportIBB;
typedef struct _JingleTransportIBBPrivate JingleTransportIBBPrivate;

GType jingle_transport_ibb_get_type (void);

/* TYPE MACROS */
#define GABBLE_TYPE_JINGLE_TRANSPORT_IBB \
  (jingle_transport_ibb_get_type ())
#define GABBLE_JINGLE_TRANSPORT_IBB(obj) \
  (G_TYPE_CHECK_INSTANCE_CAST((obj), GABBLE_TYPE_JINGLE_TRANSPORT_IBB, \
                              JingleTransportIBB))
#define GABBLE_JINGLE_TRANSPORT_IBB_CLASS(klass) \
  (G_TYPE_CHECK_CLASS_CAST((klass), GABBLE_TYPE_JINGLE_TRANSPORT_IBB, \
                           JingleTransportIBBClass))
#define GABBLE_IS_JINGLE_TRANSPORT_IBB(obj) \
  (G_TYPE_CHECK_INSTANCE_TYPE((obj), GABBLE_TYPE_JINGLE_TRANSPORT_IBB))
#define GABBLE_IS_JINGLE_TRANSPORT_IBB_CLASS(klass) \
  (G_TYPE_CHECK_CLASS_TYPE((klass), GABBLE_TYPE_JINGLE_TRANSPORT_IBB))
#define GABBLE_JINGLE_TRANSPORT_IBB_GET_CLASS(obj) \
  (G_TYPE_INSTANCE_GET_CLASS ((obj), GABBLE_TYPE_JINGLE_TRANSPORT_IBB, \
                              JingleTransportIBBClass))

struct _JingleTransportIBBClass {
    GObjectClass parent_class;
};

struct _JingleTransportIBB {
    GObject parent;
    JingleTransportIBBPrivate *priv;
};

void jingle_transport_ibb_register (WockyJingleFactory *factory);

G_END_DECLS

#endif /* __JINGLE_TRANSPORT_IBB_H__ */

