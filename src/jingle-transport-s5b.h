/*
 * jingle-transport-s5b.h - Header for JingleTransportS5B
 * Copyright (c) 2018 Ruslan N. Marchenko
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

#ifndef __JINGLE_TRANSPORT_S5B_H__
#define __JINGLE_TRANSPORT_S5B_H__

#include <glib-object.h>
#include <wocky.h>

G_BEGIN_DECLS

typedef struct _JingleTransportS5BClass   JingleTransportS5BClass;
typedef struct _JingleTransportS5B 	  JingleTransportS5B;
typedef struct _JingleTransportS5BPrivate JingleTransportS5BPrivate;

GType jingle_transport_s5b_get_type (void);

/* TYPE MACROS */
#define GABBLE_TYPE_JINGLE_TRANSPORT_S5B \
  (jingle_transport_s5b_get_type ())
#define GABBLE_JINGLE_TRANSPORT_S5B(obj) \
  (G_TYPE_CHECK_INSTANCE_CAST((obj), GABBLE_TYPE_JINGLE_TRANSPORT_S5B, \
                              JingleTransportS5B))
#define GABBLE_JINGLE_TRANSPORT_S5B_CLASS(klass) \
  (G_TYPE_CHECK_CLASS_CAST((klass), GABBLE_TYPE_JINGLE_TRANSPORT_S5B, \
                           JingleTransportS5BClass))
#define GABBLE_IS_JINGLE_TRANSPORT_S5B(obj) \
  (G_TYPE_CHECK_INSTANCE_TYPE((obj), GABBLE_TYPE_JINGLE_TRANSPORT_S5B))
#define GABBLE_IS_JINGLE_TRANSPORT_S5B_CLASS(klass) \
  (G_TYPE_CHECK_CLASS_TYPE((klass), GABBLE_TYPE_JINGLE_TRANSPORT_S5B))
#define GABBLE_JINGLE_TRANSPORT_S5B_GET_CLASS(obj) \
  (G_TYPE_INSTANCE_GET_CLASS ((obj), GABBLE_TYPE_JINGLE_TRANSPORT_S5B, \
                              JingleTransportS5BClass))

struct _JingleTransportS5BClass {
    GObjectClass parent_class;
};

struct _JingleTransportS5B {
    GObject parent;
    JingleTransportS5BPrivate *priv;
};

void jingle_transport_s5b_register (WockyJingleFactory *factory);

G_END_DECLS

#endif /* __JINGLE_TRANSPORT_S5B_H__ */

