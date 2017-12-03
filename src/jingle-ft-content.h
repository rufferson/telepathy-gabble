/*
 * jingle-ft-content.h - Header for GabbleJingleFT
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

#ifndef __JINGLE_FT_H__
#define __JINGLE_FT_H__

#include <glib-object.h>
#include <wocky/wocky.h>
#include <telepathy-glib/telepathy-glib.h>

#include "ft-channel.h"

G_BEGIN_DECLS

typedef struct _GabbleJingleFTClass GabbleJingleFTClass;

GType gabble_jingle_ft_get_type (void);

/* TYPE MACROS */
#define GABBLE_TYPE_JINGLE_FT \
  (gabble_jingle_ft_get_type ())
#define GABBLE_JINGLE_FT(obj) \
  (G_TYPE_CHECK_INSTANCE_CAST((obj), GABBLE_TYPE_JINGLE_FT, \
                              GabbleJingleFT))
#define GABBLE_JINGLE_FT_CLASS(klass) \
  (G_TYPE_CHECK_CLASS_CAST((klass), GABBLE_TYPE_JINGLE_FT, \
                           GabbleJingleFTClass))
#define GABBLE_IS_JINGLE_FT(obj) \
  (G_TYPE_CHECK_INSTANCE_TYPE((obj), GABBLE_TYPE_JINGLE_FT))
#define GABBLE_IS_JINGLE_FT_CLASS(klass) \
  (G_TYPE_CHECK_CLASS_TYPE((klass), GABBLE_TYPE_JINGLE_FT))
#define GABBLE_JINGLE_FT_GET_CLASS(obj) \
  (G_TYPE_INSTANCE_GET_CLASS ((obj), GABBLE_TYPE_JINGLE_FT, \
                              GabbleJingleFTClass))

struct _GabbleJingleFTClass {
    WockyJingleContentClass parent_class;
};

typedef struct _GabbleJingleFTPrivate GabbleJingleFTPrivate;
typedef struct _GabbleJingleFT GabbleJingleFT;

struct _GabbleJingleFT {
    WockyJingleContent parent;
    GabbleJingleFTPrivate *priv;
};

typedef struct {
  gchar *name;
  gchar *type;
  gchar *desc;
  guint64 date;
  guint64 size;
  gchar *hash;
  TpFileHashType hash_algo;
  guint64 range_off;
  guint64 range_len;
} GabbleJingleFTFileEntry;

typedef struct {
  GabbleJingleFTFileEntry *file;
} GabbleJingleFTContent;

GabbleJingleFTContent *
gabble_jingle_ft_get_content (GabbleJingleFT *ft);

void gabble_jingle_ft_set_channel (GabbleJingleFT *ft,
    GabbleFileTransferChannel *channel);

GabbleFileTransferChannel *
gabble_jingle_ft_new_channel (GabbleJingleFT *self, GabbleConnection *conn);

void jingle_ft_content_register (WockyJingleFactory *factory);

#endif /* __JINGLE_FT_H__ */

