/*
 *  OBEX Filesystem in Userspace
 *
 *  Copyright (C) 2012  Michał Poczwardowski <dmp0x7c5@gmail.com>
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include <gobex/gobex.h>
#include <glib.h>

struct obexhlp_request;

struct obexhlp_buffer {
	void *data;
	gsize tmpsize;
	gsize size;
	gboolean edited;
};

struct obexhlp_session {
	GObex *obex;
	uint16_t channel;
	GList *lsfiles;
	GIOChannel *io;
	GHashTable *file_stat;
	gchar *setpath;
	struct obexhlp_request *request;
	struct obexhlp_buffer *buffer;
	gboolean vtouch;
	gchar *vtouch_path;
	gboolean rtouch;
	int status;
	GError *err;
};
