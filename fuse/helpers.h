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

struct gobexhlp_request;

struct gobexhlp_buffer {
	void *data;
	gsize tmpsize;
	gsize size;
	gboolean edited;
};

struct gobexhlp_session {
	GObex *obex;
	GList *lsfiles;
	GIOChannel *io;
	GHashTable *file_stat;
	gchar *setpath;
	struct gobexhlp_request *request;
	struct gobexhlp_buffer *buffer;
	gboolean vtouch;
	gchar *vtouch_path;
	gboolean rtouch;
	int status;
	GError *err;
};

struct gobexhlp_session* gobexhlp_connect(const char *srcstr,
						const char *dstsrc);
void gobexhlp_disconnect(struct gobexhlp_session* session);
void gobexhlp_mkdir(struct gobexhlp_session* session, const char *path);
void gobexhlp_touch(struct gobexhlp_session* session, const char *path);
void gobexhlp_delete(struct gobexhlp_session* session, const char *path);
void gobexhlp_put(struct gobexhlp_session* session,
					struct gobexhlp_buffer *buffer,
					const char *path);
struct gobexhlp_buffer *gobexhlp_get(struct gobexhlp_session* session,
					const char *path);
struct stat *gobexhlp_getattr(struct gobexhlp_session* session,
					const char *path);
GList *gobexhlp_listfolder(struct gobexhlp_session* session, const char *path);

