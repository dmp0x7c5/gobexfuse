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

// compile: gcc fusetest.c -o fusetest `pkg-config fuse --cflags` `pkg-config fuse --libs` -I/usr/include/glib-2.0 -I/usr/lib64/glib-2.0/include -I../  ../gobex/gobex.h ../gobex/gobex.c ../gobex/gobex-defs.h ../gobex/gobex-defs.c ../gobex/gobex-packet.c ../gobex/gobex-packet.h ../gobex/gobex-header.c ../gobex/gobex-header.h ../gobex/gobex-transfer.c ../gobex/gobex-debug.h ../btio/btio.h ../btio/btio.c -lbluetooth -lglib-2.0 -lgthread-2.0


#define FUSE_USE_VERSION 26

#include <fuse.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>

#include "helpers.c"

struct gobexhlp_data* session = NULL;
static GMainLoop *main_loop = NULL;


gpointer main_loop_func(gpointer user_data)
{

	//char dststr[] = "18:87:96:4D:F0:9F"; // HTC
	char dststr[] = "00:24:EF:08:B6:32"; // SE
	
	session = gobexhlp_connect(dststr);
	if (session == NULL || session->io == NULL)
		g_error("Connection to %s failed\n", dststr);
	
	main_loop = g_main_loop_new(NULL, FALSE);
	g_main_loop_run(main_loop);

	return 0;
}


/* 
 * TODO:
 * g_thread_create has been deprecated since version 2.32 and should not
 * be used in newly-written code. Use g_thread_new() instead.
 */

void* gobexfuse_init(struct fuse_conn_info *conn)
{
	GThread * main_gthread;
	g_thread_init(NULL);
	main_gthread = g_thread_create(main_loop_func, NULL, TRUE, NULL);
	conn->async_read = 0;
	conn->want &= ~FUSE_CAP_ASYNC_READ;
	
	return 0;
}


void gobexfuse_destroy() 
{
	gobexhlp_disconnect(session);
}


static int gobexfuse_getattr(const char *path, struct stat *stbuf)
{
	int res = 0;
	struct stat *stfile;

	memset(stbuf, 0, sizeof(struct stat));

	if (strcmp(path, "/") == 0) {
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
	}
	else {
		stfile = gobexhlp_getattr(session, path);
		if (stfile == NULL)
			return -ENOENT; 
		if (stfile->st_mode == S_IFREG)
			stbuf->st_mode = stfile->st_mode | 0666;
		else // S_IFDIR
			stbuf->st_mode = stfile->st_mode | 0755;
		stbuf->st_nlink = 1;
		stbuf->st_size = stfile->st_size;
		stbuf->st_mtime = stbuf->st_atime = stbuf->st_ctime =
			stfile->st_mtime;
		stbuf->st_blksize = 512;
		stbuf->st_blocks = (stbuf->st_size + stbuf->st_blksize)
						/ stbuf->st_blksize;

	}

	return res;
}


static int gobexfuse_mkdir(const char *path, mode_t mode)
{
	gobexhlp_mkdir(session, path);

	return 0;
}


static int gobexfuse_readdir(const char *path, void *buf,
			fuse_fill_dir_t filler, off_t offset,
				struct fuse_file_info *fi)
{
	int len, i;
	gchar *string;
	GList *files;

	// secure intense queries
	//while (time(NULL) < session->last_ask + 15) {
	//	;
	//}
	//if(strcmp(path, "/") != 0)
	//	return -ENOENT;

	filler(buf, ".", NULL, 0);
	filler(buf, "..", NULL, 0);
	
	files = gobexhlp_listfolder(session, path);
	len = g_list_length(files);
	for (i = 1; i < len; i++) { // element for i==0 is NULL
		string = g_list_nth_data(files, i);
		filler(buf, string, NULL, 0);
	}

	//session->last_ask = time(NULL);

	return 0;
}


static int gobexfuse_open(const char *path, struct fuse_file_info *fi)
{
	struct gobexhlp_buffer *file_buffer;
	g_print("gobexfuse_open(%s)\n", path);

	file_buffer = gobexhlp_get(session, path);
	if (file_buffer == NULL)
		return -ENOENT;
	
	fi->fh = (uint64_t)file_buffer;

	return 0;
}


static int gobexfuse_read(const char *path, char *buf, size_t size,
			off_t offset, struct fuse_file_info *fi)
{
	gsize asize;
	struct gobexhlp_buffer *file_buffer = (struct gobexhlp_buffer*)fi->fh;

	asize = file_buffer->size - offset;
	if (asize > size) {
		asize = size;
	}
	
	memcpy(buf, file_buffer->data + offset, asize);

	return asize;
}


static int gobexfuse_write(const char *path, const char *buf, size_t size,
				off_t offset, struct fuse_file_info *fi)
{
	gsize nsize;

	struct gobexhlp_buffer *file_buffer = (struct gobexhlp_buffer*)fi->fh;
	
	if (file_buffer->size < offset + size) {
		nsize = offset + size;
		file_buffer->data = g_realloc(file_buffer->data, nsize);
		file_buffer->size = nsize;
	}
	else {
		nsize = file_buffer->size;
	}
	file_buffer->edited = TRUE;

	memcpy(file_buffer->data + offset, buf, size);

	return size;
}


static int gobexfuse_truncate(const char *path, off_t offset)
{
	/*
	 *  Allow to change the size of a file.
	 */
	return 0;
}


static int gobexfuse_release(const char *path, struct fuse_file_info *fi)
{
	struct gobexhlp_buffer *file_buffer = (struct gobexhlp_buffer*)fi->fh;
	g_print("gobexfuse_release(%s)\n", path);
	
	if (file_buffer->edited == TRUE) {
		// send new file to device
		g_print("<data>\n");
		g_print("%s", (char*)(file_buffer->data));
		g_print("\n</data>\n");
		//gobexfuse_unlink(path);
		gobexhlp_put(session, file_buffer, path);
	}

	g_free(file_buffer->data);
	g_free(file_buffer);

	return 0;
}

static int gobexfuse_utimens(const char *path, const struct timespec tv[2])
{
	/*
	 * Important for mknod (touch) operation
	 */
	return 0;
}


static int gobexfuse_mknod(const char *path, mode_t mode, dev_t dev)
{
	gobexhlp_touch(session, path);
	return 0;
}


static int gobexfuse_rename(const char *from, const char *to)
{
	gobexhlp_move(session, from, to);
	return 0;
}

static int gobexfuse_unlink(const char *path)
{
	gobexhlp_delete(session, path, TRUE);
	return 0;
}

static struct fuse_operations gobexfuse_oper = {
	.getattr = gobexfuse_getattr,
	.readdir = gobexfuse_readdir,
	.mkdir = gobexfuse_mkdir,
	.open = gobexfuse_open,
	.read = gobexfuse_read,
	.write = gobexfuse_write,
	.release = gobexfuse_release,
	.truncate = gobexfuse_truncate,
	.mknod = gobexfuse_mknod,
	.utimens = gobexfuse_utimens,
	.rename = gobexfuse_rename,
	.unlink = gobexfuse_unlink,
	.rmdir = gobexfuse_unlink,
	.init = gobexfuse_init,
	.destroy = gobexfuse_destroy,
};

int main(int argc, char *argv[])
{
	return fuse_main(argc, argv, &gobexfuse_oper, NULL);
}

