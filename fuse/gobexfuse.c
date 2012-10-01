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

#define FUSE_USE_VERSION 26

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

#include <fuse.h>
#include <fuse/fuse_opt.h>

#include "helpers.h"

struct gobexhlp_session* session = NULL;
static GMainLoop *main_loop;
static GThread *main_gthread;

struct options {
	char* dststr;
	char* srcstr;
} options;

#define GOBEXFUSE_OPT_KEY(t, p, v) { t, offsetof(struct options, p), v }

enum
{
   KEY_VERSION,
   KEY_HELP,
};

static struct fuse_opt gobexfuse_opts[] =
{
	GOBEXFUSE_OPT_KEY("--target=%s",dststr, 0),
	GOBEXFUSE_OPT_KEY("-t %s",	dststr, 0),
	GOBEXFUSE_OPT_KEY("--source=%s",srcstr, 0),
	GOBEXFUSE_OPT_KEY("-s %s",	srcstr, 0),

	FUSE_OPT_KEY("-V",             KEY_VERSION),
	FUSE_OPT_KEY("--version",      KEY_VERSION),
	FUSE_OPT_KEY("-h",             KEY_HELP),
	FUSE_OPT_KEY("--help",         KEY_HELP),
	FUSE_OPT_END
};

gpointer main_loop_func(gpointer user_data)
{
	main_loop = g_main_loop_new(NULL, FALSE);
	g_main_loop_run(main_loop);

	return 0;
}

void* gobexfuse_init(struct fuse_conn_info *conn)
{
	main_gthread = g_thread_create(main_loop_func, NULL, TRUE, NULL);

	conn->async_read = 0;
	conn->want &= ~FUSE_CAP_ASYNC_READ;

	return 0;
}

void gobexfuse_destroy()
{
	gobexhlp_disconnect(session);
	g_main_loop_quit(main_loop);
	g_thread_join(main_gthread);
}

static int gobexfuse_readdir(const char *path, void *buf,
			fuse_fill_dir_t filler, off_t offset,
				struct fuse_file_info *fi)
{
	int len, i;
	gchar *string;
	GList *files;

	filler(buf, ".", NULL, 0);
	filler(buf, "..", NULL, 0);

	files = gobexhlp_listfolder(session, path);
	len = g_list_length(files);

	for (i = 1; i < len; i++) { /* element for i==0 is NULL */
		string = g_list_nth_data(files, i);
		filler(buf, string, NULL, 0);
	}

	return session->status;
}

static int gobexfuse_getattr(const char *path, struct stat *stbuf)
{
	int res = 0;
	struct stat *stfile;

	memset(stbuf, 0, sizeof(struct stat));

	if (strcmp(path, "/") == 0) {
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
	} else {
		stfile = gobexhlp_getattr(session, path);

		if (stfile == NULL)
			return -ENOENT;

		if (stfile->st_mode == S_IFREG)
			stbuf->st_mode = stfile->st_mode | 0666;
		else /* S_IFDIR */
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

static int gobexfuse_open(const char *path, struct fuse_file_info *fi)
{
	struct gobexhlp_buffer *file_buffer;

	file_buffer = gobexhlp_get(session, path);

	if (file_buffer == NULL)
		return -ENOENT;

	fi->fh = (uint64_t)file_buffer;

	return session->status;
}

static int gobexfuse_read(const char *path, char *buf, size_t size,
			off_t offset, struct fuse_file_info *fi)
{
	gsize asize;
	struct gobexhlp_buffer *file_buffer = (struct gobexhlp_buffer*)fi->fh;

	asize = file_buffer->size - offset;

	if (asize > size)
		asize = size;

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
	} else {
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

	if (file_buffer->edited == TRUE)
		gobexhlp_put(session, file_buffer, path); /* send to device */

	g_free(file_buffer->data);
	g_free(file_buffer);

	return session->status;
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

static struct fuse_operations gobexfuse_oper = {
	.readdir = gobexfuse_readdir,
	.getattr = gobexfuse_getattr,
	.open = gobexfuse_open,
	.read = gobexfuse_read,
	.write = gobexfuse_write,
	.truncate = gobexfuse_truncate,
	.release = gobexfuse_release,
	.utimens = gobexfuse_utimens,
	.mknod = gobexfuse_mknod,
	.init = gobexfuse_init,
	.destroy = gobexfuse_destroy,
};

static int gobexfuse_opt_proc(void *data, const char *arg, int key,
					struct fuse_args *outargs)
{
	switch (key) {
	case KEY_HELP:
		g_printerr("Usage: %s mountpoint [options]\n"
				"\n"
				"general options:\n"
				"    -o opt,[opt...]  mount options\n"
				"    -h   --help      print help\n"
				"    -V   --version   print version\n"
				"\n"
				"gobexfuse options:\n"
				"    -t   --target    target btaddr "
				"(mandatory)\n"
				"    -s   --source    source btaddr\n"
				"\n"
				, outargs->argv[0]);
		fuse_opt_add_arg(outargs, "-ho");
		fuse_main(outargs->argc, outargs->argv, &gobexfuse_oper, NULL);
		exit(1);
	case KEY_VERSION:
		g_print("gobexfuse upon:\n");
		fuse_opt_add_arg(outargs, "--version");
		fuse_main(outargs->argc, outargs->argv, &gobexfuse_oper, NULL);
		exit(0);
	}
	return 1;
}

int main(int argc, char *argv[])
{
	int retfuse;
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

	memset(&options, 0, sizeof(struct options));

	if (fuse_opt_parse(&args, &options, gobexfuse_opts,
				gobexfuse_opt_proc) == -1)
		return -EINVAL;

	if (options.dststr == NULL) {
		g_printerr("Target not specified\n");
		return -EINVAL;
	}

	g_thread_init(NULL);

	session = gobexhlp_connect(options.srcstr, options.dststr);
	if (session == NULL || session->io == NULL) {
		g_printerr("Connection to %s failed\n", options.dststr);
		gobexhlp_disconnect(session);
		return -EHOSTUNREACH;
	} else {
		g_print("Connected\nMounting %s\n", options.dststr);
	}

	fuse_opt_add_arg(&args, "-s"); /* force single threaded mode */
	retfuse = fuse_main(args.argc, args.argv, &gobexfuse_oper, NULL);

	fuse_opt_free_args(&args);
	return retfuse;
}
