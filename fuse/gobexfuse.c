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
	.mknod = gobexfuse_mknod,
	.utimens = gobexfuse_utimens,
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
