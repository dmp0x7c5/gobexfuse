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

