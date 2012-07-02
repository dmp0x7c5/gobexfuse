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

	char dststr[] = "18:87:96:4D:F0:9F"; // HTC
	//char dststr[] = "00:24:EF:08:B6:32"; // SE
	
	session = gobexhlp_connect(dststr);
	if (session == NULL || session->io == NULL)
		g_error("Connection to %s failed\n", dststr);
	
	main_loop = g_main_loop_new(NULL, FALSE);
	g_main_loop_run(main_loop);
}


void* gobexfuse_init(struct fuse_conn_info *conn)
{
	GThread * main_gthread;
	g_thread_init(NULL);
	main_gthread = g_thread_create(main_loop_func, NULL, TRUE, NULL);
	conn->async_read = 0;
	conn->want &= ~FUSE_CAP_ASYNC_READ;

	return;
}


void gobexfuse_destroy() 
{
	gobexhlp_disconnect(session);
	return;
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
			stbuf->st_mode = stfile->st_mode | 0444;
		else // S_IFDIR
			stbuf->st_mode = stfile->st_mode | 0755;
		stbuf->st_nlink = 1;
		stbuf->st_size = stfile->st_size;
		stbuf->st_mtime = stfile->st_mtime;
	}

	return res;
}


static int gobexfuse_mkdir(const char *path, mode_t mode)
{
	gobexhlp_mkdir(session, path);

	return 0;
}


static int gobexfuse_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                         off_t offset, struct fuse_file_info *fi)
{
	(void) offset;
	(void) fi;
	
	int len, i;
	gchar *string;
	GList *files;

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

	return 0;
}

/*
static int gobexfuse_open(const char *path, struct fuse_file_info *fi) 
{
	return 0;
}
*/

static int gobexfuse_read(const char *path, char *buf, size_t size,
			off_t offset, struct fuse_file_info *fi)
{
	struct gobexhlp_buffer *file_buffer;
	gsize asize;

	file_buffer = gobexhlp_read(session, path);
	if (file_buffer == NULL)
		return -ENOENT;

	asize = file_buffer->size - offset;
	if (asize > size) {
		asize = size;
	}
	
	memcpy(buf, file_buffer->data + offset, asize);

	g_free(file_buffer->data);
	g_free(file_buffer);

	return asize;
}


static struct fuse_operations gobexfuse_oper = {
	.getattr = gobexfuse_getattr,
	.readdir = gobexfuse_readdir,
	.mkdir = gobexfuse_mkdir,
	.read = gobexfuse_read,
	.init = gobexfuse_init,
	.destroy = gobexfuse_destroy,
};

int main(int argc, char *argv[])
{
	return fuse_main(argc, argv, &gobexfuse_oper, NULL);
}

