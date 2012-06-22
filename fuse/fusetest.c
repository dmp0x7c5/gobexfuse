// compile: gcc testfuse.c -o testfuse `pkg-config fuse --cflags` `pkg-config fuse --libs`

#define FUSE_USE_VERSION 26

#include <fuse.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>

static const char *hello_str = "Hello World!\n";
static const char *hello_path = "/hello";

void* gobex_init(struct fuse_conn_info *conn)
{
	return;
}

void gobex_destroy() 
{
	return;
}

static int gobex_getattr(const char *path, struct stat *stbuf)
{
	int res = 0;

	memset(stbuf, 0, sizeof(struct stat));
	if (strcmp(path, "/") == 0) {
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
	}
	else if(strcmp(path, hello_path) == 0) {
		stbuf->st_mode = S_IFREG | 0444;
		stbuf->st_nlink = 1;
		stbuf->st_size = strlen(hello_str);
		stbuf->st_mtime = time(NULL);
	}
	else {
		res = -ENOENT;
	}

	return res;
}

static int gobex_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                         off_t offset, struct fuse_file_info *fi)
{
	(void) offset;
	(void) fi;

	if(strcmp(path, "/") != 0)
		return -ENOENT;

	filler(buf, ".", NULL, 0);
	filler(buf, "..", NULL, 0);
	filler(buf, hello_path + 1, NULL, 0);

	return 0;
}

static struct fuse_operations gobex_oper = {
	.getattr = gobex_getattr,
	.readdir = gobex_readdir,
	.init = gobex_init,
	.destroy = gobex_destroy,
};

int main(int argc, char *argv[])
{
	return fuse_main(argc, argv, &gobex_oper, NULL);
}

