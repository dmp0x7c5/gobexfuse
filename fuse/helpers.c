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

/* compile:
gcc  -I/usr/include/glib-2.0 -I/usr/lib64/glib-2.0/include -I../  ../gobex/gobex.h ../gobex/gobex.c ../gobex/gobex-defs.h ../gobex/gobex-defs.c ../gobex/gobex-packet.c ../gobex/gobex-packet.h ../gobex/gobex-header.c ../gobex/gobex-header.h ../gobex/gobex-transfer.c ../gobex/gobex-debug.h ../btio/btio.h ../btio/btio.c testgobexhlp.c -o testgobexhlp -lbluetooth -lreadline -lglib-2.0 -lgthread-2.0
*/

#include <gobex/gobex.h>
#include <btio/btio.h>

#include <glib.h>
#include <fcntl.h>

/* includes for get_ftp_channel() */
#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#define OBEX_FTP_UUID \
	"\xF9\xEC\x7B\xC4\x95\x3C\x11\xD2\x98\x4E\x52\x54\x00\xDC\x9E\x09"
#define OBEX_FTP_UUID_LEN 16

#define OBEX_FTP_LS "x-obex/folder-listing"

static GCond *gobexhlp_cond;
static GMutex *gobexhlp_mutex;

struct gobexhlp_request {
	gchar *name;
	gboolean complete;
};

struct gobexhlp_buffer {
	void *data;
	gsize tmpsize;
	gsize size;
	gboolean edited;
};

struct gobexhlp_data {
	const char *target;
	uint16_t channel;
	GIOChannel *io;
	GObex *obex;
	uint8_t pathdepth;
	GHashTable *file_stat;
	GHashTable *listfolder_req;
	const char *path;
	gchar *setpath;
	struct gobexhlp_request *request;
	struct gobexhlp_buffer *buffer;
	//GCond *data_cond;
	//GCond *req_cond;
	//GMutex *data_mutex;
	//GMutex *req_mutex;
};

struct gobexhlp_listfolder_req {
	GList *files;
};


struct gobexhlp_data* gobexhlp_connect(const char *target);
void gobexhlp_disconnect(struct gobexhlp_data* session);
void gobexhlp_setpath(struct gobexhlp_data* session, const char *path);
GList *gobexhlp_listfolder(struct gobexhlp_data* session, const char *path);
struct stat *gobexhlp_getattr(struct gobexhlp_data* session,
				const char *path);
void gobexhlp_delete(struct gobexhlp_data* session, const char *path);


static uint16_t find_rfcomm_uuid(void *user_data)
{
	sdp_list_t *pds = (sdp_list_t*) user_data;
	uint16_t channel = 0;

	for (;pds;pds = pds->next) {
		sdp_data_t *d = (sdp_data_t*)pds->data;
		int proto = 0;
		for (; d; d = d->next) {
			switch(d->dtd) {
			case SDP_UUID16:
			case SDP_UUID32:
			case SDP_UUID128:
				proto = sdp_uuid_to_proto(&d->val.uuid);
			break;
			case SDP_UINT8:
				if (proto == RFCOMM_UUID)
					channel = d->val.int8;
				break;
			}
		}
	}
	return channel;
}

static uint16_t get_ftp_channel(const char *dststr)
{
	sdp_session_t *sdp;
	sdp_list_t *response_list = NULL, *search_list, *attrid_list;
	sdp_list_t *r;
	uuid_t uuid;
	bdaddr_t dst;

	// FTP_SDP_UUID "00001106-0000-1000-8000-00805f9b34fb"
	uint8_t uuid_int[] = {0, 0, 0x11, 0x06, 0, 0, 0x10, 0, 0x80,
					0, 0, 0x80, 0x5f, 0x9b, 0x34, 0xfb};
	uint32_t range = 0x0000ffff;
	uint16_t channel = 0;

	str2ba(	dststr, &dst);

	sdp = sdp_connect(BDADDR_ANY, &dst, SDP_RETRY_IF_BUSY );
	if (sdp == NULL)
		return channel;

	sdp_uuid128_create(&uuid, uuid_int);
	search_list = sdp_list_append(NULL, &uuid);
	attrid_list = sdp_list_append(NULL, &range);
	sdp_service_search_attr_req(sdp, search_list, SDP_ATTR_REQ_RANGE,
					attrid_list, &response_list);
	r = response_list;

	for (; r;r = r->next) {
		sdp_record_t *rec = (sdp_record_t*) r->data;
		sdp_list_t *proto_list;

		if (sdp_get_access_protos(rec, &proto_list ) == 0) {
			sdp_list_t *p = proto_list;
			for (; p; p = p->next) {
				sdp_list_t *pds = (sdp_list_t*) p->data;
				channel = find_rfcomm_uuid(pds);
				sdp_list_free((sdp_list_t*) p->data, 0);
			}
			sdp_list_free(proto_list, 0);
		}
		sdp_record_free(rec);
	}
	sdp_close(sdp);

	return channel;
}


/* taken from client/bluetooth.c - bluetooth_getpacketopt */
static int get_packet_opt(GIOChannel *io, int *tx_mtu, int *rx_mtu)
{
	int sk = g_io_channel_unix_get_fd(io);
	int type;
	int omtu = -1;
	int imtu = -1;
	socklen_t len = sizeof(int);

	if (getsockopt(sk, SOL_SOCKET, SO_TYPE, &type, &len) < 0)
		return -errno;

	if (type != SOCK_SEQPACKET)
		return -EINVAL;

	if (!bt_io_get(io, BT_IO_L2CAP, NULL, BT_IO_OPT_OMTU, &omtu,
						BT_IO_OPT_IMTU, &imtu,
						BT_IO_OPT_INVALID))
		return -EINVAL;

	if (tx_mtu)
		*tx_mtu = omtu;

	if (rx_mtu)
		*rx_mtu = imtu;

	return 0;
}


static void obex_callback(GObex *obex, GError *err, GObexPacket *rsp,
							gpointer user_data)
{
	if (err != NULL)
		g_print("Connect failed: %s\n", err->message);
	else
		g_print("Connect succeeded\n");
}


static void bt_io_callback(GIOChannel *io, GError *err, gpointer user_data)
{
	GObex *obex;
	struct gobexhlp_data *session = user_data;
	GObexTransportType type;
	int tx_mtu = -1;
	int rx_mtu = -1;

	if (err != NULL) {
		g_printerr("%s\n", err->message);
		return;
	}

	g_print("Bluetooth socket connected\n");

	g_io_channel_set_flags(session->io, G_IO_FLAG_NONBLOCK, NULL);
	g_io_channel_set_close_on_unref(session->io, TRUE);

	if ( get_packet_opt(session->io, &tx_mtu, &rx_mtu) == 0) {
		type = G_OBEX_TRANSPORT_PACKET;
		g_print("PACKET transport tx:%d rx:%d\n", tx_mtu, rx_mtu);
	} else {
		type = G_OBEX_TRANSPORT_STREAM;
		g_print("STREAM transport\n");
	}

	obex = g_obex_new(io, type, tx_mtu, rx_mtu);
	session->obex = g_obex_ref(obex);

	g_obex_connect(session->obex, obex_callback, session, NULL,
			G_OBEX_HDR_TARGET, OBEX_FTP_UUID, OBEX_FTP_UUID_LEN,
			G_OBEX_HDR_INVALID);
}


static void free_listfolder_req(gpointer data)
{
	struct gobexhlp_listfolder_req *req = data;
	g_list_free_full(req->files, g_free);
	g_free(req);
}


struct gobexhlp_data* gobexhlp_connect(const char *target)
{
	GError *err = NULL;
	struct gobexhlp_data *session;

	g_print("gobexhlp_connect()\n");

	session = g_try_malloc0(sizeof(*session));
	if (session == NULL)
		return NULL;

	session->target = target;
	session->channel = get_ftp_channel(target);

	g_print("CHANNEL: %d\n", session->channel);

	if (session->channel == 0)
		return NULL;

	session->io = bt_io_connect(BT_IO_RFCOMM, bt_io_callback,
					session, NULL, &err,
					BT_IO_OPT_DEST, target,
					BT_IO_OPT_CHANNEL, session->channel,
					BT_IO_OPT_SEC_LEVEL, BT_IO_SEC_LOW,
					BT_IO_OPT_INVALID);

	session->file_stat = g_hash_table_new_full( g_str_hash, g_str_equal,
					g_free, g_free);
	session->listfolder_req = g_hash_table_new_full( g_str_hash,
				g_str_equal, g_free, free_listfolder_req);

	session->pathdepth = 0;
	session->setpath = g_strdup("/");
	
	//session->data_cond = g_cond_new();
	//session->data_mutex = g_mutex_new(); 
	//session->req_cond = g_cond_new();
	//session->req_mutex = g_mutex_new(); 
	
	gobexhlp_mutex = g_mutex_new();
	gobexhlp_cond = g_cond_new();

	return session;
}

void gobexhlp_disconnect(struct gobexhlp_data* session)
{
	g_print("gobexhlp_disconnect()\n");

	if (session == NULL)
		return;

	g_io_channel_shutdown(session->io, TRUE, NULL);
	g_io_channel_unref(session->io);
	g_obex_unref(session->obex);

	g_hash_table_remove_all(session->file_stat);
	g_hash_table_remove_all(session->listfolder_req);
	g_free(session->setpath);

	//g_mutex_free(session->data_mutex);
	//g_cond_free(session->data_cond);
	//g_mutex_free(session->req_mutex);
	//g_cond_free(session->req_cond);

	g_mutex_free(gobexhlp_mutex);
	g_cond_free(gobexhlp_cond);
	
	g_free(session);
	session = NULL;
}


void gobexhlp_request_new(struct gobexhlp_data *session,
					gchar *name)
{
	//g_mutex_lock(session->req_mutex);
	if (session->request != NULL) {
		/*
		 * This check in unnecessary in fuse 
		 * single threaded mode (-s option)
		 */
		g_error("Another request (%s) active!\n",
				session->request->name);
		// wait till the current request ends
	//	while (session->request != NULL)
	//		g_cond_wait(session->req_cond, session->req_mutex);
	}
	//g_mutex_unlock(session->req_mutex);

	session->request = g_malloc0(sizeof(*session->request));
	session->request->name = name;
	session->request->complete = FALSE;
	
	g_print("REQUEST NEW %s\n", session->request->name);
}


void gobexhlp_request_wait_free(struct gobexhlp_data *session)
{
	g_mutex_lock(gobexhlp_mutex);
	g_print("WAIT for %s\n", session->request->name);
	
	while (session->request->complete != TRUE) {
		g_cond_wait(gobexhlp_cond, gobexhlp_mutex);
	}

	g_mutex_unlock(gobexhlp_mutex);
	
	
	//g_mutex_lock(session->req_mutex);
	g_free(session->request->name);
	g_free(session->request);
	session->request = NULL;
	//g_cond_signal(session->req_cond);
	//g_mutex_unlock(session->req_mutex);
}


static void complete_func(GObex *obex, GError *err,
				gpointer user_data)
{
	struct gobexhlp_data *session = user_data;
	g_mutex_lock(gobexhlp_mutex);

	if (err != NULL) {
		g_error("ERROR: %s\n", err->message);
	} else {
		g_print("COMPLETE %s\n", session->request->name);
		session->request->complete = TRUE;
		g_cond_signal(gobexhlp_cond);
	}

	g_mutex_unlock(gobexhlp_mutex);
}


static void response_func(GObex *obex, GError *err, GObexPacket *rsp,
							gpointer user_data)
{
	complete_func(obex, err, user_data);

}


static void listfolder_xml_element(GMarkupParseContext *ctxt,
			const gchar *element, const gchar **names,
			const gchar **values, gpointer user_data,
			GError **gerr)
{
	gchar *key, *pathname, *name = NULL;
	struct gobexhlp_data *session = user_data;
	struct gobexhlp_listfolder_req *req;
	struct stat *stbuf;
	gint i = 0;

	stbuf = g_malloc0(sizeof(struct stat));

	if ((strcasecmp("file", element) == 0)) {
		stbuf->st_mode = S_IFREG;
	} else if ((strcasecmp("folder", element)) == 0) {
		stbuf->st_mode = S_IFDIR;
		stbuf->st_mtime = time(NULL);
	} else {
		return;
	}

	req = g_hash_table_lookup(session->listfolder_req, session->path);

	for (key = (gchar *) names[i]; key; key = (gchar *) names[++i]) {
		if (g_str_equal("name", key) == TRUE) {
			req->files = g_list_append(req->files,
					g_strdup(values[i]));
			name = g_strdup(values[i]);

		} else if (g_str_equal("size", key) == TRUE) {
			guint64 size;
			size = g_ascii_strtoll(values[i], NULL, 10);
			stbuf->st_size = size;

		} else if (g_str_equal("created", key) == TRUE) {
			GTimeVal time;
			GDateTime *datetime;
			g_time_val_from_iso8601(values[i], &time);
			datetime = g_date_time_new_from_timeval_utc(&time);
			stbuf->st_mtime = g_date_time_to_unix(datetime);
		}
	}

	if (g_str_equal("/", session->path) == TRUE)
		pathname = g_strdup_printf("/%s", name);
	else
		pathname = g_strdup_printf("%s/%s", session->path, name);

	g_free(name);

	g_hash_table_replace(session->file_stat, pathname, stbuf);
}

static const GMarkupParser parser = {
	listfolder_xml_element,
	NULL, NULL, NULL, NULL
};

static gboolean async_listfolder_consumer(const void *buf, gsize len,
							gpointer user_data)
{
	GMarkupParseContext *ctxt;
	struct gobexhlp_data *session = user_data;

	ctxt = g_markup_parse_context_new(&parser, 0, session, NULL);
	g_markup_parse_context_parse(ctxt, buf, len, NULL);
	g_markup_parse_context_free(ctxt);

	g_print("ASYNC_LISTFOLDER COMPLETED (%d)\n", (int)len);

	return TRUE;
}


#define PATH_GET_FILE 1
#define PATH_GET_DIRS 2

static gchar *path_get_element(const char *path, uint option)
{
	guint len, i;
	gchar *tmpstr = NULL, *retstr = NULL;
	gchar **directories;

	directories = g_strsplit(path, "/", -1);
	len = g_strv_length(directories);

	for (i = 0; i < len; i++)
		if (directories[i][0] != '\0') { /* protect multi slashes */
			tmpstr = directories[i]; /* last set is a file */
		}

	if (option == PATH_GET_FILE)
		retstr = g_strdup(tmpstr);

	else if (option == PATH_GET_DIRS) {
		for (i = len - 1; i >= 0; i--) {
			if (directories[i] == tmpstr) {
				directories[i][0] = '\0'; /* remove file */
				break;
			}
		}
		retstr = g_strjoinv("/", directories);
		if (retstr[0] == '\0') {
			g_free(retstr);
			retstr = g_strdup("/");
		}
	}

	g_strfreev(directories);

	return retstr;
}

void gobexhlp_setpath(struct gobexhlp_data* session, const char *path)
{
	guint len, i;
	gchar **directories, *withslash, *withslash2;
	const char *setpath;

	g_print("gobexhlp_setpath(%s)\n", path);

	withslash = g_strdup_printf("%s/", path);
	withslash2 = g_strdup_printf("%s/", session->setpath);

	if (g_strcmp0(session->setpath, path) == 0 ||
		g_strcmp0(session->setpath, withslash) == 0 ||
		g_strcmp0(withslash2, path) == 0) {
		g_print("setpath: already here\n");
		return;
	}
	g_free(withslash);
	g_free(withslash2);

	if (path[0] == '/' && session->pathdepth > 0) {
		//g_print("[/]:setroot /\n");
		gobexhlp_request_new(session,
				g_strdup_printf("setpath root"));
		g_obex_setpath(session->obex, NULL, response_func,
							session, NULL);
		gobexhlp_request_wait_free(session);
		session->pathdepth = 0;
		setpath = path + 1; /* to pass first '/' character */
	} else {
		setpath = path;
	}

	directories = g_strsplit(setpath, "/", -1);
	len = g_strv_length(directories);

	for (i = 0; i < len; i++) {
		if (directories[i][0] != '\0') { /* to protect multi / */
			//g_print("[%d]:setpath %s\n", i, directories[i]);
			gobexhlp_request_new(session,
					g_strdup_printf("setpath %s",
						directories[i]));
			g_obex_setpath(session->obex, directories[i],
						response_func, session, NULL);
			gobexhlp_request_wait_free(session);
			session->pathdepth++;
		}
	}

	g_free(session->setpath);
	session->setpath = g_strdup(path);

	g_strfreev(directories);
}

GList *gobexhlp_listfolder(struct gobexhlp_data* session, const char *path)
{
	GObexPacket *req;
	struct gobexhlp_listfolder_req *lsreq;
	guint reqpkt;

	session->path = path;
	gobexhlp_setpath( session, path);

	g_print("gobexhlp_listfolder(%s)\n", path);

	lsreq = g_malloc0(sizeof(*lsreq));
	lsreq->files = g_list_alloc();
	g_hash_table_replace(session->listfolder_req, g_strdup(path), lsreq);
	
	gobexhlp_request_new(session, g_strdup_printf("listfolder %s", path));
	req = g_obex_packet_new(G_OBEX_OP_GET, TRUE, G_OBEX_HDR_INVALID);
	g_obex_packet_add_bytes(req, G_OBEX_HDR_TYPE, OBEX_FTP_LS,
						strlen(OBEX_FTP_LS) + 1);
	reqpkt = g_obex_get_req_pkt(session->obex, req,
				async_listfolder_consumer,
				complete_func,
				session, NULL);

	gobexhlp_request_wait_free(session);

	return lsreq->files;
}

struct stat *gobexhlp_getattr(struct gobexhlp_data* session, const char *path)
{
	struct stat* stbuf;

	stbuf = g_hash_table_lookup(session->file_stat, path);

	return stbuf;
}

void gobexhlp_mkdir(struct gobexhlp_data* session, const char *path)
{
	struct stat *stbuf;
	gchar *npath, *target;

	npath = path_get_element(path, PATH_GET_DIRS);
	target = path_get_element(path, PATH_GET_FILE);

	g_print("gobexhlp_mkdir(%s)\n", path);

	gobexhlp_setpath(session, npath);
	
	gobexhlp_request_new(session, g_strdup_printf("mkdir %s", path));

	/* g_obex_mkdir also sets path, to new folder */
	g_obex_mkdir(session->obex, target, response_func, session, NULL);
	g_free(session->setpath);
	session->setpath = g_strdup(path);
	session->pathdepth++;

	stbuf = g_malloc0(sizeof(struct stat));
	stbuf->st_mode = S_IFDIR;
	stbuf->st_mtime = time(NULL);
	g_hash_table_replace(session->file_stat, g_strdup(path), stbuf);

	gobexhlp_request_wait_free(session);

	g_free(npath);
	g_free(target);
}

static gboolean async_get_consumer(const void *buf, gsize len,
							gpointer user_data)
{
	struct gobexhlp_data *session = user_data;
	struct gobexhlp_buffer *buffer = session->buffer;

	//if ( buffer->tmpsize <= 10000) 
	g_print("async_get_consumer():[%d.%d.%d]:\n", (int)len,
				(int)buffer->tmpsize, (int)buffer->size);

	memcpy(buffer->data + buffer->tmpsize, buf, len);
	buffer->tmpsize += len;

	if (buffer->tmpsize == buffer->size) {
		g_print(">>> get: file transfered\n");
	}

	//sleep(5);
	return TRUE;
}

struct gobexhlp_buffer *gobexhlp_get(struct gobexhlp_data* session,
						const char *path)
{
	gchar *npath, *target;
	struct gobexhlp_buffer *buffer;
	struct stat *stfile;

	g_print("gobexhlp_get(%s)\n", path);

	stfile = gobexhlp_getattr(session, path);
	if (stfile == NULL)
		return NULL;

	buffer = g_malloc0(sizeof(*buffer));
	buffer->data = g_malloc0(sizeof(char) * stfile->st_size);
	buffer->size = stfile->st_size;
	buffer->tmpsize = 0;
	buffer->edited = FALSE;

	if (buffer->size == 0) {
		return buffer;
	}

	npath = path_get_element(path, PATH_GET_DIRS);
	target = path_get_element(path, PATH_GET_FILE);
	gobexhlp_setpath(session, npath);

	gobexhlp_request_new(session, g_strdup_printf("get %s", path));
	session->buffer = buffer;
	g_obex_get_req(session->obex, async_get_consumer,
					complete_func, session, NULL,
					G_OBEX_HDR_NAME, target,
					G_OBEX_HDR_INVALID);

	gobexhlp_request_wait_free(session);
	
	g_free(npath);
	g_free(target);
	
	return buffer;
}

static gssize async_put_producer(void *buf, gsize len, gpointer user_data)
{
	gssize size;
	struct gobexhlp_data *session = user_data;
	struct gobexhlp_buffer *buffer = session->buffer;

	size = buffer->size - buffer->tmpsize;

	if (size > len) {
		size = len;
	}

	//if (buffer->size - buffer->tmpsize <= 40000 ||
	//		buffer->tmpsize <= 30000 )
	g_print("async_put_producer():[%d.%d.%d.%d]:\n", (int)len,
				(int)buffer->tmpsize, (int)buffer->size,
				(int)size);

	if (size == 0) {
		g_print(">>> put: file transfered\n");
		return 0;
	}


	memcpy(buf, buffer->data + buffer->tmpsize, size);
	buffer->tmpsize += size;

	return size;
}

void gobexhlp_put(struct gobexhlp_data* session,
				struct gobexhlp_buffer *buffer,
				const char *path)
{
	gchar *npath, *target;
	//struct stat *stbuf;

	npath = path_get_element(path, PATH_GET_DIRS);
	target = path_get_element(path, PATH_GET_FILE);
	g_print("gobexhlp_put(%s%s)\n", npath, target);
	
	if (gobexhlp_getattr(session, path) != NULL)
		gobexhlp_delete(session, path);

	buffer->tmpsize = 0;

	session->buffer = buffer;
	gobexhlp_request_new(session, g_strdup_printf("put %s", path));
	g_obex_put_req(session->obex, async_put_producer,
					complete_func, session, NULL,
					G_OBEX_HDR_NAME, target,
					G_OBEX_HDR_INVALID);
	g_free(npath);
	g_free(target);

	gobexhlp_request_wait_free(session);
}

void gobexhlp_touch(struct gobexhlp_data* session, const char *path)
{
	//struct gobexhlp_buffer *buffer;
	struct stat *stbuf;

	//buffer = g_malloc0(sizeof(*buffer));
	//buffer->size = 0;
	//gobexhlp_put(session, buffer, path); /* virtual touch */

	stbuf = g_malloc0(sizeof(struct stat));
	stbuf->st_mode = S_IFREG;
	stbuf->st_mtime = stbuf->st_ctime = stbuf->st_atime = time(NULL);
	stbuf->st_size = 0;
	g_hash_table_replace(session->file_stat, g_strdup(path), stbuf);
}


/*
 * After rename or copy, HTC doesn't send any response,
 * SE does nothing.
 */
void gobexhlp_move(struct gobexhlp_data* session, const char *oldpath,
		const char* newpath)
{
	gchar *npath, *target, *newtarget;

	npath = path_get_element(oldpath, PATH_GET_DIRS);
	target = path_get_element(oldpath, PATH_GET_FILE);
	newtarget = path_get_element(newpath, PATH_GET_FILE);

	gobexhlp_setpath(session, npath);

	g_print("gobexhlp_move(%s to %s)\n", target, newtarget);

	gobexhlp_request_new(session, g_strdup_printf("move %s:%s",
				oldpath, newpath));
	g_obex_move(session->obex, target, newtarget, response_func,
					session, NULL);

	g_free(npath);
	g_free(target);
	g_free(newtarget);
	
	gobexhlp_request_wait_free(session);
}


void gobexhlp_delete(struct gobexhlp_data* session, const char *path)
{
	gchar *npath, *target;

	npath = path_get_element(path, PATH_GET_DIRS);
	target = path_get_element(path, PATH_GET_FILE);

	gobexhlp_setpath(session, npath);

	g_print("gobexhlp_delete(%s)\n", target);

	gobexhlp_request_new(session, g_strdup_printf("delete %s", path));
	g_obex_delete(session->obex, target, response_func, session, NULL);

	g_hash_table_remove(session->file_stat, path);
	g_free(npath);
	g_free(target);

	gobexhlp_request_wait_free(session);
}
