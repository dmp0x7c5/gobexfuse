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
#include <btio/btio.h>

#include <glib.h>
#include <fcntl.h>
#include <errno.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#define BT_RX_MTU 32767
#define BT_TX_MTU 32767

#include "helpers.h"

#define OBEX_FTP_UUID \
	"\xF9\xEC\x7B\xC4\x95\x3C\x11\xD2\x98\x4E\x52\x54\x00\xDC\x9E\x09"
#define OBEX_FTP_UUID_LEN 16

#define OBEX_FTP_LS "x-obex/folder-listing"

static GCond *obexhlp_cond;
static GMutex *obexhlp_mutex;

struct obexhlp_request {
	gchar *name;
	gboolean complete;
};

struct obexhlp_location {
	gchar *dir;
	gchar *file;
};

void obexhlp_touch_real(struct obexhlp_session* session, gchar *path);

static volatile sig_atomic_t __sdp_io_finished = 0;

/* adopted from client/bluetooth.c - search_callback() */
static void search_callback(uint8_t type, uint16_t status,
			uint8_t *rsp, size_t size, void *user_data)
{
	struct obexhlp_session *session = user_data;
	unsigned int scanned, bytesleft = size;
	int seqlen = 0;
	uint8_t dataType;
	uint16_t port = 0;

	if (status || type != SDP_SVC_SEARCH_ATTR_RSP)
		goto done;

	scanned = sdp_extract_seqtype(rsp, bytesleft, &dataType, &seqlen);
	if (!scanned || !seqlen)
		goto done;

	rsp += scanned;
	bytesleft -= scanned;
	do {
		sdp_record_t *rec;
		sdp_list_t *protos;
		sdp_data_t *data;
		int recsize, ch = -1;

		recsize = 0;
		rec = sdp_extract_pdu(rsp, bytesleft, &recsize);
		if (!rec)
			break;

		if (!recsize) {
			sdp_record_free(rec);
			break;
		}

		if (!sdp_get_access_protos(rec, &protos)) {
			port = sdp_get_proto_port(protos, RFCOMM_UUID);
			sdp_list_foreach(protos,
					(sdp_list_func_t) sdp_list_free, NULL);
			sdp_list_free(protos, NULL);
			protos = NULL;
			goto done;
		}

		data = sdp_data_get(rec, 0x0200);
		/* PSM must be odd and lsb of upper byte must be 0 */
		if (data != NULL && (data->val.uint16 & 0x0101) == 0x0001)
			ch = data->val.uint16;

		sdp_record_free(rec);

		if (ch > 0) {
			port = ch;
			break;
		}

		scanned += recsize;
		rsp += recsize;
		bytesleft -= recsize;
	} while (scanned < size && bytesleft > 0);

done:
	session->channel = port;
	__sdp_io_finished = 1;
}

static uint16_t get_ftp_channel(struct obexhlp_session* session,
					bdaddr_t *src, bdaddr_t *dst)
{
	sdp_list_t *search, *attrid;
	uint32_t range = 0x0000ffff;
	sdp_session_t *sdp;
	uuid_t uuid;

	sdp = sdp_connect(src, dst, SDP_RETRY_IF_BUSY);
	if (sdp == NULL)
		return 0;

	/* FTP_SDP_UUID "00001106-0000-1000-8000-00805f9b34fb" */
	uint8_t uuid_int[] = {0, 0, 0x11, 0x06, 0, 0, 0x10, 0, 0x80,
					0, 0, 0x80, 0x5f, 0x9b, 0x34, 0xfb};
	sdp_uuid128_create(&uuid, uuid_int);

	if (sdp_set_notify(sdp, search_callback, session) < 0)
		goto done;

	search = sdp_list_append(NULL, &uuid);
	attrid = sdp_list_append(NULL, &range);

	if (sdp_service_search_attr_async(sdp,
				search, SDP_ATTR_REQ_RANGE, attrid) < 0) {
		sdp_list_free(attrid, NULL);
		sdp_list_free(search, NULL);
		goto done;
	}

	sdp_list_free(attrid, NULL);
	sdp_list_free(search, NULL);

	while (!__sdp_io_finished)
		sdp_process(sdp);

done:
	return session->channel;
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

	if (!bt_io_get(io, NULL, BT_IO_OPT_OMTU, &omtu,
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
	if (err != NULL) {
		g_print("OBEX Connect failed: %s\n", err->message);
		g_error_free(err);
	} else {
		g_print("OBEX Connect succeeded\n");
	}
}

static void bt_io_callback(GIOChannel *io, GError *err, gpointer user_data)
{
	struct obexhlp_session *session = user_data;
	GObexTransportType type;
	int tx_mtu = -1;
	int rx_mtu = -1;

	if (err != NULL) {
		g_printerr("%s\n", err->message);
		g_error_free(err);
		return;
	}

	g_print("Bluetooth socket connected\n");

	g_io_channel_set_close_on_unref(io, FALSE);

	if (get_packet_opt(io, &tx_mtu, &rx_mtu) == 0) {
		type = G_OBEX_TRANSPORT_PACKET;
		g_print("PACKET transport tx:%d rx:%d\n", tx_mtu, rx_mtu);
	} else {
		type = G_OBEX_TRANSPORT_STREAM;
		g_print("STREAM transport\n");
	}

	session->obex = g_obex_new(io, type, tx_mtu, rx_mtu);
	if (session->obex == NULL) {
		g_print("ERROR: obex is NULL");
		raise(SIGTERM);
	}

	g_io_channel_set_close_on_unref(io, TRUE);

	g_obex_connect(session->obex, obex_callback, session, &err,
				G_OBEX_HDR_TARGET, OBEX_FTP_UUID,
				OBEX_FTP_UUID_LEN, G_OBEX_HDR_INVALID);

	if (err != NULL) {
		g_print("ERROR: %s\n", err->message);
		g_obex_unref(session->obex);
		raise(SIGTERM);
	}
}

struct obexhlp_session* obexhlp_connect(const char *srcstr,
						const char *dststr)
{
	struct obexhlp_session *session;
	uint16_t channel;
	bdaddr_t src, dst;

	session = g_try_malloc0(sizeof(struct obexhlp_session));
	if (session == NULL)
		return NULL;

	if (srcstr == NULL)
		bacpy(&src, BDADDR_ANY);
	else
		str2ba(srcstr, &src);

	str2ba(dststr, &dst);
	channel = get_ftp_channel(session, &src, &dst);

	if (channel == 0)
		return NULL;

	if (channel > 31)
		session->io = bt_io_connect(bt_io_callback, session,
				NULL, &session->err,
				BT_IO_OPT_SOURCE_BDADDR, &src,
				BT_IO_OPT_DEST_BDADDR, &dst,
				BT_IO_OPT_PSM, channel,
				BT_IO_OPT_MODE, BT_IO_MODE_ERTM,
				BT_IO_OPT_OMTU, BT_TX_MTU,
				BT_IO_OPT_IMTU, BT_RX_MTU,
				BT_IO_OPT_SEC_LEVEL, BT_IO_SEC_LOW,
				BT_IO_OPT_INVALID);
	else
		session->io = bt_io_connect(bt_io_callback, session,
				NULL, &session->err,
				BT_IO_OPT_SOURCE_BDADDR, &src,
				BT_IO_OPT_DEST_BDADDR, &dst,
				BT_IO_OPT_CHANNEL, channel,
				BT_IO_OPT_SEC_LEVEL, BT_IO_SEC_LOW,
				BT_IO_OPT_INVALID);

	if (session->err != NULL)
		return NULL;

	session->file_stat = g_hash_table_new_full( g_str_hash, g_str_equal,
					g_free, g_free);
	session->setpath = g_strdup("/");

	obexhlp_mutex = g_mutex_new();
	obexhlp_cond = g_cond_new();

	return session;
}

void obexhlp_disconnect(struct obexhlp_session* session)
{
	if (session == NULL)
		return;

	g_obex_unref(session->obex);
	g_free(session->io);

	g_hash_table_remove_all(session->file_stat);
	g_list_free_full(session->lsfiles, g_free);
	g_free(session->setpath);

	g_mutex_free(obexhlp_mutex);
	g_cond_free(obexhlp_cond);

	g_free(session);
}

void request_new(struct obexhlp_session *session,
					gchar *name)
{
	g_print("REQUEST %s\n", name);

	if (session->vtouch == TRUE) {
		session->vtouch = FALSE;
		obexhlp_touch_real(session, session->vtouch_path);
		g_free(session->vtouch_path);
	}

	if (session->request != NULL)
		g_error("Another request (%s) active!\n",
					session->request->name);

	session->status = 0;
	session->request = g_malloc0(sizeof(struct obexhlp_request));
	session->request->name = name;

	/*
	 * suspend/resume operations recreates g_io_add_watch(),
	 * it fixes obex->io freeze during transfer
	 */
	g_obex_suspend(session->obex);
	g_obex_resume(session->obex);
}

void request_wait_free(struct obexhlp_session *session)
{
	g_print("WAIT for %s\n", session->request->name);

	g_obex_suspend(session->obex);
	g_obex_resume(session->obex);

	if (session->err != NULL) {
		g_print("ERROR: %s (%d)\n", session->err->message,
						session->err->code);
		g_error_free(session->err);
		raise(SIGTERM);
		return;
	}

	g_mutex_lock(obexhlp_mutex);

	while (session->request->complete != TRUE)
		g_cond_wait(obexhlp_cond, obexhlp_mutex);

	g_mutex_unlock(obexhlp_mutex);

	g_free(session->request->name);
	g_free(session->request);
	session->request = NULL;
}

static void complete_func(GObex *obex, GError *err,
				gpointer user_data)
{
	struct obexhlp_session *session = user_data;

	if (err != NULL) {
		g_print("ERROR: %s\n", err->message);
		session->status = -ECANCELED;
		g_error_free(err);
	} else {
		g_print("COMPLETE %s\n", session->request->name);
	}

	g_mutex_lock(obexhlp_mutex);
	session->request->complete = TRUE;
	g_cond_signal(obexhlp_cond);
	g_mutex_unlock(obexhlp_mutex);
}

static void response_func(GObex *obex, GError *err, GObexPacket *rsp,
							gpointer user_data)
{
	complete_func(obex, err, user_data);
}

void obexhlp_setpath(struct obexhlp_session *session, const char *path)
{
	guint i = 0, split = 0;
	gchar **path_v;
	gsize len;

	g_print("obexhlp_setpath(%s)\n", path);

	if (g_str_has_prefix(path, session->setpath)) {
		split = strlen(session->setpath);
	} else {
		request_new(session, g_strdup_printf("setpath root"));
		g_obex_setpath(session->obex, "", response_func,
						session, &session->err);
		request_wait_free(session);
	}

	path_v = g_strsplit(path+split, "/", -1);
	len = g_strv_length(path_v);

	for (i = 0; i < len; i++)
		if (path_v[i][0] != '\0') {
			request_new(session,
				g_strdup_printf("setpath %s", path_v[i]));
			g_obex_setpath(session->obex, path_v[i],
					response_func, session, &session->err);
			request_wait_free(session);
		}

	g_free(session->setpath);
	session->setpath = g_strdup(path);

	g_strfreev(path_v);
}

static void listfolder_xml_element(GMarkupParseContext *ctxt,
			const gchar *element, const gchar **names,
			const gchar **values, gpointer user_data,
			GError **gerr)
{
	gchar *key, *pathname, *name = NULL;
	struct obexhlp_session *session = user_data;
	struct stat *stbuf;
	gint i = 0;

	stbuf = g_malloc0(sizeof(struct stat));

	if ((strcasecmp("file", element) == 0)) {
		stbuf->st_mode = S_IFREG;
	} else if ((strcasecmp("folder", element)) == 0) {
		stbuf->st_mode = S_IFDIR;
		stbuf->st_mtime = time(NULL);
	} else {
		g_free(stbuf);
		return;
	}

	for (key = (gchar *) names[i]; key; key = (gchar *) names[++i]) {
		if (g_str_equal("name", key) == TRUE) {
			session->lsfiles = g_list_append(session->lsfiles,
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

	if (g_str_equal("/", session->setpath) == TRUE)
		pathname = g_strdup_printf("/%s", name);
	else
		pathname = g_strdup_printf("%s/%s", session->setpath, name);

	g_hash_table_replace(session->file_stat, pathname, stbuf);
	g_free(name);
}

static const GMarkupParser parser = {
	listfolder_xml_element,
	NULL, NULL, NULL, NULL
};

static void complete_listfolder_func(GObex *obex, GError *err,
				gpointer user_data)
{
	GMarkupParseContext *ctxt;
	struct obexhlp_session *session = user_data;
	struct obexhlp_buffer *buffer = session->buffer;

	if (err == NULL) {
		ctxt = g_markup_parse_context_new(&parser, 0, session, NULL);
		g_markup_parse_context_parse(ctxt, buffer->data, buffer->size,
							NULL);
		g_markup_parse_context_free(ctxt);
	}

	complete_func(obex, err, user_data);
}

static gboolean async_get_consumer(const void *buf, gsize len,
							gpointer user_data)
{
	struct obexhlp_session *session = user_data;
	struct obexhlp_buffer *buffer = session->buffer;

	if (buffer->size == 0)
		buffer->data = g_malloc0(sizeof(char) * len);
	else
		buffer->data = g_realloc(buffer->data, buffer->size + len);

	memcpy(buffer->data + buffer->size, buf, len);
	buffer->size += len;

	g_obex_suspend(session->obex);
	g_obex_resume(session->obex);

	return TRUE;
}

GList *obexhlp_listfolder(struct obexhlp_session* session,
					const char *path)
{
	struct obexhlp_buffer *buffer;
	GObexPacket *req;
	guint reqpkt;

	obexhlp_setpath(session, path);

	g_print("obexhlp_listfolder(%s)\n", path);

	if (session->lsfiles != NULL) {
		g_list_free_full(session->lsfiles, g_free);
		session->lsfiles = NULL;
	}

	session->lsfiles = g_list_alloc();
	buffer = g_malloc0(sizeof(struct obexhlp_buffer));
	session->buffer = buffer;

	request_new(session, g_strdup_printf("listfolder %s", path));
	req = g_obex_packet_new(G_OBEX_OP_GET, TRUE, G_OBEX_HDR_INVALID);
	g_obex_packet_add_bytes(req, G_OBEX_HDR_TYPE, OBEX_FTP_LS,
						strlen(OBEX_FTP_LS) + 1);
	reqpkt = g_obex_get_req_pkt(session->obex, req,
				async_get_consumer,
				complete_listfolder_func,
				session, &session->err);
	request_wait_free(session);
	g_free(buffer->data);
	g_free(buffer);

	return session->lsfiles;
}

struct stat *obexhlp_getattr(struct obexhlp_session* session,
					const char *path)
{
	return g_hash_table_lookup(session->file_stat, path);
}

static struct obexhlp_location *get_location(const char *path)
{
	struct obexhlp_location *location;
	gchar **directories;
	guint i, len, fid = 0;

	location = g_malloc0(sizeof(*location));
	directories = g_strsplit(path, "/", -1);
	len = g_strv_length(directories);

	for (i = 0; i < len; i++)
		if (directories[i][0] != '\0') /* protect multi slashes */
			fid = i; /* last nonempty is a file */

	location->file = g_strdup(directories[fid]);
	directories[fid][0] = '\0'; /* remove file */
	location->dir = g_strjoinv("/", directories);

	g_strfreev(directories);

	return location;
}

void free_location(struct obexhlp_location *location)
{
	g_free(location->file);
	g_free(location->dir);
	g_free(location);
}

struct obexhlp_buffer *obexhlp_get(struct obexhlp_session* session,
						const char *path)
{
	struct obexhlp_location *l;
	struct obexhlp_buffer *buffer;
	struct stat *stfile;
	l = get_location(path);

	g_print("obexhlp_get(%s%s)\n", l->dir, l->file);

	stfile = obexhlp_getattr(session, path);
	if (stfile == NULL)
		return NULL;

	buffer = g_malloc0(sizeof(*buffer));

	if (stfile->st_size == 0)
		return buffer;

	obexhlp_setpath(session, l->dir);
	request_new(session, g_strdup_printf("get %s", path));
	session->buffer = buffer;
	g_obex_get_req(session->obex, async_get_consumer,
					complete_func, session, &session->err,
					G_OBEX_HDR_NAME, l->file,
					G_OBEX_HDR_INVALID);
	free_location(l);
	request_wait_free(session);

	return buffer;
}

static gssize async_put_producer(void *buf, gsize len, gpointer user_data)
{
	gssize size;
	struct obexhlp_session *session = user_data;
	struct obexhlp_buffer *buffer = session->buffer;

	size = buffer->size - buffer->tmpsize;

	if (size > len)
		size = len;

	g_obex_suspend(session->obex);
	g_obex_resume(session->obex);

	if (size == 0)
		return 0;

	memcpy(buf, buffer->data + buffer->tmpsize, size);
	buffer->tmpsize += size;

	return size;
}

void obexhlp_put(struct obexhlp_session* session,
				struct obexhlp_buffer *buffer,
				const char *path)
{
	struct obexhlp_location *l;
	l = get_location(path);

	g_print("obexhlp_put(%s%s)\n", l->dir, l->file);

	if (g_strcmp0(path, session->vtouch_path) == 0 &&
				session->vtouch == TRUE) {
		session->vtouch = FALSE;
		g_free(session->vtouch_path);
	} else {
		/* delete existing file */
		if (session->rtouch == FALSE)
			obexhlp_delete(session, path);
	}

	obexhlp_setpath(session, l->dir);
	buffer->tmpsize = 0;
	session->buffer = buffer;
	request_new(session, g_strdup_printf("put %s", path));
	g_obex_put_req(session->obex, async_put_producer,
					complete_func, session, &session->err,
					G_OBEX_HDR_NAME, l->file,
					G_OBEX_HDR_INVALID);
	free_location(l);
	request_wait_free(session);
}

/* virtual file creation */
void obexhlp_touch(struct obexhlp_session* session, const char *path)
{
	struct stat *stbuf;

	g_print("obexhlp_touch(%s)\n", path);

	stbuf = g_malloc0(sizeof(struct stat));
	stbuf->st_mode = S_IFREG;
	g_hash_table_replace(session->file_stat, g_strdup(path), stbuf);

	session->vtouch = TRUE;
	session->vtouch_path = g_strdup(path);
}

void obexhlp_touch_real(struct obexhlp_session* session, gchar *path)
{
	struct obexhlp_buffer *buffer, *tmpbuf;

	g_print("obexhlp_touch_real(%s)\n", path);

	tmpbuf = session->buffer; /* save buffer state */

	buffer = g_malloc0(sizeof(struct obexhlp_buffer));
	session->rtouch = TRUE;
	obexhlp_put(session, buffer, path);
	session->rtouch = FALSE;
	g_free(buffer);

	session->buffer = tmpbuf;
}

void obexhlp_delete(struct obexhlp_session* session, const char *path)
{
	struct obexhlp_location *l;
	l = get_location(path);

	g_print("obexhlp_delete(%s)\n", l->file);

	obexhlp_setpath(session, l->dir);
	request_new(session, g_strdup_printf("delete %s", path));
	g_obex_delete(session->obex, l->file, response_func, session,
							&session->err);

	g_hash_table_remove(session->file_stat, path);

	free_location(l);
	request_wait_free(session);
}

void obexhlp_mkdir(struct obexhlp_session* session, const char *path)
{
	struct obexhlp_location *l;
	struct stat *stbuf;

	g_print("obexhlp_mkdir(%s)\n", path);

	l = get_location(path);
	obexhlp_setpath(session, l->dir);

	request_new(session, g_strdup_printf("mkdir %s", path));
	/* g_obex_mkdir also sets path, to new folder */
	g_obex_mkdir(session->obex, l->file, response_func, session,
							&session->err);
	g_free(session->setpath);
	session->setpath = g_strdup(path);

	stbuf = g_malloc0(sizeof(struct stat));
	stbuf->st_mode = S_IFDIR;
	stbuf->st_mtime = time(NULL);
	g_hash_table_replace(session->file_stat, g_strdup(path), stbuf);

	free_location(l);
	request_wait_free(session);
}

void obexhlp_move(struct obexhlp_session* session, const char *oldpath,
						const char* newpath)
{
	struct obexhlp_location *l_from, *l_to;

	l_to = get_location(newpath);
	l_from = get_location(oldpath);
	obexhlp_setpath(session, l_from->dir);

	g_print("obexhlp_move(%s to %s)\n", l_from->file, l_to->file);

	request_new(session, g_strdup_printf("move %s:%s",
					oldpath, newpath));
	g_obex_move(session->obex, l_from->file, l_to->file, response_func,
						session, &session->err);
	free_location(l_to);
	free_location(l_from);
	request_wait_free(session);
}
