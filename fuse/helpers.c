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

static GCond *gobexhlp_cond;
static GMutex *gobexhlp_mutex;

struct gobexhlp_request {
	gchar *name;
	gboolean complete;
};

struct gobexhlp_location {
	gchar *dir;
	gchar *file;
};

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

static uint16_t get_ftp_channel(bdaddr_t *src, bdaddr_t *dst)
{
	sdp_session_t *sdp;
	sdp_list_t *r, *search_list, *attrid_list;
	sdp_list_t *response_list = NULL;
	uuid_t uuid;

	/* FTP_SDP_UUID "00001106-0000-1000-8000-00805f9b34fb" */
	uint8_t uuid_int[] = {0, 0, 0x11, 0x06, 0, 0, 0x10, 0, 0x80,
					0, 0, 0x80, 0x5f, 0x9b, 0x34, 0xfb};
	uint32_t range = 0x0000ffff;
	uint16_t channel = 0;

	sdp = sdp_connect(src, dst, SDP_RETRY_IF_BUSY );
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

	g_free(search_list);
	g_free(attrid_list);
	g_free(response_list);

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
	if (err != NULL) {
		g_debug("Connect failed: %s\n", err->message);
		g_error_free(err);
	} else {
		g_debug("Connect succeeded\n");
	}
}

static void bt_io_callback(GIOChannel *io, GError *err, gpointer user_data)
{
	struct gobexhlp_session *session = user_data;
	GObexTransportType type;
	int tx_mtu = -1;
	int rx_mtu = -1;

	if (err != NULL) {
		g_printerr("%s\n", err->message);
		g_error_free(err);
		return;
	}

	g_debug("Bluetooth socket connected\n");

	g_io_channel_set_flags(session->io, G_IO_FLAG_NONBLOCK, NULL);
	g_io_channel_set_close_on_unref(session->io, TRUE);

	if (get_packet_opt(session->io, &tx_mtu, &rx_mtu) == 0) {
		type = G_OBEX_TRANSPORT_PACKET;
		g_debug("PACKET transport tx:%d rx:%d\n", tx_mtu, rx_mtu);
	} else {
		type = G_OBEX_TRANSPORT_STREAM;
		g_debug("STREAM transport\n");
	}

	session->obex = g_obex_new(io, type, tx_mtu, rx_mtu);
	g_obex_connect(session->obex, obex_callback, session, NULL,
				G_OBEX_HDR_TARGET, OBEX_FTP_UUID,
				OBEX_FTP_UUID_LEN, G_OBEX_HDR_INVALID);
}

struct gobexhlp_session* gobexhlp_connect(const char *srcstr,
						const char *dststr)
{
	struct gobexhlp_session *session;
	uint16_t channel;
	bdaddr_t src, dst;

	session = g_try_malloc0(sizeof(struct gobexhlp_session));
	if (session == NULL)
		return NULL;

	if (srcstr == NULL)
		bacpy(&src, BDADDR_ANY);
	else
		str2ba(srcstr, &src);

	str2ba(dststr, &dst);
	channel = get_ftp_channel(&src, &dst);

	if (channel == 0)
		return NULL;

	if (channel > 31)
		session->io = bt_io_connect(BT_IO_L2CAP, bt_io_callback,
				session, NULL, &session->err,
				BT_IO_OPT_SOURCE_BDADDR, &src,
				BT_IO_OPT_DEST_BDADDR, &dst,
				BT_IO_OPT_PSM, channel,
				BT_IO_OPT_MODE, BT_IO_MODE_ERTM,
				BT_IO_OPT_OMTU, BT_TX_MTU,
				BT_IO_OPT_IMTU, BT_RX_MTU,
				BT_IO_OPT_SEC_LEVEL, BT_IO_SEC_LOW,
				BT_IO_OPT_INVALID);
	else
		session->io = bt_io_connect(BT_IO_RFCOMM, bt_io_callback,
				session, NULL, &session->err,
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

	gobexhlp_mutex = g_mutex_new();
	gobexhlp_cond = g_cond_new();

	return session;
}

void gobexhlp_disconnect(struct gobexhlp_session* session)
{
	if (session == NULL)
		return;

	g_obex_unref(session->obex);
	g_free(session->io);

	g_hash_table_remove_all(session->file_stat);
	g_list_free_full(session->lsfiles, g_free);
	g_free(session->setpath);

	g_mutex_free(gobexhlp_mutex);
	g_cond_free(gobexhlp_cond);

	g_free(session);
}

void request_new(struct gobexhlp_session *session,
					gchar *name)
{
	g_print("REQUEST %s\n", name);

	if (session->request != NULL)
		g_error("Another request (%s) active!\n",
					session->request->name);

	session->status = 0;
	session->request = g_malloc0(sizeof(struct gobexhlp_request));
	session->request->name = name;

	/*
	 * suspend/resume operations recreates g_io_add_watch(),
	 * it fixes obex->io freeze during transfer
	 */
	g_obex_suspend(session->obex);
	g_obex_resume(session->obex);
}

void request_wait_free(struct gobexhlp_session *session)
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

	g_mutex_lock(gobexhlp_mutex);

	while (session->request->complete != TRUE)
		g_cond_wait(gobexhlp_cond, gobexhlp_mutex);

	g_mutex_unlock(gobexhlp_mutex);

	g_free(session->request->name);
	g_free(session->request);
	session->request = NULL;
}

static void complete_func(GObex *obex, GError *err,
				gpointer user_data)
{
	struct gobexhlp_session *session = user_data;

	if (err != NULL) {
		g_print("ERROR: %s\n", err->message);
		session->status = -ECANCELED;
		g_error_free(err);
	} else {
		g_print("COMPLETE %s\n", session->request->name);
	}

	g_mutex_lock(gobexhlp_mutex);
	session->request->complete = TRUE;
	g_cond_signal(gobexhlp_cond);
	g_mutex_unlock(gobexhlp_mutex);
}

static void response_func(GObex *obex, GError *err, GObexPacket *rsp,
							gpointer user_data)
{
	complete_func(obex, err, user_data);
}

void gobexhlp_setpath(struct gobexhlp_session *session, const char *path)
{
	guint i = 0, split = 0;
	gchar **path_v;
	gsize len;

	g_print("gobexhlp_setpath(%s)\n", path);

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
	struct gobexhlp_session *session = user_data;
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
	struct gobexhlp_session *session = user_data;
	struct gobexhlp_buffer *buffer = session->buffer;

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
	struct gobexhlp_session *session = user_data;
	struct gobexhlp_buffer *buffer = session->buffer;

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

GList *gobexhlp_listfolder(struct gobexhlp_session* session,
					const char *path)
{
	struct gobexhlp_buffer *buffer;
	GObexPacket *req;
	guint reqpkt;

	gobexhlp_setpath(session, path);

	g_print("gobexhlp_listfolder(%s)\n", path);

	if (session->lsfiles != NULL) {
		g_list_free_full(session->lsfiles, g_free);
		session->lsfiles = NULL;
	}

	session->lsfiles = g_list_alloc();
	buffer = g_malloc0(sizeof(struct gobexhlp_buffer));
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
