
#include <stdlib.h>
#include <stdio.h>

#include <gobex/gobex.h>
#include <btio/btio.h>

#include <glib.h>

// includes for get_ftp_channel()
#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

// from client/bluetooth.c
#define BT_RX_MTU 32767
#define BT_TX_MTU 32767

#define OBEX_FTP_UUID \
	"\xF9\xEC\x7B\xC4\x95\x3C\x11\xD2\x98\x4E\x52\x54\x00\xDC\x9E\x09"
#define OBEX_FTP_UUID_LEN 16

#define OBEX_FTP_LS "x-obex/folder-listing"

struct gobexhlp_data {
	const char *target;
	uint16_t channel;
	GIOChannel *io;
	GObex *obex;
	uint8_t pathdepth;
	GHashTable *file_stat;
	GList *files;
	const char *path;
	int foobar;
};

struct gobexhlp_data* gobexhlp_connect(const char *target);
void gobexhlp_setpath(struct gobexhlp_data* session, const char *path);
void gobexhlp_openfolder(struct gobexhlp_data* session, const char *path);

uint16_t get_ftp_channel(const char *dststr)
{
	sdp_session_t *sdp;
	sdp_list_t *response_list = NULL, *search_list, *attrid_list;
	uuid_t uuid;
	bdaddr_t dst;

	// FTP_SDP_UUID "00001106-0000-1000-8000-00805f9b34fb"
	uint8_t uuid_int[] = {0, 0, 0x11, 0x06, 0, 0, 0x10, 0, 0x80,
					0, 0, 0x80, 0x5f, 0x9b, 0x34, 0xfb};
	uint32_t range = 0x0000ffff;
	uint16_t channel = -1;
	
	str2ba(	dststr, &dst);
	
	sdp = sdp_connect( BDADDR_ANY, &dst, SDP_RETRY_IF_BUSY );
	if (sdp == NULL)
		return channel;

	sdp_uuid128_create(&uuid, uuid_int);
	
	search_list = sdp_list_append( NULL, &uuid);
	attrid_list = sdp_list_append( NULL, &range);

	sdp_service_search_attr_req( sdp, search_list, SDP_ATTR_REQ_RANGE,
					attrid_list, &response_list);

	sdp_list_t *r = response_list;
	
	for (;r;r = r->next) {
		sdp_record_t *rec = (sdp_record_t*) r->data;
		sdp_list_t *proto_list;

		// get a list of the protocol sequences
		if (sdp_get_access_protos( rec, &proto_list ) == 0) {
			sdp_list_t *p = proto_list;
			// go through each protocol sequence
			for (;p;p = p->next) {
				sdp_list_t *pds = (sdp_list_t*)p->data;
				// go through each protocol list of the protocol sequence
				for (;pds;pds = pds->next) {
					 // check the protocol attributes
					sdp_data_t *d = (sdp_data_t*)pds->data;
					int proto = 0;
					for (;d;d=d->next) {
						switch(d->dtd) { 
						case SDP_UUID16:
						case SDP_UUID32:
						case SDP_UUID128:
							proto = sdp_uuid_to_proto(&d->val.uuid);
						break;
                        			case SDP_UINT8:
                            				if(proto == RFCOMM_UUID)
								channel = d->val.int8; 
                            			break;
						}
					}
				}
            			sdp_list_free( (sdp_list_t*)p->data, 0);
			}
		sdp_list_free( proto_list, 0);
		}
	sdp_record_free(rec);
	}
	sdp_close(sdp);

	return channel;
}

static void obex_callback(GObex *obex, GError *err, GObexPacket *rsp,
							gpointer user_data)
{
	struct gobexhlp_data *session = user_data;
	
	if (err != NULL)
		g_print("Connect failed: %s\n", err->message);
	else
		g_print("Connect succeeded\n");

}

static void bt_io_callback(GIOChannel *io, GError *err, gpointer user_data)
{
	GObex *obex;
	struct gobexhlp_data *session = user_data;

	if (err != NULL) {
		g_printerr("%s\n", err->message);
		return;
	}

	g_print("Bluetooth socket connected\n");
	
	g_io_channel_set_flags(session->io, G_IO_FLAG_NONBLOCK, NULL);
	g_io_channel_set_close_on_unref(session->io, TRUE);

	obex = g_obex_new(io, G_OBEX_TRANSPORT_STREAM, BT_TX_MTU, BT_RX_MTU);
	session->obex = g_obex_ref(obex);
	//g_obex_set_disconnect_function(session->obex, disconn_func, NULL);

	g_obex_connect(session->obex, obex_callback, session, NULL,
			G_OBEX_HDR_TARGET, OBEX_FTP_UUID, OBEX_FTP_UUID_LEN,
			G_OBEX_HDR_INVALID);
}

struct gobexhlp_data* gobexhlp_connect(const char *target)
{
	uint16_t channel;
	GError *err = NULL;
	struct gobexhlp_data *session;

	session = g_try_malloc0(sizeof(*session));
	if (session == NULL)
		return NULL;

	session->target = target;
	session->channel = get_ftp_channel(target);
	if (session->channel == -1)
		return NULL;
	
	session->io = bt_io_connect(BT_IO_RFCOMM, bt_io_callback,
			session, NULL, &err,
			BT_IO_OPT_DEST, target,
			BT_IO_OPT_CHANNEL, session->channel,
			BT_IO_OPT_SEC_LEVEL, BT_IO_SEC_LOW,
			BT_IO_OPT_INVALID);
	
	session->pathdepth = 0;
	session->foobar = 0;

	//session->folder_table = g_hash_table_new( g_str_hash, g_str_equal);

	return session;
}

void gobexhlp_clear(struct gobexhlp_data* session)
{
	g_obex_unref(session->obex);
	g_list_free(session->files);
	g_free(session);
}

static void response_func(GObex *obex, GError *err, GObexPacket *rsp,
							gpointer user_data)
{
	if (err != NULL)
		g_error("%s\n", err->message);
	g_print("responde_func\n");
}

static void complete_func(GObex *obex, GError *err, gpointer user_data)
{
	if (err != NULL)
		g_error("%s\n", err->message);
	g_print("complete_func\n");
}


static void listfolder_xml_element(GMarkupParseContext *ctxt,
			const gchar *element, const gchar **names,
			const gchar **values, gpointer user_data,
			GError **gerr)
{
	gchar *key;
	gint i;
	struct gobexhlp_data *session = user_data;

	if (strcasecmp("file", element) != 0 &&
		strcasecmp("folder", element) != 0)
		return;
	g_print("%s ", element);

	i = 0;
	for (key = (gchar *) names[i]; key; key = (gchar *) names[++i]) {
		if (g_str_equal("name", key) == TRUE) {
			g_print( "nejm:%s ", values[i]);
			session->files = g_list_append(session->files,
					g_strdup(values[i]));

		} if (g_str_equal("size", key) == TRUE) {
			guint64 size;
			size = g_ascii_strtoll(values[i], NULL, 10);
			g_print( "size:%d(int) ", (int)size);

		} if (g_str_equal("created", key) == TRUE) {
			GTimeVal time;
			GDateTime *datetime;
			gboolean status = g_time_val_from_iso8601(values[i], &time);
			datetime = g_date_time_new_from_timeval_utc(&time);
			g_print( "date:(%s) ",
				(char*)g_date_time_format(datetime, "%F %T" ));
		} else {
			g_print( "%s:%s ", key, values[i]);
		}
	}
	g_print("\n");

}

static const GMarkupParser parser = {
	listfolder_xml_element,
	NULL,
	NULL,
	NULL,
	NULL
};

static gboolean listfolder_consumer(const void *buf, gsize len,
							gpointer user_data)
{
	GMarkupParseContext *ctxt;
	struct gobexhlp_data *session = user_data;
	session->foobar++;

	//g_print("from(%s) data consumer:(%d)\n%s\n--end--\n", session->target,
	//						(int)len, (char*)buf);
	if (session->files != NULL) {
		g_list_free(session->files);
	}
	session->files = g_list_alloc();

	ctxt = g_markup_parse_context_new(&parser, 0, session, NULL);
	g_markup_parse_context_parse(ctxt, buf, len, NULL);
	g_print("endofparse\n");
	g_markup_parse_context_free(ctxt);

	//g_hash_table_replace( session->folder_table, "path", files);

	return TRUE;
}

void gobexhlp_setpath(struct gobexhlp_data* session, const char *path)
{
	guint len, i;
	gchar **directories;
	const char *setpath;

	if (path[0] == '/' && session->pathdepth > 0) {
		g_print("[X]:setroot /\n");
		for (i = 0; i < session->pathdepth; i++)
			g_obex_setpath(session->obex, "..", response_func,
							NULL, NULL);
		session->pathdepth = 0;
		setpath = path+1;
	} else {
		setpath = path;
	}

	directories = g_strsplit(setpath, "/", -1);
	len = g_strv_length(directories);
	for (i = 0; i < len; i++) {
		if(directories[i][0] != '\0') { // to protect multi slashes
			g_print("[%d]:setpath %s\n", i, directories[i]);
			g_obex_setpath(session->obex, directories[i],
						response_func, NULL, NULL);
			session->pathdepth++;
		}
	}
}

void gobexhlp_openfolder(struct gobexhlp_data* session, const char *path)
{
	GObexPacket *req;
	g_print("openfolder %s\n", path);
	
	gobexhlp_setpath( session, path);
	session->path = path;

	req = g_obex_packet_new(G_OBEX_OP_GET, TRUE, G_OBEX_HDR_INVALID);
	g_obex_packet_add_bytes(req, G_OBEX_HDR_TYPE, OBEX_FTP_LS,
						strlen(OBEX_FTP_LS) + 1);
	g_obex_get_req_pkt(session->obex, req, listfolder_consumer, complete_func,
							session, NULL);
}


void gobexhlp_readfolder(struct gobexhlp_data* session, const char *path)
{
	int len, i;
	gchar *string;
	
	g_print(">>> readfolder\n");
	if ( session->path = path) {
		len = g_list_length(session->files);
		g_print(">>> path equals (len:%d)\n", len);
		for (i = 1; i < len; i++) { // element for i==0 is NULL
			string = g_list_nth_data(session->files, i);
			g_print("%d.%s ", i, string);
			g_free(string);
		}
		g_print("\n");
	}
}
