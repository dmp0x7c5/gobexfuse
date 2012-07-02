/* compile:
gcc  -I/usr/include/glib-2.0 -I/usr/lib64/glib-2.0/include -I../  ../gobex/gobex.h ../gobex/gobex.c ../gobex/gobex-defs.h ../gobex/gobex-defs.c ../gobex/gobex-packet.c ../gobex/gobex-packet.h ../gobex/gobex-header.c ../gobex/gobex-header.h ../gobex/gobex-transfer.c ../gobex/gobex-debug.h ../btio/btio.h ../btio/btio.c testgobexhlp.c -o testgobexhlp -lbluetooth -lreadline -lglib-2.0 -lgthread-2.0
*/

#include <gobex/gobex.h>
#include <btio/btio.h>

#include <glib.h>
#include <fcntl.h>

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
	GHashTable *listfolder_req;
	const char *path;
	gchar *setpath;
};

struct gobexhlp_listfolder_req {
	GList *files;
	gboolean complete;
};

struct gobexhlp_buffer {
	void *data;
	gsize tmpsize;
	gsize size;
	gboolean complete;
};


struct gobexhlp_data* gobexhlp_connect(const char *target);
void gobexhlp_disconnect(struct gobexhlp_data* session);
void gobexhlp_setpath(struct gobexhlp_data* session, const char *path);
GList *gobexhlp_listfolder(struct gobexhlp_data* session, const char *path);
struct stat *gobexhlp_getattr(struct gobexhlp_data* session,
				const char *path);


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
                            				if (proto == RFCOMM_UUID)
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


void free_listfolder_req(gpointer data)
{
	struct gobexhlp_listfolder_req *req = data;
	g_list_free_full(req->files, g_free);
	g_free(req);
}


struct gobexhlp_data* gobexhlp_connect(const char *target)
{
	uint16_t channel;
	GError *err = NULL;
	struct gobexhlp_data *session;
	
	g_print("gobexhlp_connect()\n");

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
	

	session->file_stat = g_hash_table_new_full( g_str_hash, g_str_equal,
					g_free, g_free);
	session->listfolder_req = g_hash_table_new_full( g_str_hash,
				g_str_equal, g_free, free_listfolder_req);

	session->pathdepth = 0;
	session->setpath = g_strdup("/");

	return session;
}


void gobexhlp_disconnect(struct gobexhlp_data* session)
{
	g_print("gobexhlp_disconnect()\n");
	
	g_io_channel_shutdown(session->io, TRUE, NULL);
	g_io_channel_unref(session->io);
	g_obex_unref(session->obex);

	g_hash_table_remove_all(session->file_stat);
	g_hash_table_remove_all(session->listfolder_req);
	g_free(session->setpath);

	g_free(session);
	session = NULL;
}


static void response_func(GObex *obex, GError *err, GObexPacket *rsp,
							gpointer user_data)
{
	if (err != NULL)
		g_error("response_func: %s\n", err->message);
}


static void complete_func(GObex *obex, GError *err, gpointer user_data)
{
	if (err != NULL)
		g_error("complete_func: %s\n", err->message);
}


static void listfolder_xml_element(GMarkupParseContext *ctxt,
			const gchar *element, const gchar **names,
			const gchar **values, gpointer user_data,
			GError **gerr)
{
	gchar *key, *name, *pathname;
	gint i;
	struct gobexhlp_data *session = user_data;
	struct gobexhlp_listfolder_req *req;
	struct stat *stbuf;

	stbuf = g_malloc0(sizeof(struct stat));

	if ((strcasecmp("file", element) == 0)) {
		stbuf->st_mode = S_IFREG;
	}
	else if ((strcasecmp("folder", element)) == 0) {
		stbuf->st_mode = S_IFDIR;
		stbuf->st_mtime = time(NULL);
	}
	else {
		return;
	}

	req = g_hash_table_lookup(session->listfolder_req, session->path);

	i = 0;
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
			gboolean status = g_time_val_from_iso8601(values[i], &time);
			datetime = g_date_time_new_from_timeval_utc(&time);
			stbuf->st_mtime = g_date_time_to_unix(datetime);
		}
	}

	if (g_str_equal("/", session->path) == TRUE)
		pathname = g_strdup_printf("/%s", name);
	else
		pathname = g_strdup_printf("%s/%s", session->path, name);

	g_print("%s ", pathname);
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
	struct gobexhlp_listfolder_req *req;
	const char *b = buf;
	int i;

	/*
	g_print("async_listfolder_consumer(%s):[%d]:\n<data>\n",
						session->path, (int)len);
	for (i = 0; i < len; i++)
		g_print("%c", b[i]);
	g_print("</data>\n");
	*/

	g_print("listfolder_xml_element consumed: ");
	ctxt = g_markup_parse_context_new(&parser, 0, session, NULL);
	g_markup_parse_context_parse(ctxt, buf, len, NULL);
	g_markup_parse_context_free(ctxt);
	g_print("\n");
	
	req = g_hash_table_lookup(session->listfolder_req, session->path);
	req->complete = TRUE;

	return TRUE;
}


#define PATH_GET_FILE 1
#define PATH_GET_DIRS 2

gchar *path_get_element(const char *path, uint option)
{
	guint len, i;
	gchar *tmpstr = NULL, *retstr;
	gchar **directories;

	directories = g_strsplit(path, "/", -1);
	len = g_strv_length(directories);
	for (i = 0; i < len; i++)
		if (directories[i][0] != '\0') { // to protect multi slashes
			tmpstr = directories[i]; // last set is a file
		}

	if (option == PATH_GET_FILE)
		retstr = g_strdup(tmpstr);
	
	else if (option == PATH_GET_DIRS) {
		for (i = len-1; i >= 0; i--) {
			if( directories[i] == tmpstr) {
				directories[i][0] = '\0'; // remove file
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
	gchar **directories;
	const char *setpath;
	gchar *filename = NULL;

	g_print("gobexhlp_setpath(%s)\n", path);
	
	if (g_strcmp0(session->setpath, path) == 0) { 
		g_print("setpath: already here\n");
		return;
	}

	if (path[0] == '/' && session->pathdepth > 0) {
		g_print("[/]:setroot /\n");
		g_obex_setpath(session->obex, NULL, response_func,
							NULL, NULL);
		session->pathdepth = 0;
		setpath = path + 1; // to pass first '/' character
	} else {
		setpath = path;
	}

	directories = g_strsplit(setpath, "/", -1);
	len = g_strv_length(directories);
	for (i = 0; i < len; i++) {
		if (directories[i][0] != '\0') { // to protect multi slashes
			g_print("[%d]:setpath %s\n", i, directories[i]);
			g_obex_setpath(session->obex, directories[i],
						response_func, NULL, NULL);
			session->pathdepth++;
			filename = directories[i];
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
	guint reqpkt, start;
	guint timeout = 5;

	session->path = path;
	gobexhlp_setpath( session, path);

	g_print("gobexhlp_listfolder(%s)\n", path);
	
	lsreq = g_malloc0(sizeof(*lsreq));
	lsreq->files = g_list_alloc();
	lsreq->complete = FALSE;

	g_hash_table_replace(session->listfolder_req, g_strdup(path), lsreq);

	req = g_obex_packet_new(G_OBEX_OP_GET, TRUE, G_OBEX_HDR_INVALID);
	g_obex_packet_add_bytes(req, G_OBEX_HDR_TYPE, OBEX_FTP_LS,
						strlen(OBEX_FTP_LS) + 1);

	reqpkt = g_obex_get_req_pkt(session->obex, req,
				async_listfolder_consumer, complete_func,
				session, NULL);
	/*
	 * In case of "du -sh sth" it fails, waits till timeout, probably
	 * due to intense queries function aync_listfolder_consumer doesn't
	 * run - sleep(10) between request solves issue. 
	 * Note: Maybe intense setpath causes this freeze?
	 */
	g_print("(while lsreq->complete)\n");
	start = time(NULL);
	while (lsreq->complete != TRUE)
		if (time(NULL) > start + timeout) {
			g_print("\nTimeout\n\n");
			break;
		}

	return lsreq->files;
}


struct stat *gobexhlp_getattr(struct gobexhlp_data* session, const char *path)
{
	struct stat* stbuf;
	gchar *npath;

	stbuf = g_hash_table_lookup(session->file_stat, path);

	if (stbuf == NULL) {
		npath = path_get_element(path, PATH_GET_DIRS);
		gobexhlp_listfolder(session, npath);
		g_free(npath);
		stbuf = g_hash_table_lookup(session->file_stat, path);
	}

	return stbuf;
}


void gobexhlp_mkdir(struct gobexhlp_data* session, const char *path)
{
	struct stat *stbuf;
	gchar *npath, *target;

	npath = path_get_element(path, PATH_GET_DIRS);
	target = path_get_element(path, PATH_GET_FILE);

	//g_print("npath:%s(%d)\ntarget:%s\n", npath, (int)strlen(npath), target);
	g_print("gobexhlp_mkdir(%s)\n", path);

	gobexhlp_setpath(session, npath);

	// g_obex_mkdir also sets path, to new folder
	g_obex_mkdir(session->obex, target, response_func, NULL, NULL); 
	g_free(session->setpath);
	session->setpath = g_strdup(path);
	session->pathdepth++;

	stbuf = g_malloc0(sizeof(struct stat));
	stbuf->st_mode = S_IFDIR;
	stbuf->st_mtime = time(NULL);
	g_hash_table_replace(session->file_stat, g_strdup(path), stbuf);
	
	
	g_free(npath);
	g_free(target);
}


static gboolean async_read_consumer(const void *buf, gsize len,
							gpointer user_data)
{
	struct gobexhlp_buffer *buffer = user_data;
	int i;
	const char *b = buf;

	g_print("async_read_consumer():[%d]:\n", (int)len);
	/*
	g_print("<data>\n");
	for (i = 0; i < len; i++)
		g_print("%c", b[i]);
	g_print("</data>\n");
	*/

	memcpy(buffer->data + buffer->tmpsize, buf, len);
	buffer->tmpsize += len;

	if (buffer->tmpsize == buffer->size) {
		g_print(">>> file transfered\n");
		buffer->complete = TRUE;
	}

	return TRUE;
}


struct gobexhlp_buffer *gobexhlp_get(struct gobexhlp_data* session,
						const char *path)
{
	gchar *npath, *target;
	struct gobexhlp_buffer *buffer;
	guint start;
	struct stat *stfile;
	guint timeout = 60;

	npath = path_get_element(path, PATH_GET_DIRS);
	target = path_get_element(path, PATH_GET_FILE);
	gobexhlp_setpath(session, npath);

	g_print("gobexhlp_get(%s:%s)\n", npath, target);
	stfile = gobexhlp_getattr(session, path);
	if (stfile == NULL)
		return NULL;

	buffer = g_malloc0(sizeof(*buffer));
	buffer->data = g_malloc0(sizeof(char) * stfile->st_size);
	buffer->size = stfile->st_size;
	buffer->complete = FALSE;
	buffer->tmpsize = 0;

	g_obex_get_req(session->obex, async_read_consumer,
					complete_func, buffer, NULL,
					G_OBEX_HDR_NAME, target,
					G_OBEX_HDR_INVALID);
	
	g_free(npath);
	g_free(target);
	
	g_print("(while buffer->complete)\n");
	start = time(NULL);
	while (buffer->complete != TRUE)
		if (time(NULL) > start + timeout) {
			g_print("\nTimeout\n\n");
			break;
		}

	return buffer;
}


