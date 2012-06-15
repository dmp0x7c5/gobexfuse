/* Example gobex usage */

/* Notes:
 compile: 
gcc  -I/usr/include/glib-2.0 -I/usr/lib64/glib-2.0/include -I../  ../gobex/gobex.h ../gobex/gobex.c ../gobex/gobex-defs.h ../gobex/gobex-defs.c ../gobex/gobex-packet.c ../gobex/gobex-packet.h ../gobex/gobex-header.c ../gobex/gobex-header.h ../gobex/gobex-transfer.c ../gobex/gobex-debug.h ../btio/btio.h ../btio/btio.c  listfolder.c -o listfolder -lbluetooth -lreadline -lglib-2.0
 
 my htc: 18:87:96:4D:F0:9F 
 grep -R 'x-obex/folder-listing' *
 
*/

/*
obc_transfer type x-obex/folder-listing
and "xfer" stands for "transfer"
*/
// sdptool browse 18:87:96:4D:F0:9F

#include <stdlib.h>
#include <stdio.h>

#include <bluetooth/bluetooth.h>

#include <gobex/gobex.h>
#include <btio/btio.h>

//from client/bluetooth.c
#define BT_RX_MTU 32767
#define BT_TX_MTU 32767

#define OBEX_FTP_UUID \
	"\xF9\xEC\x7B\xC4\x95\x3C\x11\xD2\x98\x4E\x52\x54\x00\xDC\x9E\x09"
#define OBEX_FTP_UUID_LEN 16

#define OBEX_FTP_LS "x-obex/folder-listing"


static GObex *obex = NULL;
static GMainLoop *main_loop = NULL;

static void xml_element(GMarkupParseContext *ctxt,
			const gchar *element,
			const gchar **names,
			const gchar **values,
			gpointer user_data,
			GError **gerr)
{
	gchar *key;
	gint i;

	if (strcasecmp("file", element) != 0 && strcasecmp("folder", element) != 0)
		return;
	g_print("%s ", element);

	i = 0;
	for (key = (gchar *) names[i]; key; key = (gchar *) names[++i]) {
		if (g_str_equal("size", key) == TRUE) {
			guint64 size;
			size = g_ascii_strtoll(values[i], NULL, 10);
			g_print( "size:%d ", (int)size);
		} else
			g_print( "%s:%s ", key, values[i]);
	}
	g_print("\n");

}

static const GMarkupParser parser = {
	xml_element,
	NULL,
	NULL,
	NULL,
	NULL
};

static gboolean data_consumer (const void *buf, gsize len, gpointer user_data)
{
	GMarkupParseContext *ctxt;

	ctxt = g_markup_parse_context_new(&parser, 0, NULL, NULL);
	g_markup_parse_context_parse(ctxt, buf, len, NULL);
	g_markup_parse_context_free(ctxt);

	return TRUE;
}

static void get_complete(GObex *obex, GError *err, gpointer user_data)
{
	if (err != NULL)
		g_print("get failed: %s\n", err->message);
	else
		g_print("get succeeded\n");
}

static void conn_complete(GObex *obex, GError *err, GObexPacket *rsp,
							gpointer user_data)
{
	GObexPacket *req;
	guint xfer;

	if (err != NULL)
		g_print("Connect failed: %s\n", err->message);
	else
		g_print("Connect succeeded\n");


	// get filelist:
	// obc_transfer_get( type, name, filename, err)
	// ftp.c… transfer = obc_transfer_get("x-obex/folder-listing", NULL, NULL, &err);
	// transfer.c… transfer = obc_transfer_create(G_OBEX_OP_GET, filename, name, type); // creating obc_transfer struct
	// transfer.c… perr = transfer_open(transfer, O_WRONLY | O_CREAT | O_TRUNC, 0600, err); // prepare local file
	
	req = g_obex_packet_new(G_OBEX_OP_GET, TRUE, G_OBEX_HDR_INVALID);

	/*if (transfer->name != NULL)
		g_obex_packet_add_unicode(req, G_OBEX_HDR_NAME,
							transfer->name);
	*/
	g_obex_packet_add_bytes(req, G_OBEX_HDR_TYPE, OBEX_FTP_LS,
						strlen(OBEX_FTP_LS) + 1);
	xfer = g_obex_get_req_pkt(obex, req, data_consumer, get_complete, NULL, NULL);
	
}

static void disconn_func(GObex *obex, GError *err, gpointer user_data)
{
	g_printerr("Disconnected: %s\n", err ? err->message : "(no error)");
}

static void transport_callback(GIOChannel *io, GError *err, gpointer user_data)
{
	GObexTransportType transport = GPOINTER_TO_UINT(user_data);

	if (err != NULL) {
		g_printerr("here:%s\n", err->message);
		return;
	}

	g_print("Bluetooth socket connected\n");

	obex = g_obex_new(io, transport, BT_TX_MTU, BT_RX_MTU);
	g_obex_set_disconnect_function(obex, disconn_func, NULL);

	g_obex_connect(obex, conn_complete, NULL, NULL,
			G_OBEX_HDR_TARGET, OBEX_FTP_UUID, OBEX_FTP_UUID_LEN,
			G_OBEX_HDR_INVALID);
}


int main(int argc, char *argv[]) {

	GObexTransportType transport;
	GIOChannel *io;
	GError *err = NULL;

	// hard coded two phones
	uint16_t port = 5;
	char dststr[] = "18:87:96:4D:F0:9F";
	//uint16_t port = 7;
	//char dststr[] = "00:24:EF:08:B6:32";

	transport = G_OBEX_TRANSPORT_STREAM;

	/*if (port > 31) {
		io = bt_io_connect(BT_IO_L2CAP, transport_callback, GUINT_TO_POINTER(transport),
				NULL, &err,
				BT_IO_OPT_DEST_BDADDR, dststr,
				BT_IO_OPT_PSM, port,
				BT_IO_OPT_MODE, BT_IO_MODE_ERTM,
				BT_IO_OPT_OMTU, BT_TX_MTU,
				BT_IO_OPT_IMTU, BT_RX_MTU,
				BT_IO_OPT_SEC_LEVEL, BT_IO_SEC_LOW,
				BT_IO_OPT_INVALID);
	} else {*/
	io = bt_io_connect(BT_IO_RFCOMM, transport_callback, GUINT_TO_POINTER(transport),
			NULL, &err,
			BT_IO_OPT_DEST, dststr,
			BT_IO_OPT_CHANNEL, port,
			BT_IO_OPT_SEC_LEVEL, BT_IO_SEC_LOW,
			BT_IO_OPT_INVALID);
	//}

	if (io != NULL) {
		g_print("io ok\n");
	} else {
		g_print("m:%s\n", err->message);
		g_error_free(err);
		exit(EXIT_FAILURE);
	}

	main_loop = g_main_loop_new(NULL, FALSE);
	g_main_loop_run(main_loop);


	exit(EXIT_SUCCESS);
}
