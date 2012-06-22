
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
};

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

	//bt_string2uuid( &uuid, FTP_SDP_UUID);
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
	if (err != NULL)
		g_print("Connect failed: %s\n", err->message);
	else
		g_print("Connect succeeded\n");

}

static void bt_io_callback(GIOChannel *io, GError *err, gpointer user_data)
{
	struct gobexhlp_data *session = user_data;

	if (err != NULL) {
		g_printerr("here:%s\n", err->message);
		return;
	}

	g_print("Bluetooth socket connected\n");

	session->obex = g_obex_new(io, G_OBEX_TRANSPORT_STREAM, BT_TX_MTU, BT_RX_MTU);
	//g_obex_set_disconnect_function(session->obex, disconn_func, NULL);

	g_obex_connect(session->obex, obex_callback, NULL, NULL,
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

	return session;
}

