// compile: gcc  -I/usr/include/glib-2.0 -I/usr/lib64/glib-2.0/include getftpchannel.c -o getftpchannel -lbluetooth -lglib-2.0

#include <stdio.h>

// "An Introduction to Bluetooth Programming" - http://people.csail.mit.edu/albert/bluez-intro/ was really useful
// also http://www.humbug.in/2010/sample-bluetooth-rfcomm-client-app-in-c/

#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <glib.h>

#define FTP_SDP_UUID "00001106-0000-1000-8000-00805f9b34fb"

/* function taken from client/bluetooth.c */
static int bt_string2uuid(uuid_t *uuid, const char *string)
{
	uint32_t data0, data4;
	uint16_t data1, data2, data3, data5;

	if (sscanf(string, "%08x-%04hx-%04hx-%04hx-%08x%04hx",
				&data0, &data1, &data2, &data3, &data4, &data5) == 6) {
		uint8_t val[16];

		data0 = g_htonl(data0);
		data1 = g_htons(data1);
		data2 = g_htons(data2);
		data3 = g_htons(data3);
		data4 = g_htonl(data4);
		data5 = g_htons(data5);

		memcpy(&val[0], &data0, 4);
		memcpy(&val[4], &data1, 2);
		memcpy(&val[6], &data2, 2);
		memcpy(&val[8], &data3, 2);
		memcpy(&val[10], &data4, 4);
		memcpy(&val[14], &data5, 2);

		sdp_uuid128_create(uuid, val);

		return 0;
	}

	return -1;
}



int main(int argc, const char *argv[]) {
	sdp_session_t *sdp;
	sdp_list_t *response_list = NULL, *search_list, *attrid_list;
	int err;
	uint32_t range = 0x0000ffff;
	uuid_t uuid;
	//char dststr[] = "00:24:EF:08:B6:32";
	char dststr[] = "18:87:96:4D:F0:9F";
	bdaddr_t dst;
	str2ba(	dststr, &dst);

	sdp = sdp_connect( BDADDR_ANY, &dst, SDP_RETRY_IF_BUSY );
	if( sdp == NULL) {
		g_error("sdp connect fail\n");
	} else {
		g_print("sdp connect ok\n");
	}

	bt_string2uuid( &uuid, FTP_SDP_UUID);
	search_list = sdp_list_append( NULL, &uuid);
	attrid_list = sdp_list_append( NULL, &range);

	err = sdp_service_search_attr_req( sdp, search_list,
			SDP_ATTR_REQ_RANGE, attrid_list, &response_list);

// SPD:
    sdp_list_t *r = response_list;
    int channel = -1;

    // go through each of the service records
    for (; r; r = r->next ) {
        sdp_record_t *rec = (sdp_record_t*) r->data;
        sdp_list_t *proto_list;
        
        // get a list of the protocol sequences
        if( sdp_get_access_protos( rec, &proto_list ) == 0 ) {
        sdp_list_t *p = proto_list;

        // go through each protocol sequence
        for( ; p ; p = p->next ) {
            sdp_list_t *pds = (sdp_list_t*)p->data;

            // go through each protocol list of the protocol sequence
            for( ; pds ; pds = pds->next ) {

                // check the protocol attributes
                sdp_data_t *d = (sdp_data_t*)pds->data;
                int proto = 0;
                for( ; d; d = d->next ) {
                    switch( d->dtd ) { 
                        case SDP_UUID16:
                        case SDP_UUID32:
                        case SDP_UUID128:
                            proto = sdp_uuid_to_proto( &d->val.uuid );
                            break;
                        case SDP_UINT8:
                            if( proto == RFCOMM_UUID ) {
				channel = d->val.int8; 
			    }
                            break;
                    }
                }
            }
            sdp_list_free( (sdp_list_t*)p->data, 0 );
        }
        sdp_list_free( proto_list, 0 );

        }

        printf("found service record 0x%x\n", rec->handle);
        sdp_record_free( rec );
    }
	if( channel == -1) {
		g_error("FTP service not found");
	}
	g_print("FTP channel: %d\n", channel);

	sdp_close(sdp);
	return 0;
}
