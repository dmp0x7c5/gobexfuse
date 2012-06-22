/* compile: 
gcc  -I/usr/include/glib-2.0 -I/usr/lib64/glib-2.0/include -I../  ../gobex/gobex.h ../gobex/gobex.c ../gobex/gobex-defs.h ../gobex/gobex-defs.c ../gobex/gobex-packet.c ../gobex/gobex-packet.h ../gobex/gobex-header.c ../gobex/gobex-header.h ../gobex/gobex-transfer.c ../gobex/gobex-debug.h ../btio/btio.h ../btio/btio.c testgobexhlp.c -o testgobexhlp -lbluetooth -lreadline -lglib-2.0
*/

#include "helpers.c"
#include <glib.h>

struct gobexhlp_data* session;
static GMainLoop *main_loop = NULL;

int main(int argc, const char *argv[])
{
	char dststr[] = "00:24:EF:08:B6:32";
	//char dststr[] = "18:87:96:4D:F0:9F";
	
	session = gobexhlp_connect( dststr);
	if (session == NULL || session->io == NULL)
		g_error("Connection to %s failed\n", dststr);
	
	main_loop = g_main_loop_new(NULL, FALSE);
	g_main_loop_run(main_loop);
	
	return 0;
}

