/* compile: 
gcc  -I/usr/include/glib-2.0 -I/usr/lib64/glib-2.0/include -I../  ../gobex/gobex.h ../gobex/gobex.c ../gobex/gobex-defs.h ../gobex/gobex-defs.c ../gobex/gobex-packet.c ../gobex/gobex-packet.h ../gobex/gobex-header.c ../gobex/gobex-header.h ../gobex/gobex-transfer.c ../gobex/gobex-debug.h ../btio/btio.h ../btio/btio.c testgobexhlp.c -o testgobexhlp -lbluetooth -lreadline -lglib-2.0
*/

#include "helpers.c"
#include <glib.h>

static GMainLoop *main_loop = NULL;

gboolean menu(gpointer user_data)
{
	struct gobexhlp_data *session = user_data;
	char cmd;
	char cmdstr[50];
	
		scanf("%c", &cmd);
		switch (cmd) {
		case 's':
			scanf("%s", cmdstr);
			gobexhlp_setpath(session, cmdstr);
		break;
		case 'l':
			//scanf("%s", cmdstr);
			gobexhlp_openfolder(session, cmdstr);
		break;
		case 'q':
			return FALSE;
		break;
		case 'p':
			g_print("pong\n");
		break;
		case 'Q':
			g_main_loop_quit(main_loop);
		break;
		}

	return TRUE;
}

int main(int argc, const char *argv[])
{
	struct gobexhlp_data* session = NULL;
	//char dststr[] = "00:24:EF:08:B6:32";
	char dststr[] = "18:87:96:4D:F0:9F";
	char cmd;
	char cmdstr[50];
	
	session = gobexhlp_connect(dststr);
	if (session == NULL || session->io == NULL)
		g_error("Connection to %s failed\n", dststr);
	
	main_loop = g_main_loop_new(NULL, FALSE);
	g_idle_add( menu, session);
	g_main_loop_run(main_loop);

	return 0;
}

