/* compile: 
gcc  -I/usr/include/glib-2.0 -I/usr/lib64/glib-2.0/include -I../  ../gobex/gobex.h ../gobex/gobex.c ../gobex/gobex-defs.h ../gobex/gobex-defs.c ../gobex/gobex-packet.c ../gobex/gobex-packet.h ../gobex/gobex-header.c ../gobex/gobex-header.h ../gobex/gobex-transfer.c ../gobex/gobex-debug.h ../btio/btio.h ../btio/btio.c testgobexhlp.c -o testgobexhlp -lbluetooth -lreadline -lglib-2.0
*/

#include "helpers.c"
#include <glib.h>

static GMainLoop *main_loop = NULL;
struct gobexhlp_data* session = NULL;

gboolean menu()
{
	char cmd = ' ';
	char cmdstr[50];
	
	char dststr[] = "18:87:96:4D:F0:9F";
	//char dststr[] = "00:24:EF:08:B6:32";
	
	while(cmd != 'Q') {
		scanf("%c", &cmd);
		switch (cmd) {
		case 'c':
			session = gobexhlp_connect(dststr);
			if (session == NULL || session->io == NULL)
				g_error("Connection to %s failed\n", dststr);
		break;
		case 'l':
			scanf("%s", cmdstr);
			gobexhlp_openfolder(session, cmdstr);
		break;
		case 'p':
			g_print("pong\n");
		break;
		case 'i':
			g_print("loopbool: %s\n",
					g_main_loop_is_running(main_loop) ==
					TRUE ? "true" : "false");
		break;
		case 'r':
			gobexhlp_readfolder(session, cmdstr);
		break;
		}
	}
	g_main_loop_quit(main_loop);

	return TRUE;
}

gpointer main_loop_func(gpointer data)
{

	main_loop = g_main_loop_new(NULL, FALSE);
	g_main_loop_run(main_loop);
}

int main(int argc, const char *argv[])
{
	GThread * main_gthread;

	g_thread_init(NULL);
	main_gthread = g_thread_create(main_loop_func, NULL, TRUE, NULL);
	menu();
	
	return 0;
}

