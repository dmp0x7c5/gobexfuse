
AM_MAKEFLAGS = --no-print-directory

servicedir = $(datarootdir)/dbus-1/services

service_in_files =

doc_files = doc/obexd-api.txt doc/agent-api.txt doc/client-api.txt

test_files = test/simple-agent test/exchange-business-cards \
		test/list-folders test/pbap-client test/ftp-client \
		test/map-client test/opp-client

gdbus_sources = gdbus/gdbus.h gdbus/mainloop.c gdbus/watch.c \
					gdbus/object.c gdbus/polkit.c

btio_sources = btio/btio.h btio/btio.c

gobex_sources = gobex/gobex.h gobex/gobex.c \
			gobex/gobex-defs.h gobex/gobex-defs.c \
			gobex/gobex-packet.c gobex/gobex-packet.h \
			gobex/gobex-header.c gobex/gobex-header.h \
			gobex/gobex-transfer.c gobex/gobex-debug.h \
			gobex/gobex-apparam.h gobex/gobex-apparam.c

noinst_PROGRAMS =
libexec_PROGRAMS =

if SERVER
confdir = $(sysconfdir)/obex

service_in_files += src/obexd.service.in

builtin_modules =
builtin_sources =
builtin_nodist =

builtin_modules += bluetooth
builtin_sources += plugins/bluetooth.c

if USB
builtin_modules += usb
builtin_sources += plugins/usb.c
endif

builtin_modules += filesystem
builtin_sources += plugins/filesystem.c plugins/filesystem.h

if NOKIA_PCSUITE
builtin_modules += pcsuite
builtin_sources += plugins/pcsuite.c
endif

builtin_modules += opp
builtin_sources += plugins/opp.c

builtin_modules += ftp
builtin_sources += plugins/ftp.c plugins/ftp.h

builtin_modules += pbap
builtin_sources += plugins/pbap.c plugins/phonebook.h \
			plugins/vcard.h plugins/vcard.c

builtin_modules += mas
builtin_sources += plugins/mas.c plugins/messages.h \
			src/map_ap.h

builtin_modules += irmc
builtin_sources += plugins/irmc.c

builtin_modules += syncevolution
builtin_sources += plugins/syncevolution.c

builtin_nodist += plugins/phonebook.c
builtin_nodist += plugins/messages.c

libexec_PROGRAMS += src/obexd

src_obexd_SOURCES = $(gdbus_sources) $(builtin_sources) $(btio_sources) \
			$(gobex_sources) src/main.c src/obexd.h \
			src/plugin.h src/plugin.c \
			src/log.h src/log.c src/manager.h src/manager.c \
			src/obex.h src/obex.c src/obex-priv.h \
			src/mimetype.h src/mimetype.c \
			src/service.h src/service.c \
			src/transport.h src/transport.c \
			src/server.h src/server.c

src_obexd_LDADD = @DBUS_LIBS@ @GLIB_LIBS@ @GTHREAD_LIBS@ \
					@EBOOK_LIBS@ @BLUEZ_LIBS@ \
					@LIBICAL_LIBS@ @TRACKER_LIBS@ -ldl

src_obexd_LDFLAGS = -Wl,--export-dynamic

builtin_files = src/builtin.h $(builtin_nodist)

nodist_src_obexd_SOURCES = $(builtin_files)

plugindir = $(libdir)/obex/plugins

plugin_LTLIBRARIES =

src/plugin.$(OBJEXT): src/builtin.h

src/builtin.h: src/genbuiltin $(builtin_sources)
	$(AM_V_GEN)$(srcdir)/src/genbuiltin $(builtin_modules) > $@

endif

if CLIENT
service_in_files += client/obex-client.service.in

libexec_PROGRAMS += client/obex-client

client_obex_client_SOURCES = $(gdbus_sources) $(gobex_sources) \
				$(btio_sources) \
				client/main.c src/log.h src/log.c \
				client/manager.h client/manager.c \
				client/session.h client/session.c \
				client/bluetooth.h client/bluetooth.c \
				client/sync.h client/sync.c \
				client/pbap.h client/pbap.c \
				client/ftp.h client/ftp.c \
				client/opp.h client/opp.c \
				client/map.h client/map.c \
				client/transfer.h client/transfer.c \
				client/transport.h client/transport.c \
				client/dbus.h client/dbus.c \
				client/driver.h client/driver.c \
				src/map_ap.h

client_obex_client_LDADD = @GLIB_LIBS@ @DBUS_LIBS@ @BLUEZ_LIBS@
endif

if FUSE
bin_PROGRAMS = fuse/gobexfuse
#noinst_PROGRAMS += fuse/gobexfuse

fuse_gobexfuse_SOURCES = $(gobex_sources) $(btio_sources) \
		fuse/helpers.c fuse/gobexfuse.c

fuse_gobexfuse_LDADD = @GLIB_LIBS@ @GTHREAD_LIBS@ @BLUEZ_LIBS@ @FUSE_LIBS@ 
endif

service_DATA = $(service_in_files:.service.in=.service)

AM_CFLAGS = @BLUEZ_CFLAGS@ @EBOOK_CFLAGS@ @GTHREAD_CFLAGS@ @GLIB_CFLAGS@ \
			@DBUS_CFLAGS@ @LIBICAL_CFLAGS@ @TRACKER_CFLAGS@ \
			-DOBEX_PLUGIN_BUILTIN -DPLUGINDIR=\""$(plugindir)"\" \
			-D_FILE_OFFSET_BITS=64

INCLUDES = -I$(builddir)/src -I$(srcdir)/src -I$(srcdir)/plugins \
				-I$(srcdir)/gdbus \
				-I$(srcdir)/btio -I$(srcdir)/gobex

CLEANFILES = $(service_DATA) $(builtin_files)

EXTRA_DIST = src/genbuiltin $(doc_files) $(test_files) \
			src/obexd.service.in client/obex-client.service.in \
			plugins/phonebook-dummy.c plugins/phonebook-ebook.c \
			plugins/phonebook-tracker.c \
			plugins/messages-dummy.c plugins/messages-tracker.c

DISTCHECK_CONFIGURE_FLAGS = --enable-client --enable-server

MAINTAINERCLEANFILES = Makefile.in \
	aclocal.m4 configure config.h.in config.sub config.guess \
	ltmain.sh depcomp compile missing install-sh mkinstalldirs

%.service: %.service.in config.log
	$(AM_V_GEN)$(SED) -e "s|\@libexecdir\@|$(libexecdir)|" $< > $@

plugins/phonebook.c: plugins/@PHONEBOOK_DRIVER@
	$(AM_V_GEN)$(LN_S) @abs_top_srcdir@/$< $@

plugins/messages.c: plugins/@MESSAGES_DRIVER@
	$(AM_V_GEN)$(LN_S) @abs_top_srcdir@/$< $@

TESTS = unit/test-gobex-apparam unit/test-gobex-header unit/test-gobex-packet \
				unit/test-gobex unit/test-gobex-transfer

noinst_PROGRAMS += unit/test-gobex-header unit/test-gobex-packet \
			unit/test-gobex unit/test-gobex-transfer \
			unit/test-gobex-apparam

unit_test_gobex_SOURCES = $(gobex_sources) unit/test-gobex.c \
							unit/util.c unit/util.h
unit_test_gobex_LDADD = @GLIB_LIBS@

unit_test_gobex_packet_SOURCES = $(gobex_sources) unit/test-gobex-packet.c \
							unit/util.c unit/util.h
unit_test_gobex_packet_LDADD = @GLIB_LIBS@

unit_test_gobex_header_SOURCES = $(gobex_sources) unit/test-gobex-header.c \
							unit/util.c unit/util.h
unit_test_gobex_header_LDADD = @GLIB_LIBS@

unit_test_gobex_transfer_SOURCES = $(gobex_sources) unit/util.c unit/util.h \
						unit/test-gobex-transfer.c
unit_test_gobex_transfer_LDADD = @GLIB_LIBS@

unit_test_gobex_apparam_SOURCES = $(gobex_sources) unit/util.c unit/util.h \
						unit/test-gobex-apparam.c
unit_test_gobex_apparam_LDADD = @GLIB_LIBS@

if READLINE
noinst_PROGRAMS += tools/test-client
tools_test_client_SOURCES = $(gobex_sources) $(btio_sources) \
							tools/test-client.c
tools_test_client_LDADD = @GLIB_LIBS@ @BLUEZ_LIBS@ @READLINE_LIBS@
endif

noinst_PROGRAMS += tools/test-server
tools_test_server_SOURCES = $(gobex_sources) $(btio_sources) \
							tools/test-server.c
tools_test_server_LDADD = @GLIB_LIBS@ @BLUEZ_LIBS@
