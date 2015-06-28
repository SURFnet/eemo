# $Id$

MAINTAINERCLEANFILES =		$(srcdir)/Makefile.in

AM_CFLAGS =			-I$(srcdir)/.. \
				-I$(srcdir)/../..

lib_LTLIBRARIES = 		libeemo_dnszabbix.la

libeemo_dnszabbix_la_SOURCES =	eemo_dnszabbix_entry.c \
				eemo_dnszabbix_stats.c \
				eemo_dnszabbix_stats.h \
				../eemo_plugin_log.c \
				../eemo_plugin_log.h

libeemo_dnszabbix_la_LDFLAGS =	-version-info @EEMO_DNSZABBIX_VERSION_INFO@
