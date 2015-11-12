# $Id$

MAINTAINERCLEANFILES =		$(srcdir)/Makefile.in

AM_CFLAGS =			-I$(srcdir)/.. \
				-I$(srcdir)/../..

lib_LTLIBRARIES = 		libeemo_dumppcap.la

libeemo_dumppcap_la_SOURCES =	dumppcap.c \
				../eemo_plugin_log.c \
				../eemo_plugin_log.h

libeemo_dumppcap_la_LDFLAGS =	-version-info @EEMO_DUMPPCAP_VERSION_INFO@
