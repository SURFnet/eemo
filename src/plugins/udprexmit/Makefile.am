# $Id$

MAINTAINERCLEANFILES =		$(srcdir)/Makefile.in

AM_CFLAGS =			-I$(srcdir)/.. \
				-I$(srcdir)/../..

lib_LTLIBRARIES = 		libeemo_udprexmit.la

libeemo_udprexmit_la_SOURCES =	eemo_udprexmit.c \
				../eemo_plugin_log.c \
				../eemo_plugin_log.h

libeemo_udprexmit_la_LDFLAGS =	-version-info @EEMO_UDPREXMIT_VERSION_INFO@
