# $Id$

MAINTAINERCLEANFILES =		$(srcdir)/Makefile.in

AM_CFLAGS =			-I$(srcdir)/.. \
				-I$(srcdir)/../..

lib_LTLIBRARIES = 		libeemo_demo.la

libeemo_demo_la_SOURCES =	eemo_demo_entry.c \
				../eemo_plugin_log.c \
				../eemo_plugin_log.h

libeemo_demo_la_LDFLAGS =	-version-info @EEMO_DEMO_VERSION_INFO@
