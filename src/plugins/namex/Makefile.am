# $Id$

MAINTAINERCLEANFILES =		$(srcdir)/Makefile.in

lib_LTLIBRARIES = 		libeemo_namex.la

libeemo_namex_la_CFLAGS =	@PTHREAD_CFLAGS@ \
				-I$(srcdir)/.. \
				-I$(srcdir)/../.. 

libeemo_namex_la_SOURCES =	namex.c \
				../eemo_plugin_log.c \
				../eemo_plugin_log.h

libeemo_namex_la_LDFLAGS =	-version-info @EEMO_NAMEX_VERSION_INFO@ @PTHREAD_LIBS@
