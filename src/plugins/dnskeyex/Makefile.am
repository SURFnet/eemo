# $Id$

MAINTAINERCLEANFILES =		$(srcdir)/Makefile.in

lib_LTLIBRARIES = 		libeemo_dnskeyex.la

libeemo_dnskeyex_la_CFLAGS =	@PTHREAD_CFLAGS@ \
				-I$(srcdir)/.. \
				-I$(srcdir)/../.. 

libeemo_dnskeyex_la_SOURCES =	dnskeyex.c \
				../eemo_plugin_log.c \
				../eemo_plugin_log.h

libeemo_dnskeyex_la_LDFLAGS =	-version-info @EEMO_DNSKEYEX_VERSION_INFO@ @PTHREAD_LIBS@
