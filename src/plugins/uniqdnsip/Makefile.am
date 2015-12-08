# $Id$

MAINTAINERCLEANFILES =		$(srcdir)/Makefile.in

lib_LTLIBRARIES = 		libeemo_uniqdnsip.la

libeemo_uniqdnsip_la_CFLAGS =	@PTHREAD_CFLAGS@ \
				-I$(srcdir)/.. \
				-I$(srcdir)/../.. 

libeemo_uniqdnsip_la_SOURCES =	uniqdnsip.c \
				../eemo_plugin_log.c \
				../eemo_plugin_log.h

libeemo_uniqdnsip_la_LDFLAGS =	-version-info @EEMO_UNIQDNSIP_VERSION_INFO@ @PTHREAD_LIBS@
