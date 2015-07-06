# $Id$

MAINTAINERCLEANFILES =		$(srcdir)/Makefile.in

lib_LTLIBRARIES = 		libeemo_ecsmonitor.la

libeemo_ecsmonitor_la_CFLAGS =	@PTHREAD_CFLAGS@ \
				-I$(srcdir)/.. \
				-I$(srcdir)/../.. 

libeemo_ecsmonitor_la_SOURCES =	ecsmonitor.c \
				../eemo_plugin_log.c \
				../eemo_plugin_log.h

libeemo_ecsmonitor_la_LDFLAGS =	-version-info @EEMO_ECSMONITOR_VERSION_INFO@ @PTHREAD_LIBS@
