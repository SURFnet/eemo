# $Id$

MAINTAINERCLEANFILES =			$(srcdir)/Makefile.in

lib_LTLIBRARIES = 			libeemo_nonecsmonitor.la

libeemo_nonecsmonitor_la_CFLAGS =	@PTHREAD_CFLAGS@ \
					-I$(srcdir)/.. \
					-I$(srcdir)/../.. 

libeemo_nonecsmonitor_la_SOURCES =	nonecsmonitor.c \
					../eemo_plugin_log.c \
					../eemo_plugin_log.h

libeemo_nonecsmonitor_la_LDFLAGS =	-version-info @EEMO_NONECSMONITOR_VERSION_INFO@ @PTHREAD_LIBS@
