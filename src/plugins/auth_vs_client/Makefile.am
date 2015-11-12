# $Id$

MAINTAINERCLEANFILES =			$(srcdir)/Makefile.in

lib_LTLIBRARIES = 			libeemo_auth_vs_client.la

libeemo_auth_vs_client_la_CFLAGS =	@PTHREAD_CFLAGS@ \
					-I$(srcdir)/.. \
					-I$(srcdir)/../.. 

libeemo_auth_vs_client_la_SOURCES =	auth_vs_client.c \
					../eemo_plugin_log.c \
					../eemo_plugin_log.h

libeemo_auth_vs_client_la_LDFLAGS =	-version-info @EEMO_AUTH_VS_CLIENT_VERSION_INFO@ @PTHREAD_LIBS@
