# $Id$

MAINTAINERCLEANFILES =			$(srcdir)/Makefile.in

AM_CFLAGS =				-I$(srcdir)/.. \
					-I$(srcdir)/../.. \
					@PTHREAD_CFLAGS@

lib_LTLIBRARIES =			libeemo_dnssensorfw.la

libeemo_dnssensorfw_la_SOURCES =	eemo_dnssensorfw_entry.c \
					eemo_dnssensorfw_ipfw.c \
					eemo_dnssensorfw_ipfw.h \
					../eemo_plugin_log.c \
					../eemo_plugin_log.h

libeemo_dnssensorfw_la_LIBADD =		@PTHREAD_LIBS@

libeemo_dnssensorfw_la_LDFLAGS =	-version-info @EEMO_DNSSENSORFW_VERSION_INFO@

SUBDIRS =				testsink

