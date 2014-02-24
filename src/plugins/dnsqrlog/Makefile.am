# $Id$

MAINTAINERCLEANFILES =		$(srcdir)/Makefile.in

AM_CFLAGS =			-I$(srcdir)/.. \
				-I$(srcdir)/../..

lib_LTLIBRARIES =		libeemo_dnsqrlog.la

libeemo_dnsqrlog_la_SOURCES =	eemo_dnsqrlog_entry.c \
				eemo_dnsqrlog.c \
				eemo_dnsqrlog.h \
				../eemo_plugin_log.c \
				../eemo_plugin_log.h

libeemo_dnsqrlog_la_LDFLAGS =	-version-info @EEMO_DNSQFW_VERSION_INFO@
