# $Id$

MAINTAINERCLEANFILES =		$(srcdir)/Makefile.in

AM_CFLAGS =			-I$(srcdir)/.. \
				-I$(srcdir)/../..

lib_LTLIBRARIES =		libeemo_dnsqfw.la

libeemo_dnsqfw_la_SOURCES =	eemo_dnsqfw_entry.c \
				eemo_dnsqfw_aggr.c \
				eemo_dnsqfw_aggr.h \
				../eemo_plugin_log.c \
				../eemo_plugin_log.h

libeemo_dnsqfw_la_LDFLAGS =	-version-info @EEMO_DNSQFW_VERSION_INFO@

SUBDIRS = testsink
