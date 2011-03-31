# $Id$

MAINTAINERCLEANFILES =			$(srcdir)/Makefile.in

AM_CFLAGS =				-I$(srcdir)/.. \
					-I$(srcdir)/../..

lib_LTLIBRARIES =			libeemo_icmpfragmon.la

libeemo_icmpfragmon_la_SOURCES =	eemo_icmpfragmon_entry.c \
					eemo_icmpfragmon_aggr.c \
					eemo_icmpfragmon_aggr.h \
					../eemo_plugin_log.c \
					../eemo_plugin_log.h

libeemo_icmpfragmon_la_LDFLAGS =	-version-info @EEMO_ICMPFRAGMON_VERSION_INFO@
