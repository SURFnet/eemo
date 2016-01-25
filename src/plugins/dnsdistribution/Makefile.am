# $Id$

MAINTAINERCLEANFILES =		$(srcdir)/Makefile.in

AM_CFLAGS =			-I$(srcdir)/.. \
				-I$(srcdir)/../.. 

lib_LTLIBRARIES = 		libeemo_dnsdistribution.la

libeemo_dnsdistribution_la_SOURCES =	eemo_dnsdistribution_entry.c \
					eemo_dnsdistribution_stats.c \
					eemo_dnsdistribution_stats.h \
					../eemo_plugin_log.c \
					../eemo_plugin_log.h

libeemo_dnsdistribution_la_LDFLAGS =	-version-info @EEMO_DNSSTATS_VERSION_INFO@
