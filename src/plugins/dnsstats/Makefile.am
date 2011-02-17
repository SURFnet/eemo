# $Id$

MAINTAINERCLEANFILES =		$(srcdir)/Makefile.in

AM_CFLAGS =			-I$(srcdir)/.. \
				-I$(srcdir)/../..

lib_LTLIBRARIES = 		libeemo_dnsstats.la

libeemo_dnsstats_la_SOURCES =	eemo_dnsstats_entry.c

libeemo_dnsstats_la_LIBADD =	-lconfig

libeemo_dnsstats_la_LDFLAGS =	-version-info @EEMO_DNSSTATS_VERSION_INFO@
