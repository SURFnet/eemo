# $Id$

ACLOCAL_AMFLAGS = -I m4

MAINTAINERCLEANFILES = \
        config.log config.status \
        $(srcdir)/Makefile.in \
        $(srcdir)/config.h.in $(srcdir)/config.h.in~ \
        $(srcdir)/configure \
        $(srcdir)/install-sh $(srcdir)/ltmain.sh $(srcdir)/missing \
        $(srcdir)/depcomp $(srcdir)/aclocal.m4 $(srcdir)/compile \
        $(srcdir)/config.guess $(srcdir)/config.sub \
	$(srcdir)/eemo.spec

EXTRA_DIST = 		AUTHORS \
			ChangeLog \
			LICENSE \
			NEWS \
			README

doc_DATA =		AUTHORS \
			ChangeLog \
			LICENSE \
			NEWS \
			README

noinst_SCRIPTS =	eemo.spec

dist_noinst_SCRIPTS =	eemo.spec.in

eemo.spec: eemo.spec.in
	sed -e 's/_EEMO_VERSION_/@VERSION@/g' < $(srcdir)/eemo.spec.in > eemo.spec

SUBDIRS = src config
