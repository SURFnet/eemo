# $Id$

MAINTAINERCLEANFILES =	$(srcdir)/Makefile.in

sbin_PROGRAMS = 	eemo \
			eemo_mux

eemo_CFLAGS =		@LIBCONFIG_CFLAGS@

eemo_SOURCES =		dns_handler.c \
			dns_handler.h \
			dns_parser.c \
			dns_parser.h \
			dns_types.h \
			eemo.h \
			eemo_api.h \
			eemo_config.c \
			eemo_config.h \
			eemo_modules.c \
			eemo_modules.h \
			eemo_handlefactory.c \
			eemo_handlefactory.h \
			eemo_log.c \
			eemo_log.h \
			eemo_main.c \
			eemo_packet.c \
			eemo_packet.h \
			ether_capture.c \
			ether_capture.h \
			ether_handler.c \
			ether_handler.h \
			icmp_handler.c \
			icmp_handler.h \
			ifaddr_lookup.c \
			ifaddr_lookup.h \
			ip_handler.c \
			ip_handler.h \
			tcp_handler.c \
			tcp_handler.h \
			udp_handler.c \
			udp_handler.h \
			utlist.h \
			uthash.h

eemo_LDADD =		-lpcap @LIBCONFIG_LIBS@

eemo_mux_CFLAGS = 	@LIBCONFIG_CFLAGS@ @OPENSSL_CFLAGS@

eemo_mux_SOURCES =	eemo_mux_main.c \
			eemo_config.c \
			eemo_config.h \
			eemo_log.c \
			eemo_log.h \
			eemo_mux_muxer.c \
			eemo_mux_muxer.h

eemo_mux_LDADD =	-lpcap @LIBCONFIG_LIBS@ @OPENSSL_LIBS@

SUBDIRS =		plugins
