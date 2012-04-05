# $Id$

MAINTAINERCLEANFILES =	$(srcdir)/Makefile.in

sbin_PROGRAMS = 	eemo

eemo_SOURCES =		dns_handler.c \
			dns_handler.h \
			dns_parser.c \
			dns_parser.h \
			dns_types.h \
			eemo.h \
			eemo_api.h \
			eemo_config.c \
			eemo_config.h \
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
			utlist.h

eemo_LDADD =		-lpcap -lconfig

SUBDIRS =		plugins
