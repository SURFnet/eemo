MAINTAINERCLEANFILES =		$(srcdir)/Makefile.in

sbin_PROGRAMS = 		eemo \
				eemo_mux \
				eemo_sensor

eemo_CFLAGS =			@LIBCONFIG_CFLAGS@ @PTHREAD_CFLAGS@ @OPENSSL_CFLAGS@

if WITH_SQLITE3
eemo_CFLAGS +=			@SQLITE3_CFLAGS@
endif

eemo_SOURCES =			dns_handler.c \
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
				eemo_capture.c \
				eemo_capture.h \
				ether_capture.c \
				ether_capture.h \
				file_capture.c \
				file_capture.h \
				mux_capture.c \
				mux_capture.h \
				eemo_mux_proto.h \
				eemo_mux_cmdxfer.c \
				eemo_mux_cmdxfer.h \
				eemo_tlscomm.c \
				eemo_tlscomm.h \
				eemo_tlsutil.c \
				eemo_tlsutil.h \
				mt_openssl.c \
				mt_openssl.h \
				raw_handler.c \
				raw_handler.h \
				ether_handler.c \
				ether_handler.h \
				icmp_handler.c \
				icmp_handler.h \
				ifaddr_lookup.c \
				ifaddr_lookup.h \
				ip_handler.c \
				ip_handler.h \
				ip_reassemble.c \
				ip_reassemble.h \
				ip_metadata.c \
				ip_metadata.h \
				tcp_handler.c \
				tcp_handler.h \
				udp_handler.c \
				udp_handler.h \
				utlist.h \
				uthash.h \
				endian_compat.h

eemo_LDADD =			-lpcap @LIBCONFIG_LIBS@ @PTHREAD_LIBS@ @OPENSSL_LIBS@

if WITH_SQLITE3
eemo_LDADD +=			@SQLITE3_LDFLAGS@
endif

eemo_mux_CFLAGS =	 	@LIBCONFIG_CFLAGS@ @OPENSSL_CFLAGS@ @PTHREAD_CFLAGS@

eemo_mux_SOURCES =		eemo_mux_main.c \
				eemo_config.c \
				eemo_config.h \
				eemo_log.c \
				eemo_log.h \
				eemo_mux_muxer.c \
				eemo_mux_muxer.h \
				eemo_mux_proto.h \
				eemo_tlscomm.c \
				eemo_tlscomm.h \
				eemo_tlsutil.c \
				eemo_tlsutil.h \
				eemo_mux_cmdxfer.c \
				eemo_mux_cmdxfer.h \
				eemo_mux_client.c \
				eemo_mux_client.h \
				mt_openssl.c \
				mt_openssl.h \
				endian_compat.h

eemo_mux_LDADD =		@LIBCONFIG_LIBS@ @OPENSSL_LIBS@ @PTHREAD_LIBS@

eemo_sensor_CFLAGS =		@LIBCONFIG_CFLAGS@ @OPENSSL_CFLAGS@ @PTHREAD_CFLAGS@

eemo_sensor_SOURCES =		eemo_sensor_main.c \
				eemo_sensor_sensor.c \
				eemo_sensor_sensor.h \
				eemo_mux_proto.h \
				eemo_config.c \
				eemo_config.h \
				eemo_log.c \
				eemo_log.h \
				eemo_tlsutil.c \
				eemo_tlsutil.h \
				eemo_tlscomm.c \
				eemo_tlscomm.h \
				eemo_mux_cmdxfer.c \
				eemo_mux_cmdxfer.h \
				mt_openssl.c \
				mt_openssl.h \
				endian_compat.h

eemo_sensor_LDADD =		-lpcap @LIBCONFIG_LIBS@ @OPENSSL_LIBS@ @PTHREAD_LIBS@

SUBDIRS =			plugins
