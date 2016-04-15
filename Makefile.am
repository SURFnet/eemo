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

# Top level
bin_PROGRAMS =
sbin_PROGRAMS =
noinst_PROGRAMS =
noinst_SCRIPTS =
dist_noinst_SCRIPTS =
lib_LTLIBRARIES =
bin_SCRIPTS =
sbin_SCRIPTS =
EXTRA_DIST =
doc_DATA =

# Base distribution
EXTRA_DIST += 		AUTHORS \
			ChangeLog \
			LICENSE \
			NEWS \
			README.md

doc_DATA +=		AUTHORS \
			ChangeLog \
			LICENSE \
			NEWS \
			README.md

noinst_SCRIPTS +=	eemo.spec \
			eemo.rc \
			eemo_mux.rc \
			eemo_sensor.rc

dist_noinst_SCRIPTS +=	eemo.spec.in \
			eemo.rc \
			eemo_mux.rc \
			eemo_sensor.rc 

eemo.spec: eemo.spec.in
	sed -e 's/_EEMO_VERSION_/@VERSION@/g' < $(srcdir)/eemo.spec.in > eemo.spec

# Configuration
EXTRA_DIST +=		config/sample-eemo.conf \
			config/sample-eemo_mux.conf \
			config/sample-eemo_sensor.conf

doc_DATA +=		config/sample-eemo.conf \
			config/sample-eemo_mux.conf \
			config/sample-eemo_sensor.conf

# Scripts
EXTRA_DIST +=		scripts/eemo_generate_cert.sh \
			scripts/eemo.init \
			scripts/eemo_mux.init \
			scripts/eemo_sensor.init

bin_SCRIPTS +=		scripts/eemo_generate_cert.sh

doc_DATA +=		scripts/eemo.init \
			scripts/eemo_mux.init \
			scripts/eemo_sensor.init

# Main eemo sources
sbin_PROGRAMS += 		sbin/eemo \
				sbin/eemo_mux \
				sbin/eemo_sensor

sbin_eemo_CFLAGS =		@LIBCONFIG_CFLAGS@ @PTHREAD_CFLAGS@ @OPENSSL_CFLAGS@ @ZLIB_CFLAGS@ -Isrc

if WITH_SQLITE3
sbin_eemo_CFLAGS +=		@SQLITE3_CFLAGS@
endif

sbin_eemo_SOURCES =		src/dns_handler.c \
				src/dns_handler.h \
				src/dns_parser.c \
				src/dns_parser.h \
				src/dns_types.h \
				src/eemo.h \
				src/eemo_api.h \
				src/eemo_config.c \
				src/eemo_config.h \
				src/eemo_fio.c \
				src/eemo_fio.h \
				src/eemo_modules.c \
				src/eemo_modules.h \
				src/eemo_handlefactory.c \
				src/eemo_handlefactory.h \
				src/eemo_log.c \
				src/eemo_log.h \
				src/eemo_main.c \
				src/eemo_packet.c \
				src/eemo_packet.h \
				src/eemo_capture.c \
				src/eemo_capture.h \
				src/ether_capture.c \
				src/ether_capture.h \
				src/file_capture.c \
				src/file_capture.h \
				src/mux_capture.c \
				src/mux_capture.h \
				src/eemo_mux_proto.h \
				src/eemo_mux_cmdxfer.c \
				src/eemo_mux_cmdxfer.h \
				src/eemo_tlscomm.c \
				src/eemo_tlscomm.h \
				src/eemo_tlsutil.c \
				src/eemo_tlsutil.h \
				src/mt_openssl.c \
				src/mt_openssl.h \
				src/raw_handler.c \
				src/raw_handler.h \
				src/ether_handler.c \
				src/ether_handler.h \
				src/icmp_handler.c \
				src/icmp_handler.h \
				src/ifaddr_lookup.c \
				src/ifaddr_lookup.h \
				src/ip_handler.c \
				src/ip_handler.h \
				src/ip_reassemble.c \
				src/ip_reassemble.h \
				src/ip_metadata.c \
				src/ip_metadata.h \
				src/tcp_handler.c \
				src/tcp_handler.h \
				src/udp_handler.c \
				src/udp_handler.h \
				src/cidrmatch.c \
				src/cidrmatch.h \
				src/utlist.h \
				src/uthash.h \
				src/hyperloglogpp.c \
				src/hyperloglogpp.h \
				src/endian_compat.h

sbin_eemo_LDADD =		-lpcap @LIBCONFIG_LIBS@ @PTHREAD_LIBS@ @OPENSSL_LIBS@ @ZLIB_LIBS@ -lm

if WITH_SQLITE3
sbin_eemo_LDADD +=		@SQLITE3_LDFLAGS@
endif

sbin_eemo_mux_CFLAGS =	 	@LIBCONFIG_CFLAGS@ @OPENSSL_CFLAGS@ @PTHREAD_CFLAGS@ -Isrc

sbin_eemo_mux_SOURCES =		src/eemo_mux_main.c \
				src/eemo_config.c \
				src/eemo_config.h \
				src/eemo_log.c \
				src/eemo_log.h \
				src/eemo_mux_muxer.c \
				src/eemo_mux_muxer.h \
				src/eemo_mux_proto.h \
				src/eemo_tlscomm.c \
				src/eemo_tlscomm.h \
				src/eemo_tlsutil.c \
				src/eemo_tlsutil.h \
				src/eemo_mux_cmdxfer.c \
				src/eemo_mux_cmdxfer.h \
				src/eemo_mux_queue.c \
				src/eemo_mux_queue.h \
				src/mt_openssl.c \
				src/mt_openssl.h \
				src/endian_compat.h

sbin_eemo_mux_LDADD =		@LIBCONFIG_LIBS@ @OPENSSL_LIBS@ @PTHREAD_LIBS@

sbin_eemo_sensor_CFLAGS =	@LIBCONFIG_CFLAGS@ @OPENSSL_CFLAGS@ @PTHREAD_CFLAGS@ -Isrc

sbin_eemo_sensor_SOURCES =	src/eemo_sensor_main.c \
				src/eemo_sensor_sensor.c \
				src/eemo_sensor_sensor.h \
				src/eemo_mux_queue.c \
				src/eemo_mux_queue.h \
				src/eemo_mux_proto.h \
				src/eemo_config.c \
				src/eemo_config.h \
				src/eemo_log.c \
				src/eemo_log.h \
				src/eemo_tlsutil.c \
				src/eemo_tlsutil.h \
				src/eemo_tlscomm.c \
				src/eemo_tlscomm.h \
				src/eemo_mux_cmdxfer.c \
				src/eemo_mux_cmdxfer.h \
				src/mt_openssl.c \
				src/mt_openssl.h \
				src/endian_compat.h

sbin_eemo_sensor_LDADD =	-lpcap @LIBCONFIG_LIBS@ @OPENSSL_LIBS@ @PTHREAD_LIBS@

##############################################################################
# PLUGINS BELOW                                                              #
##############################################################################

# auth_vs_client plugin
lib_LTLIBRARIES += 			lib/libeemo_auth_vs_client.la

lib_libeemo_auth_vs_client_la_CFLAGS =	@PTHREAD_CFLAGS@ -Isrc -Isrc/plugins -Isrc/plugins/auth_vs_client @LIBCONFIG_CFLAGS@

lib_libeemo_auth_vs_client_la_SOURCES =	src/plugins/auth_vs_client/auth_vs_client.c \
					src/plugins/eemo_plugin_log.c \
					src/plugins/eemo_plugin_log.h

lib_libeemo_auth_vs_client_la_LDFLAGS =	-version-info @EEMO_AUTH_VS_CLIENT_VERSION_INFO@ @PTHREAD_LIBS@

# demo plugin
lib_LTLIBRARIES += 			lib/libeemo_demo.la

lib_libeemo_demo_la_CFLAGS =		-Isrc -Isrc/plugins -Isrc/plugins/demo @LIBCONFIG_CFLAGS@

lib_libeemo_demo_la_SOURCES =		src/plugins/demo/eemo_demo_entry.c \
					src/plugins/eemo_plugin_log.c \
					src/plugins/eemo_plugin_log.h

lib_libeemo_demo_la_LDFLAGS =		-version-info @EEMO_DEMO_VERSION_INFO@

# dnsdistribution plugin
lib_LTLIBRARIES += 			lib/libeemo_dnsdistribution.la

lib_libeemo_dnsdistribution_la_CFLAGS =	-Isrc -Isrc/plugins -Isrc/plugins/dnsdistribution @LIBCONFIG_CFLAGS@

lib_libeemo_dnsdistribution_la_SOURCES =src/plugins/dnsdistribution/eemo_dnsdistribution_entry.c \
					src/plugins/dnsdistribution/eemo_dnsdistribution_stats.c \
					src/plugins/dnsdistribution/eemo_dnsdistribution_stats.h \
					src/plugins/eemo_plugin_log.c \
					src/plugins/eemo_plugin_log.h

lib_libeemo_dnsdistribution_la_LDFLAGS =-version-info @EEMO_DNSSTATS_VERSION_INFO@

# dnskeyex plugin
lib_LTLIBRARIES += 			lib/libeemo_dnskeyex.la

lib_libeemo_dnskeyex_la_CFLAGS =	@PTHREAD_CFLAGS@ -Isrc -Isrc/plugins -Isrc/plugins/dnskeyex @LIBCONFIG_CFLAGS@

lib_libeemo_dnskeyex_la_SOURCES =	src/plugins/dnskeyex/dnskeyex.c \
					src/plugins/eemo_plugin_log.c \
					src/plugins/eemo_plugin_log.h

lib_libeemo_dnskeyex_la_LDFLAGS =	-version-info @EEMO_DNSKEYEX_VERSION_INFO@ @PTHREAD_LIBS@

# dnsqfw plugin
lib_LTLIBRARIES +=			lib/libeemo_dnsqfw.la

lib_libeemo_dnsqfw_la_CFLAGS =		-Isrc -Isrc/plugins -Isrc/plugins/dnsqfw @LIBCONFIG_CFLAGS@

lib_libeemo_dnsqfw_la_SOURCES =		src/plugins/dnsqfw/eemo_dnsqfw_entry.c \
					src/plugins/dnsqfw/eemo_dnsqfw_aggr.c \
					src/plugins/dnsqfw/eemo_dnsqfw_aggr.h \
					src/plugins/eemo_plugin_log.c \
					src/plugins/eemo_plugin_log.h

lib_libeemo_dnsqfw_la_LDFLAGS =		-version-info @EEMO_DNSQFW_VERSION_INFO@

noinst_PROGRAMS +=			bin/dnsqfw_testsink

bin_dnsqfw_testsink_CFLAGS =		-Isrc -Isrc/plugins -Isrc/plugins/dnsqfw -Isrc/plugins/dnsqfw/testsink -Isrc/plugins/icmpfragmon

bin_dnsqfw_testsink_SOURCES =		src/plugins/dnsqfw/testsink/dnsqfw_sink_main.c

# dnsqrlog plugin
lib_LTLIBRARIES +=			lib/libeemo_dnsqrlog.la

lib_libeemo_dnsqrlog_la_CFLAGS =	-Isrc -Isrc/plugins -Isrc/plugins/dnsqrlog @LIBCONFIG_CFLAGS@

lib_libeemo_dnsqrlog_la_SOURCES =	src/plugins/dnsqrlog/eemo_dnsqrlog_entry.c \
					src/plugins/dnsqrlog/eemo_dnsqrlog.c \
					src/plugins/dnsqrlog/eemo_dnsqrlog.h \
					src/plugins/eemo_plugin_log.c \
					src/plugins/eemo_plugin_log.h

lib_libeemo_dnsqrlog_la_LDFLAGS =	-version-info @EEMO_DNSQFW_VERSION_INFO@

# dnssensorfw plugin
lib_LTLIBRARIES +=			lib/libeemo_dnssensorfw.la

lib_libeemo_dnssensorfw_la_CFLAGS =	-Isrc -Isrc/plugins -Isrc/plugins/dnssensorfw @PTHREAD_CFLAGS@ @LIBCONFIG_CFLAGS@

lib_libeemo_dnssensorfw_la_SOURCES =	src/plugins/dnssensorfw/eemo_dnssensorfw_entry.c \
					src/plugins/dnssensorfw/eemo_dnssensorfw_ipfw.c \
					src/plugins/dnssensorfw/eemo_dnssensorfw_ipfw.h \
					src/plugins/eemo_plugin_log.c \
					src/plugins/eemo_plugin_log.h

lib_libeemo_dnssensorfw_la_LIBADD =	@PTHREAD_LIBS@

lib_libeemo_dnssensorfw_la_LDFLAGS =	-version-info @EEMO_DNSSENSORFW_VERSION_INFO@

noinst_PROGRAMS +=			bin/dnssensorfw_testsink

bin_dnssensorfw_testsink_SOURCES =	src/plugins/dnssensorfw/testsink/dnssensor_sink.c

# dnsstats plugin
lib_LTLIBRARIES += 			lib/libeemo_dnsstats.la

lib_libeemo_dnsstats_la_CFLAGS =	-Isrc -Isrc/plugins -Isrc/plugins/dnsstats @LIBCONFIG_CFLAGS@

lib_libeemo_dnsstats_la_SOURCES =	src/plugins/dnsstats/eemo_dnsstats_entry.c \
					src/plugins/dnsstats/eemo_dnsstats_stats.c \
					src/plugins/dnsstats/eemo_dnsstats_stats.h \
					src/plugins/eemo_plugin_log.c \
					src/plugins/eemo_plugin_log.h

lib_libeemo_dnsstats_la_LDFLAGS =	-version-info @EEMO_DNSSTATS_VERSION_INFO@

EXTRA_DIST +=				src/plugins/dnsstats/cacti/dnsstats_cacti.sh \
					src/plugins/dnsstats/cacti/README-dnsstats \
					src/plugins/dnsstats/cacti/eemo_cacti_DNSSEC_queries.xml \
					src/plugins/dnsstats/cacti/eemo_cacti_IP_types.xml \
					src/plugins/dnsstats/cacti/eemo_cacti_common_queries.xml \
					src/plugins/dnsstats/cacti/eemo_cacti_protocol_types.xml \
					src/plugins/dnsstats/cacti/eemo_cacti_query_classes.xml

sbin_SCRIPTS +=				src/plugins/dnsstats/cacti/dnsstats_cacti.sh

doc_DATA +=				src/plugins/dnsstats/cacti/README-dnsstats \
					src/plugins/dnsstats/cacti/eemo_cacti_DNSSEC_queries.xml \
					src/plugins/dnsstats/cacti/eemo_cacti_IP_types.xml \
					src/plugins/dnsstats/cacti/eemo_cacti_common_queries.xml \
					src/plugins/dnsstats/cacti/eemo_cacti_protocol_types.xml \
					src/plugins/dnsstats/cacti/eemo_cacti_query_classes.xml

# dnszabbix plugin
lib_LTLIBRARIES += 			lib/libeemo_dnszabbix.la

lib_libeemo_dnszabbix_la_CFLAGS =	-Isrc -Isrc/plugins -Isrc/plugins/dnszabbix @LIBCONFIG_CFLAGS@

lib_libeemo_dnszabbix_la_SOURCES =	src/plugins/dnszabbix/eemo_dnszabbix_entry.c \
					src/plugins/dnszabbix/eemo_dnszabbix_stats.c \
					src/plugins/dnszabbix/eemo_dnszabbix_stats.h \
					src/plugins/eemo_plugin_log.c \
					src/plugins/eemo_plugin_log.h

lib_libeemo_dnszabbix_la_LDFLAGS =	-version-info @EEMO_DNSZABBIX_VERSION_INFO@

# dumppcap plugin
lib_LTLIBRARIES +=	 		lib/libeemo_dumppcap.la

lib_libeemo_dumppcap_la_CFLAGS =	-Isrc -Isrc/plugins -Isrc/plugins/dumppcap @LIBCONFIG_CFLAGS@

lib_libeemo_dumppcap_la_SOURCES =	src/plugins/dumppcap/dumppcap.c \
					src/plugins/eemo_plugin_log.c \
					src/plugins/eemo_plugin_log.h

lib_libeemo_dumppcap_la_LDFLAGS =	-version-info @EEMO_DUMPPCAP_VERSION_INFO@

# ecsmonitor plugin
lib_LTLIBRARIES += 			lib/libeemo_ecsmonitor.la

lib_libeemo_ecsmonitor_la_CFLAGS =	@PTHREAD_CFLAGS@ -Isrc -Isrc/plugins -Isrc/plugins/ecsmonitor @LIBCONFIG_CFLAGS@

lib_libeemo_ecsmonitor_la_SOURCES =	src/plugins/ecsmonitor/ecsmonitor.c \
					src/plugins/eemo_plugin_log.c \
					src/plugins/eemo_plugin_log.h

lib_libeemo_ecsmonitor_la_LDFLAGS =	-version-info @EEMO_ECSMONITOR_VERSION_INFO@ @PTHREAD_LIBS@

# icmpfragmon plugin
lib_LTLIBRARIES +=			lib/libeemo_icmpfragmon.la

lib_libeemo_icmpfragmon_la_CFLAGS =	-Isrc -Isrc/plugins -Isrc/plugins/icmpfragmon @LIBCONFIG_CFLAGS@

lib_libeemo_icmpfragmon_la_SOURCES =	src/plugins/icmpfragmon/eemo_icmpfragmon_entry.c \
					src/plugins/icmpfragmon/eemo_icmpfragmon_aggr.c \
					src/plugins/icmpfragmon/eemo_icmpfragmon_aggr.h \
					src/plugins/eemo_plugin_log.c \
					src/plugins/eemo_plugin_log.h

lib_libeemo_icmpfragmon_la_LDFLAGS =	-version-info @EEMO_ICMPFRAGMON_VERSION_INFO@

# namex plugin
lib_LTLIBRARIES +=	 		lib/libeemo_namex.la

lib_libeemo_namex_la_CFLAGS =		@PTHREAD_CFLAGS@ -Isrc -Isrc/plugins -Isrc/plugins/namex @LIBCONFIG_CFLAGS@

lib_libeemo_namex_la_SOURCES =		src/plugins/namex/namex.c \
					src/plugins/eemo_plugin_log.c \
					src/plugins/eemo_plugin_log.h

lib_libeemo_namex_la_LDFLAGS =		-version-info @EEMO_NAMEX_VERSION_INFO@ @PTHREAD_LIBS@

# nonecsmonitor
lib_LTLIBRARIES += 			lib/libeemo_nonecsmonitor.la

lib_libeemo_nonecsmonitor_la_CFLAGS =	@PTHREAD_CFLAGS@ -Isrc -Isrc/plugins -Isrc/plugins/nonecsmonitor @LIBCONFIG_CFLAGS@

lib_libeemo_nonecsmonitor_la_SOURCES =	src/plugins/nonecsmonitor/nonecsmonitor.c \
					src/plugins/eemo_plugin_log.c \
					src/plugins/eemo_plugin_log.h

lib_libeemo_nonecsmonitor_la_LDFLAGS =	-version-info @EEMO_NONECSMONITOR_VERSION_INFO@ @PTHREAD_LIBS@

# udprexmit plugin
lib_LTLIBRARIES += 			lib/libeemo_udprexmit.la

lib_libeemo_udprexmit_la_CFLAGS =	-Isrc -Isrc/plugins -Isrc/plugins/udprexmit @LIBCONFIG_CFLAGS@

lib_libeemo_udprexmit_la_SOURCES =	src/plugins/udprexmit/eemo_udprexmit.c \
					src/plugins/eemo_plugin_log.c \
					src/plugins/eemo_plugin_log.h

lib_libeemo_udprexmit_la_LDFLAGS =	-version-info @EEMO_UDPREXMIT_VERSION_INFO@

# darkscanex plugin
lib_LTLIBRARIES +=			lib/libeemo_darkscanex.la

lib_libeemo_darkscanex_la_CFLAGS =	-Isrc -Isrc/plugins -Isrc/plugins/darkscanex @LIBCONFIG_CFLAGS@ @PTHREAD_CFLAGS@

lib_libeemo_darkscanex_la_SOURCES =	src/plugins/darkscanex/darkscanex.c \
					src/plugins/eemo_plugin_log.c \
					src/plugins/eemo_plugin_log.h \
					src/uthash.h

lib_libeemo_darkscanex_la_LDFLAGS =	-version-info @EEMO_DARKSCANEX_VERSION_INFO@ @PTHREAD_LIBS@

# querypop plugin
lib_LTLIBRARIES +=			lib/libeemo_querypop.la

lib_libeemo_querypop_la_CFLAGS =	-Isrc -Isrc/plugins -Isrc/plugins/querypop @LIBCONFIG_CFLAGS@ @PTHREAD_CFLAGS@

lib_libeemo_querypop_la_SOURCES =	src/plugins/querypop/querypop.c \
					src/plugins/eemo_plugin_log.c \
					src/plugins/eemo_plugin_log.h \
					src/uthash.h

lib_libeemo_querypop_la_LDFLAGS =	-version-info @EEMO_QUERYPOP_VERSION_INFO@ @PTHREAD_LIBS@
