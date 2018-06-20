################################################################################
# Version information                                                          #
################################################################################

# Program version

define([EEMO_VERSION_MAJOR], [0])
define([EEMO_VERSION_MINOR], [5])
define([EEMO_VERSION_BUILDREV], esyscmd([sh -c "git rev-list --count HEAD|tr -d '\n'"]))
define([PACKAGE_SUFFIX], [])

# Plugin library versions

# Version guidelines
# Interface added/removed/changed:   <PLUGIN>_VERSION_CURRENT++, <PLUGIN>_VERSION_REVISION=0
# Code changed:                      <PLUGIN>_VERSION_REVISION++
# Interface added:                   <PLUGIN>_VERSION_AGE++
# Interface removed:                 <PLUGIN>_VERSION_AGE=0

# Demo plugin
define([EEMO_DEMO_CURRENT], [1])
define([EEMO_DEMO_REVISION], [0])
define([EEMO_DEMO_AGE], [0])

# DNS statistics plugin
define([EEMO_DNSSTATS_CURRENT], [1])
define([EEMO_DNSSTATS_REVISION], [0])
define([EEMO_DNSSTATS_AGE], [0])

# DNSSEC validating resolver monitoring
define([EEMO_DNSQFW_CURRENT], [1])
define([EEMO_DNSQFW_REVISION], [0])
define([EEMO_DNSQFW_AGE], [0])

# ICMP fragment reassembly timeout monitoring
define([EEMO_ICMPFRAGMON_CURRENT], [1])
define([EEMO_ICMPFRAGMON_REVISION], [0])
define([EEMO_ICMPFRAGMON_AGE], [0])

# IP/ICMP to DNS sensor forwarder
define([EEMO_DNSSENSORFW_CURRENT], [1])
define([EEMO_DNSSENSORFW_REVISION], [0])
define([EEMO_DNSSENSORFW_AGE], [0])

# UDP retransmission plugin
define([EEMO_UDPREXMIT_CURRENT], [1])
define([EEMO_UDPREXMIT_REVISION], [0])
define([EEMO_UDPREXMIT_AGE], [0])

# EDNS0 client subnet monitoring plugin
define([EEMO_ECSMONITOR_CURRENT], [1])
define([EEMO_ECSMONITOR_REVISION], [0])
define([EEMO_ECSMONITOR_AGE], [0])

# DNS statistics module for Zabbix
define([EEMO_DNSZABBIX_CURRENT], [1])
define([EEMO_DNSZABBIX_REVISION], [0])
define([EEMO_DNSZABBIX_AGE], [0])

# PCAP dumping
define([EEMO_DUMPPCAP_CURRENT], [1])
define([EEMO_DUMPPCAP_REVISION], [0])
define([EEMO_DUMPPCAP_AGE], [0])

# Extract DNSKEYs from authoritative answers
define([EEMO_DNSKEYEX_CURRENT], [1])
define([EEMO_DNSKEYEX_REVISION], [0])
define([EEMO_DNSKEYEX_AGE], [0])

# Extract answer names from DNS answers
define([EEMO_NAMEX_CURRENT], [1])
define([EEMO_NAMEX_REVISION], [0])
define([EEMO_NAMEX_AGE], [0])

# Monitor queries for a specific name
define([EEMO_AUTH_VS_CLIENT_CURRENT], [1])
define([EEMO_AUTH_VS_CLIENT_REVISION], [0])
define([EEMO_AUTH_VS_CLIENT_AGE], [0])

# Non-EDNS0 client subnet monitoring plugin
define([EEMO_NONECSMONITOR_CURRENT], [1])
define([EEMO_NONECSMONITOR_REVISION], [0])
define([EEMO_NONECSMONITOR_AGE], [0])

# Plugin that collects statistics on unique DNS clients seen
define([EEMO_UNIQDNSIP_CURRENT], [1])
define([EEMO_UNIQDNSIP_REVISION], [0])
define([EEMO_UNIQDNSIP_AGE], [0])

# Plugin that extracts DNS-scanning queries from PCAPs
define([EEMO_DARKSCANEX_CURRENT], [1])
define([EEMO_DARKSCANEX_REVISION], [0])
define([EEMO_DARKSCANEX_AGE], [0])

# Plugin that measures query and client populations
define([EEMO_QUERYPOP_CURRENT], [1])
define([EEMO_QUERYPOP_REVISION], [0])
define([EEMO_QUERYPOP_AGE], [0])

# Plugin that measures SLD query popularity
define([EEMO_SLDPOP_CURRENT], [1])
define([EEMO_SLDPOP_REVISION], [0])
define([EEMO_SLDPOP_AGE], [0])

# Plugin for darknet monitoring
define([EEMO_DARKMON_CURRENT], [1])
define([EEMO_DARKMON_REVISION], [0])
define([EEMO_DARKMON_AGE], [0])

# Plugin for compact CSV DNS query logging
define([EEMO_CSVQLOG_CURRENT], [1])
define([EEMO_CSVQLOG_REVISION], [0])
define([EEMO_CSVQLOG_AGE], [0])

# Plugin for compact CSV DNS query logging
define([EEMO_QRSIZEDIST_CURRENT], [1])
define([EEMO_QRSIZEDIST_REVISION], [0])
define([EEMO_QRSIZEDIST_AGE], [0])

# Plugin for DNS de-NAT project
define([EEMO_DNSDENATEX_CURRENT], [1])
define([EEMO_DNSDENATEX_REVISION], [0])
define([EEMO_DNSDENATEX_AGE], [0])

# Plugin for logging query src IPs with high-precision timestamps
define([EEMO_QSRCIPS_CURRENT], [1])
define([EEMO_QSRCIPS_REVISION], [0])
define([EEMO_QSRCIPS_AGE], [0])

# Plugin for logging query src IPs and AS
define([EEMO_QANDASLOG_CURRENT], [1])
define([EEMO_QANDASLOG_REVISION], [0])
define([EEMO_QANDASLOG_AGE], [0])

# Plugin for DNS statistics collection for InfluxDB
define([EEMO_DNSINFLUX_CURRENT], [1])
define([EEMO_DNSINFLUX_REVISION], [0])
define([EEMO_DNSINFLUX_AGE], [0])

# Plugin for dnstap output to a UNIX domain socket
define([EEMO_DNSTAPOUT_CURRENT], [1])
define([EEMO_DNSTAPOUT_REVISION], [0])
define([EEMO_DNSTAPOUT_AGE], [0])

################################################################################
# Configuration functions                                                      #
################################################################################

# Init
AC_PREREQ(2.61)
AC_INIT([eemo],[EEMO_VERSION_MAJOR.EEMO_VERSION_MINOR.EEMO_VERSION_BUILDREV[]PACKAGE_SUFFIX])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE(foreign subdir-objects)
ACX_PREFIXHACK

# Variable substitutions
EEMO_DNSSTATS_VERSION_INFO="EEMO_DNSSTATS_CURRENT:EEMO_DNSSTATS_REVISION:EEMO_DNSSTATS_AGE"
AC_SUBST(EEMO_DNSSTATS_VERSION_INFO)
EEMO_DEMO_VERSION_INFO="EEMO_DEMO_CURRENT:EEMO_DEMO_REVISION:EEMO_DEMO_AGE"
AC_SUBST(EEMO_DEMO_VERSION_INFO)
EEMO_DNSQFW_VERSION_INFO="EEMO_DNSQFW_CURRENT:EEMO_DNSQFW_REVISION:EEMO_DNSQFW_AGE"
AC_SUBST(EEMO_DNSQFW_VERSION_INFO)
EEMO_ICMPFRAGMON_VERSION_INFO="EEMO_ICMPFRAGMON_CURRENT:EEMO_ICMPFRAGMON_REVISION:EEMO_ICMPFRAGMON_AGE"
AC_SUBST(EEMO_ICMPFRAGMON_VERSION_INFO)
EEMO_DNSSENSORFW_VERSION_INFO="EEMO_DNSSENSORFW_CURRENT:EEMO_DNSSENSORFW_REVISION:EEMO_DNSSENSORFW_AGE"
AC_SUBST(EEMO_DNSSENSORFW_VERSION_INFO)
EEMO_UDPREXMIT_VERSION_INFO="EEMO_UDPREXMIT_CURRENT:EEMO_UDPREXMIT_REVISION:EEMO_UDPREXMIT_AGE"
AC_SUBST(EEMO_UDPREXMIT_VERSION_INFO)
EEMO_ECSMONITOR_VERSION_INFO="EEMO_ECSMONITOR_CURRENT:EEMO_ECSMONITOR_REVISION:EEMO_ECSMONITOR_AGE"
AC_SUBST(EEMO_ECSMONITOR_VERSION_INFO)
EEMO_DNSZABBIX_VERSION_INFO="EEMO_DNSZABBIX_CURRENT:EEMO_DNSZABBIX_REVISION:EEMO_DNSZABBIX_AGE"
AC_SUBST(EEMO_DNSZABBIX_VERSION_INFO)
EEMO_DUMPPCAP_VERSION_INFO="EEMO_DUMPPCAP_CURRENT:EEMO_DUMPPCAP_REVISION:EEMO_DUMPPCAP_AGE"
AC_SUBST(EEMO_DUMPPCAP_VERSION_INFO)
EEMO_DNSKEYEX_VERSION_INFO="EEMO_DNSKEYEX_CURRENT:EEMO_DNSKEYEX_REVISION:EEMO_DNSKEYEX_AGE"
AC_SUBST(EEMO_DNSKEYEX_VERSION_INFO)
EEMO_NAMEX_VERSION_INFO="EEMO_NAMEX_CURRENT:EEMO_NAMEX_REVISION:EEMO_NAMEX_AGE"
AC_SUBST(EEMO_NAMEX_VERSION_INFO)
EEMO_AUTH_VS_CLIENT_VERSION_INFO="EEMO_AUTH_VS_CLIENT_CURRENT:EEMO_AUTH_VS_CLIENT_REVISION:EEMO_AUTH_VS_CLIENT_AGE"
AC_SUBST(EEMO_AUTH_VS_CLIENT_VERSION_INFO)
EEMO_NONECSMONITOR_VERSION_INFO="EEMO_NONECSMONITOR_CURRENT:EEMO_NONECSMONITOR_REVISION:EEMO_NONECSMONITOR_AGE"
AC_SUBST(EEMO_NONECSMONITOR_VERSION_INFO)
EEMO_UNIQDNSIP_VERSION_INFO="EEMO_UNIQDNSIP_CURRENT:EEMO_UNIQDNSIP_REVISION:EEMO_UNIQDNSIP_AGE"
AC_SUBST(EEMO_UNIQDNSIP_VERSION_INFO)
EEMO_DARKSCANEX_VERSION_INFO="EEMO_DARKSCANEX_CURRENT:EEMO_DARKSCANEX_REVISION:EEMO_DARKSCANEX_AGE"
AC_SUBST(EEMO_DARKSCANEX_VERSION_INFO)
EEMO_QUERYPOP_VERSION_INFO="EEMO_QUERYPOP_CURRENT:EEMO_QUERYPOP_REVISION:EEMO_QUERYPOP_AGE"
AC_SUBST(EEMO_QUERYPOP_VERSION_INFO)
EEMO_SLDPOP_VERSION_INFO="EEMO_SLDPOP_CURRENT:EEMO_SLDPOP_REVISION:EEMO_SLDPOP_AGE"
AC_SUBST(EEMO_SLDPOP_VERSION_INFO)
EEMO_DARKMON_VERSION_INFO="EEMO_DARKMON_CURRENT:EEMO_DARKMON_REVISION:EEMO_DARKMON_AGE"
AC_SUBST(EEMO_DARKMON_VERSION_INFO)
EEMO_CSVQLOG_VERSION_INFO="EEMO_CSVQLOG_CURRENT:EEMO_CSVQLOG_REVISION:EEMO_CSVQLOG_AGE"
AC_SUBST(EEMO_CSVQLOG_VERSION_INFO)
EEMO_QRSIZEDIST_VERSION_INFO="EEMO_QRSIZEDIST_CURRENT:EEMO_QRSIZEDIST_REVISION:EEMO_QRSIZEDIST_AGE"
AC_SUBST(EEMO_QRSIZEDIST_VERSION_INFO)
EEMO_DNSDENATEX_VERSION_INFO="EEMO_DNSDENATEX_CURRENT:EEMO_DNSDENATEX_REVISION:EEMO_DNSDENATEX_AGE"
AC_SUBST(EEMO_DNSDENATEX_VERSION_INFO)
EEMO_QSRCIPS_VERSION_INFO="EEMO_QSRCIPS_CURRENT:EEMO_QSRCIPS_REVISION:EEMO_QSRCIPS_AGE"
AC_SUBST(EEMO_QSRCIPS_VERSION_INFO)
EEMO_QANDASLOG_VERSION_INFO="EEMO_QANDASLOG_CURRENT:EEMO_QANDASLOG_REVISION:EEMO_QANDASLOG_AGE"
AC_SUBST(EEMO_QANDASLOG_VERSION_INFO)
EEMO_DNSINFLUX_VERSION_INFO="EEMO_DNSINFLUX_CURRENT:EEMO_DNSINFLUX_REVISION:EEMO_DNSINFLUX_AGE"
AC_SUBST(EEMO_DNSINFLUX_VERSION_INFO)
EEMO_DNSTAPOUT_VERSION_INFO="EEMO_DNSTAPOUT_CURRENT:EEMO_DNSTAPOUT_REVISION:EEMO_DNSTAPOUT_AGE"
AC_SUBST(EEMO_DNSTAPOUT_VERSION_INFO)

# Checks for compilers and other programs
AC_PROG_CC_C99
AC_PROG_INSTALL

# Compiler flags
ACX_PEDANTIC
ACX_STRICT

# Libtool settings
AC_DISABLE_STATIC
AC_PROG_LIBTOOL

# Log level
AC_ARG_WITH(
	[loglevel],
	[AS_HELP_STRING([--with-loglevel=INT],[The log level. 0=No log 1=Error 2=Warning 3=Info 4=Debug (default INT=3)])],
	[EEMO_LOGLEVEL="$withval"],
	[EEMO_LOGLEVEL=3]
)

# Check for libraries
ACX_DLOPEN
ACX_PCAP
PKG_CHECK_MODULES([LIBCONFIG], [libconfig >= 1.3.2],, AC_MSG_ERROR([libconfig 1.3.2 or newer not found]))
ACX_PTHREAD
PKG_CHECK_MODULES([OPENSSL], [openssl >= 1.0.1],, AC_MSG_ERROR([OpenSSL 1.0.1 or newer not found]))
PKG_CHECK_MODULES([ZLIB], [zlib >= 0.2.0],, AC_MSG_ERROR([zlib 1.2.8 or newer not found]))
PKG_CHECK_MODULES([LIBARCHIVE], [libarchive >= 3.0.0],, AC_MSG_ERROR([libarchive 3.0.0 or newer not found]))
PKG_CHECK_MODULES([LIBPROTOBUFC], [libprotobuf-c >= 1.2.1],[
	PKG_CHECK_MODULES([FSTRM], [libfstrm >= 0.2.0],, AC_MSG_ERROR([libfstrm 0.2.0 required to build the dnstap output plugin]))
	AC_CHECK_PROG([PROTOCC], protoc-c, yes, no)
	if test $PROTOCC = no ; then
		AC_MSG_ERROR([protoc-c is required to build the dnstap output plugin])
	fi
	AM_CONDITIONAL([HAVE_DNSTAP], true)
], [
	AC_MSG_WARN([libprotobuf-c 1.2.1 or newer not found -- skipping build of dnstap plugin])
])
AX_LIB_SQLITE3(3.7.0)

AM_COND_IF([WITH_SQLITE3], ,AC_MSG_WARN([Not building IP-to-AS or GeoIP support since these depend on SQLite!]))

# Check for headers
AC_CHECK_HEADERS([pcap.h])
AC_CHECK_HEADERS([arpa/inet.h])
AC_CHECK_HEADERS([netinet/in.h])
AC_CHECK_HEADERS([netdb.h])
AC_CHECK_HEADERS([ifaddrs.h])
AC_CHECK_HEADERS([sys/socket.h])
AC_CHECK_HEADERS([unistd.h])
AC_CHECK_HEADERS([syslog.h])
AC_CHECK_HEADERS([signal.h])
AC_HEADER_STDC

# Check for functions
AC_FUNC_MEMCMP
AC_CHECK_FUNCS(ntohs ntohl,,AC_MSG_ERROR([ntohs and ntohl are required to build eemo]))
AC_CHECK_FUNCS(getnameinfo,,AC_MSG_ERROR([getnameinfo is required to build eemo]))
AC_CHECK_FUNCS(getifaddrs,,AC_MSG_ERROR([getifaddrs is required to build eemo]))
AC_CHECK_FUNCS(syslog,,AC_MSG_ERROR([syslog is required to build eemo]))

# Define default paths
full_sysconfdir=`eval eval eval eval eval echo "${sysconfdir}" | sed "s#NONE#${prefix}#" | sed "s#NONE#${ac_default_prefix}#"`
full_localstatedir=`eval eval eval eval eval echo "${localstatedir}" | sed "s#NONE#${prefix}#" | sed "s#NONE#${ac_default_prefix}#"`
full_libdir=`eval eval eval eval eval echo "${libdir}" | sed "s#NONE#${prefix}#" | sed "s#NONE#${ac_default_prefix}#"`
default_eemo_conf="`eval echo ${full_sysconfdir} | sed s,NONE,$ac_default_prefix,g`/eemo.conf"
default_pid_file="`eval echo ${full_localstatedir} | sed s,NONE,$ac_default_prefix,g`/run/eemo.pid"
default_eemo_mux_conf="`eval echo ${full_sysconfdir} | sed s,NONE,$ac_default_prefix,g`/eemo_mux.conf"
default_mux_pid_file="`eval echo ${full_localstatedir} | sed s,NONE,$ac_default_prefix,g`/run/eemo_mux.pid"
default_eemo_sensor_conf="`eval echo ${full_sysconfdir} | sed s,NONE,$ac_default_prefix,g`/eemo_sensor.conf"
default_sensor_pid_file="`eval echo ${full_localstatedir} | sed s,NONE,$ac_default_prefix,g`/run/eemo_sensor.pid"

# Define some variables for the code
AC_DEFINE_UNQUOTED(
	[VERSION_MAJOR],
	[EEMO_VERSION_MAJOR],
	[Major version number]
)
AC_DEFINE_UNQUOTED(
	[VERSION_MINOR],
	[EEMO_VERSION_MINOR],
	[Minor version number]
)
AC_DEFINE_UNQUOTED(
	[EEMO_LOGLEVEL],
	[$EEMO_LOGLEVEL],
	[The log level set by the user]
)
AC_DEFINE_UNQUOTED(
	[DEFAULT_EEMO_CONF],
	["$default_eemo_conf"],
	[The default configuration file]
)
AC_DEFINE_UNQUOTED(
	[DEFAULT_EEMO_PIDFILE],
	["$default_pid_file"],
	[The default PID file]
)

AC_DEFINE_UNQUOTED(
	[DEFAULT_EEMO_MUX_CONF],
	["$default_eemo_mux_conf"],
	[The default configuration file for the sensor multiplexer]
)
AC_DEFINE_UNQUOTED(
	[DEFAULT_EEMO_MUX_PIDFILE],
	["$default_mux_pid_file"],
	[The default PID file for the sensor multiplexer]
)

AC_DEFINE_UNQUOTED(
	[DEFAULT_EEMO_SENSOR_CONF],
	["$default_eemo_sensor_conf"],
	[The default configuration file for the sensor daemon]
)
AC_DEFINE_UNQUOTED(
	[DEFAULT_EEMO_SENSOR_PIDFILE],
	["$default_sensor_pid_file"],
	[The default PID file for the sensor daemon]
)

# Generate theinstall script
AC_PROG_INSTALL

# Generate the makefiles
AC_CONFIG_FILES([
	Makefile
])

AC_OUTPUT
