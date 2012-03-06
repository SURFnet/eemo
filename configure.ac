dnl
dnl $Id$
dnl

################################################################################
# Version information                                                          #
################################################################################

# Program version

define([EEMO_VERSION_MAJOR], [0])
define([EEMO_VERSION_MINOR], [1])
define([EEMO_VERSION_BUILDREV], esyscmd([sh -c "svnversion|tr -d '\n'"]))
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

################################################################################
# Configuration functions                                                      #
################################################################################

# Init
AC_PREREQ(2.61)
AC_INIT([eemo],[EEMO_VERSION_MAJOR.EEMO_VERSION_MINOR.EEMO_VERSION_BUILDREV[]PACKAGE_SUFFIX])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_SRCDIR([src/Makefile.am])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE(foreign)
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

# Check for headers
AC_CHECK_HEADERS([pcap.h])
AC_CHECK_HEADERS([arpa/inet.h])
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

# Generate theinstall script
AC_PROG_INSTALL

# Generate the makefiles
AC_CONFIG_FILES([
	Makefile
	src/Makefile
	src/plugins/Makefile
	src/plugins/demo/Makefile
	src/plugins/dnsqfw/Makefile
	src/plugins/dnsqfw/testsink/Makefile
	src/plugins/dnsstats/Makefile
	src/plugins/dnsstats/cacti/Makefile
	src/plugins/dnssensorfw/Makefile
	src/plugins/dnssensorfw/testsink/Makefile
	src/plugins/icmpfragmon/Makefile
	config/Makefile
])

AC_OUTPUT
