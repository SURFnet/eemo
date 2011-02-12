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

# Checks for compilers
AC_PROG_CC

# Compiler flags
ACX_PEDANTIC
ACX_STRICT

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

# Check for headers
AC_CHECK_HEADERS([pcap.h])
AC_CHECK_HEADERS([arpa/inet.h])
AC_CHECK_HEADERS([netdb.h])
AC_CHECK_HEADERS([ifaddrs.h])
AC_CHECK_HEADERS([sys/socket.h])
AC_CHECK_HEADERS([unistd.h])
AC_HEADER_STDC

# Check for functions
AC_FUNC_MEMCMP
AC_CHECK_FUNCS(ntohs ntohl)
AC_CHECK_FUNCS(getnameinfo)
AC_CHECK_FUNCS(getifaddrs)

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

# Generate theinstall script
AC_PROG_INSTALL

# Generate the makefiles
AC_CONFIG_FILES([
	Makefile
	src/Makefile
])

AC_OUTPUT
