# $Id$

AC_DEFUN([ACX_PCAP],[
	AC_CHECK_LIB([pcap],[pcap_loop], 
		[AC_DEFINE(HAVE_PCAP,1,[PCAP is available])],
			[AC_MSG_ERROR(libpcap is required to build eemo)]
		)]
	)
])
