Copyright (c) 2010-2014 SURFnet bv
http://www.surf.nl/en/about-surf/subsidiaries/surfnet

All rights reserved. This tool is distributed under a BSD-style license. For more information, see LICENSE

1. INTRODUCTION
===============

For efficient network monitoring, administration and research having a flexible tool that can capture network traffic and perform on-the-fly analysis is indispensable. There are already many good tools out there, such as tcpdump and WireShark. What these tools lack is the ability to perform continuous unsupervised monitoring and analysis of network traffic. This is where eemo comes in. As the long name (Extensible Ethernet MOnitor) suggests, eemo is a tool that does network monitoring and is highly extensible through a comprehensive plug-in API.

eemo allows you to write plug-ins that process captured packets at several levels. It has built-in parsers for:

 - Raw Ethernet frames
 - IP packets
 - UDP or TCP packets
 - ICMP packets
 - DNS packets (with name processing)

eemo was originally conceived as a tool to perform on-the-fly analysis of DNS data on authoritative and recursive caching name servers but has been written to be flexible and extensible so can in principle be used for many other purposes. As these things go, eemo was written as a Swiss army knife for local administrators, and as such has sparse documentation. Nevertheless, the source code is well documented and a number of sample plug-ins are provided that demonstrate how you can build on eemo to create your own network analysis modules.

I will not make empty promises and say that I intend to provide comprehensive documentation in the future. I will strive to improve on what is currently there but rely on spare time to write documentation, and - like many developers - tend to rather spend that time on new features that I need.  Nevertheless, I hope that the tool as-is may be of use to other people hence I'm releasing it in open source.


2. PREREQUISITES
================

To build eemo, you will need a modern set of autotools installed and the following dependencies:

 - POSIX-compliant build system
 - libpcap
 - libconfig >= 1.3.2
 - OpenSSL 0.9.8 or up (not a strict dependency, but needed for an extension I'm working on)

3. BUILDING
===========

To build eemo fresh from the repository, execute the following commands:

    sh ./autogen.sh
    ./configure
    make


4. INSTALLING
=============

Installation is simple, execute:

    make install

From the base directory in the repository.


5. USING THE TOOL
=================

Normally, eemo will run as a daemon. The default configuration file is in /etc/eemo.conf, but you can specify a different configuration file on the command-line. There is also a basic init.d script provided, as well as an RPM specification for Red Hat, CentOS and Fedora systems. To learn more about how eemo works, have a look at the sample configuration sample-eemo.conf provided in the repository in the config directory.

To learn the basics about eemo's command-line options, execute:

    src/eemo -h

6. CONTACT
==========

Questions/remarks/suggestions/praise on this tool can be sent to:

Roland van Rijswijk-Deij <roland.vanrijswijk@surfnet.nl>
