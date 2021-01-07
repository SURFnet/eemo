# EEMO
## The Extensible Ethernet MOnitor

Copyright (c) 2010-2017 SURFnet bv
http://www.surf.nl/en/about-surf/subsidiaries/surfnet

Copyright (c) 2014-2021 Roland van Rijswijk-Deij

All rights reserved. This tool is distributed under a BSD-style license. For more information, see LICENSE

## 1. INTRODUCTION

For efficient network monitoring, administration and research, having a flexible tool that can capture network traffic and perform on-the-fly analysis is indispensable. There are already many good tools out there, such as tcpdump and WireShark. What these tools lack is the ability to perform continuous unsupervised monitoring and analysis of network traffic. This is where eemo comes in. As the long name (Extensible Ethernet MOnitor) suggests, eemo is a tool that does network monitoring and is highly extensible through a comprehensive plug-in API.

eemo allows you to write plug-ins that process captured packets at several levels. It has built-in parsers for:

 - Raw Ethernet frames
 - IP packets
 - UDP or TCP packets
 - ICMP packets
 - DNS packets (with name processing)

eemo was originally conceived as a tool to perform on-the-fly analysis of DNS data on authoritative and recursive caching name servers but has been written to be flexible and extensible so can in principle be used for many other purposes. As these things go, eemo was written as a Swiss army knife for local administrators, and as such has sparse documentation. Nevertheless, the source code is well documented and a number of sample plug-ins are provided that demonstrate how you can build on eemo to create your own network analysis modules.

I will not make empty promises and say that I intend to provide comprehensive documentation in the future. I will strive to improve on what is currently there but rely on spare time to write documentation, and - like many developers - tend to rather spend that time on new features that I need.  Nevertheless, I hope that the tool as-is may be of use to other people hence I'm releasing it in open source.

Since version 0.3 eemo now includes the option of running a local sensor that does the capturing (eemo_sensor) and can forward the captured data stream to a sensor multiplexer (eemo_mux). The eemo executable itself can connect to a multiplexer and request access to multiple feeds. Transportation of the feeds is over TLS to ensure confidentiality of the captured data.

## 2. PREREQUISITES

To build eemo, you will need a modern set of autotools installed and the following dependencies:

 - POSIX-compliant build system
 - libpcap
 - libconfig >= 1.3.2
 - OpenSSL 1.0.1 or up (NOTE: changed since r0.3.136 -- higher version required for ephemeral DH using ECC in sensor, multiplexer and client TLS connections)

## 3. BUILDING

To build eemo fresh from the repository, execute the following commands:

    sh ./autogen.sh
    ./configure
    make


## 4. INSTALLING

Installation is simple, execute:

    make install

From the base directory in the repository.


## 5. USING THE TOOL

Normally, eemo will run as a daemon. The default configuration file is in /etc/eemo.conf, but you can specify a different configuration file on the command-line. There is also a basic init.d script provided, as well as an RPM specification for Red Hat, CentOS and Fedora systems. To learn more about how eemo works, have a look at the sample configuration sample-eemo.conf provided in the repository in the config directory.

To learn the basics about eemo's command-line options, execute:

    src/eemo -h

## 6. QUICK SETUP GUIDE FOR SENSOR/MULTIPLEXER/CLIENT CONFIGURATION

Since version 0.3, eemo supports a capture and forward system. Below is a quick start guide.

### CAPTURING WITH THE SENSOR

To capture with a sensor, you will need the eemo_sensor tool. For more information on its command-line options, execute:

    src/eemo_sensor -h

To configure the sensor, you will need three things:

 - a valid self-signed X.509 certificate with the accompanying private key
 - a valid self-signed X.509 certificate for the multiplexer that the sensor will connect to (see below)
 - a GUID to identify the capture stream

The distribution includes a script to generate self-signed certificates. To generate a new certificate, execute:

    scripts/eemo_generate_cert.sh [<hostname>]

The <hostname> parameter is optional, if you leave it out, the system's hostname will be used.

To generate a random new GUID, execute:

    src/eemo_sensor -G

All you need to do now is configure your sensor, a template configuration is included as config/sample-eemo_sensor.conf

**NOTE:** the directory containing the multiplexer certificates will need to be indexed by OpenSSL for server authentication to work correctly. To ensure this, change into the certificate directory and execute:

    c_rehash .

### MULTIPLEXER

Sensors send their data to a centrally located multiplexer. The executable for the multiplexer is eemo_mux and to learn more about it, execute:

    src/eemo_mux -h

To configure the multiplexer, you will need three things:

 - a valid self-signed X.509 certificate with accompanying private key
 - valid self-signed X.509 certificates for sensors
 - valid self-signed X.509 certificates for clients

Generating a new certificate for the multiplexer works the same as for the sensor (see above). You need to copy valid sensor and client certificates into a directory that you specify in the configuration file (eemo_mux.conf, example included as config/sample-eemo_mux.conf). Make sure to re-index the directory if you add new certificates (you can do this safely while the multiplexer is running and do not need to restart it if you add new certificates). To re-index, change to the directory containing the certificates and execute:

    c_rehash .

### CLIENT

The eemo executable can connect to a multiplexer by configuring it accordingly (for an example, see config/sample-eemo.conf). To set up eemo as client for a multiplexer, you will need:

 - a valid self-signed X.509 certificate with accompanying private key (see above, under sensor)
 - a valid self-signed X.509 certificate for the multiplexer that the client will connect to

Again, if you add a multiplexer certificate, remember to execute:

    c_rehash .

# 7. CONTACT

Questions/remarks/suggestions/praise on this tool can be sent to:

Roland van Rijswijk-Deij <roland.vanrijswijk@surfnet.nl>
