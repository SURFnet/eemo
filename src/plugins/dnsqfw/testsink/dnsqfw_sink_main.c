/* $Id$ */

/*
 * Copyright (c) 2010-2011 SURFnet bv
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of SURFnet bv nor the names of its contributors 
 *    may be used to endorse or promote products derived from this 
 *    software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include "dns_types.h"
#include "eemo_dnsqfw_aggr.h"

#define QFW_TEST_SINK_PORT	53535

/* Set to AF_INET for IPv4, AF_INET6 for IPv6 */
#define INET_FAMILY		AF_INET

int main(int argc, char* argv[])
{
	int sock = -1;
	unsigned char buf[65536];

	/* Create socket */
	if (INET_FAMILY == AF_INET)
	{
		struct sockaddr_in addr;

		sock = socket(INET_FAMILY, SOCK_DGRAM, IPPROTO_UDP);

		if (sock == -1)
		{
			/* Failed to created socket */
			fprintf(stderr, "Failed to create IPv%d socket\n", (INET_FAMILY == AF_INET) ? 4 : 6);

			return -1;
		}

		/* Bind to all interfaces */
		addr.sin_family = AF_INET;
		addr.sin_port = htons(QFW_TEST_SINK_PORT);
		addr.sin_addr.s_addr = INADDR_ANY;

		if (bind(sock, (struct sockaddr*) &addr, sizeof(addr)) != 0)
		{
			fprintf(stderr, "Failed to bind to port %d\n", QFW_TEST_SINK_PORT);
		}
	}
	else if (INET_FAMILY == AF_INET6)
	{
		struct sockaddr_in6 addr;
		struct in6_addr v6all = IN6ADDR_ANY_INIT;

		sock = socket(INET_FAMILY, SOCK_DGRAM, IPPROTO_UDP);

		if (sock == -1)
		{
			/* Failed to created socket */
			fprintf(stderr, "Failed to create IPv%d socket\n", (INET_FAMILY == AF_INET) ? 4 : 6);

			return -1;
		}

		/* Bind to all interfaces */
		addr.sin6_family = AF_INET6;
		addr.sin6_port = htons(QFW_TEST_SINK_PORT);
		addr.sin6_addr = v6all;

		if (bind(sock, (struct sockaddr*) &addr, sizeof(addr)) != 0)
		{
			fprintf(stderr, "Failed to bind to port %d\n", QFW_TEST_SINK_PORT);
		}
	}
	else
	{
		fprintf(stderr, "Program compiled with unknown address family %d\n", INET_FAMILY);

		return -1;
	}

	/* Wait for incoming packets */
	while (1)
	{
		struct sockaddr sender;
		socklen_t sender_len = 0;

		ssize_t received = recvfrom(sock, (void*) buf, 65536, 0, &sender, &sender_len);

		if (received > 0)
		{
			int ofs = 0;
			int qcount = 0;
			unsigned char msg_type = 0;
			unsigned int sensor_id = 0;

			printf("Received %d bytes\n", (int) received);

			/* Determine the sensor ID */
			sensor_id += buf[ofs++] << 24;
			sensor_id += buf[ofs++] << 16;
			sensor_id += buf[ofs++] << 8;
			sensor_id += buf[ofs++];

			/* Determine the message type */
			msg_type = buf[ofs++];

			printf("Sending sensor ID is 0x%08X\n\n", sensor_id);

			if (msg_type == QFW_MSG_QDATA)
			{
				printf("Received data is query data\n\n");
				/* Print the data */
				while (ofs < received)
				{
					unsigned short qtype = 0;
					unsigned short qclass = 0;
					unsigned char is_tcp = 0;
					unsigned char is_dnssec = 0;
					unsigned short qname_len = 0;
					unsigned char ip_len = 0;
					char qname[2048];
					char client_ip[257];
	
					qclass += buf[ofs++] << 8;
					qclass += buf[ofs++];
					qtype += buf[ofs++] << 8;
					qtype += buf[ofs++];
					is_tcp = buf[ofs++];
					is_dnssec = buf[ofs++];
					qname_len += buf[ofs++] << 8;
					qname_len += buf[ofs++];
					memset(qname, 0, 2048);
					memcpy(qname, &buf[ofs], qname_len);
					ofs += qname_len;
					ip_len = buf[ofs++];
					memset(client_ip, 0, 257);
					memcpy(client_ip, &buf[ofs], ip_len);
					ofs += ip_len;
	
					printf("class = %5u, type = %5u, tcp = %d, dnssec = %d, client = %s, name = %s\n",
						qclass,
						qtype,
						is_tcp,
						is_dnssec,
						client_ip,
						qname);
	
					qcount++;
				}
	
				printf("\nReported on %d queries\n\n", qcount);
			}
			else
			{
				printf("\nUnknown message type, skipping\n\n");
			}
		}
	}

	/* Close all sockets */	
	close(sock);

	return 0;
}

