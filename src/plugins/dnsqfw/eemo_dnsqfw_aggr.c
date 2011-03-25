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

/*
 * The Extensible Ethernet Monitor (EEMO)
 * DNS query aggregation and forwarding
 */

#include "config.h"
#include "eemo.h"
#include "eemo_log.h"
#include "eemo_dnsqfw_aggr.h"
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#define IP_ANY	"*"

/* Configuration */
char** 	qfw_ips 		= NULL;
int	qfw_ipcount		= 0;
char*	qfw_server		= NULL;
int	qfw_port		= 0;

/* Communication socket */
int		qfw_socket	= -1;
struct sockaddr	qfw_sockaddr;
socklen_t	qfw_addrlen	= 0;

/* UDP assembly buffer */
unsigned char	qfw_buffer[QFW_UDP_MAXSIZE];
size_t		qfw_buffer_len	= 0;

/* Start of connection transmission */
static const unsigned char qfw_start_transmission[8] = { 'S', 'T', 'A', 'R', 'T', 0, 0, 1 };

/* Transmit an UDP packet to the server */
void eemo_dnsqfw_aggr_transmit(const unsigned char* send_buf, size_t buf_len)
{
	if (qfw_socket != -1)
	{
		ssize_t sent = sendto(qfw_socket, (const void*) send_buf, buf_len, 0, &qfw_sockaddr, qfw_addrlen);

		DEBUG_MSG("Transmitted %d byte(s)", sent);
	}
}

/* Aggregate DNS query data */
void eemo_dnsqfw_aggr_add(ushort qclass, ushort qtype, const char* qname, int is_tcp)
{
	size_t to_add = 0;
	size_t qname_len = strlen(qname);

	/* Calculate size to add */
	to_add += sizeof(ushort) * 3;
	to_add += qname_len;
	
	if ((qfw_buffer_len + to_add) > QFW_UDP_MAXSIZE)
	{
		/* Emit the current buffer */
		eemo_dnsqfw_aggr_transmit(qfw_buffer, qfw_buffer_len);

		/* Clear the buffer */
		memset(qfw_buffer, 0, QFW_UDP_MAXSIZE);
		qfw_buffer_len = 0;
	}

	/* Append the new data in network byte order */
	qfw_buffer[qfw_buffer_len++] = (qclass & 0xff00) >> 8;
	qfw_buffer[qfw_buffer_len++] = (qclass & 0x00ff);
	qfw_buffer[qfw_buffer_len++] = (qtype & 0xff00) >> 8;
	qfw_buffer[qfw_buffer_len++] = (qtype & 0x00ff);
	qfw_buffer[qfw_buffer_len++] = is_tcp ? 1 : 0;
	qfw_buffer[qfw_buffer_len++] = (qname_len & 0xff00) >> 8;
	qfw_buffer[qfw_buffer_len++] = (qname_len & 0x00ff);
	
	memcpy(&qfw_buffer[qfw_buffer_len], qname, qname_len);

	qfw_buffer_len += qname_len;

	DEBUG_MSG("Buffer is now filled with %d byte(s) of data", qfw_buffer_len);
}

/* Initialise DNS query forwarding */
void eemo_dnsqfw_aggr_init(char** ips, int ip_count, char* server, int port)
{
	int i = 0;
	struct addrinfo* server_addrs = NULL;
	struct addrinfo* addr_it = NULL;
	struct addrinfo hints;
	char port_str[16];

	qfw_ips = ips;
	qfw_ipcount = ip_count;

	DEBUG_MSG("Listening to %d IP addresses", qfw_ipcount);

	for (i = 0; i < qfw_ipcount; i++)
	{
		DEBUG_MSG("Listening for queries to IP %s", ips[i]);
	}

	qfw_server = server;
	qfw_port = port;

	DEBUG_MSG("Sending data to %s:%d", qfw_server, qfw_port);

	/* Clear data buffer */
	memset(qfw_buffer, 0, QFW_UDP_MAXSIZE);
	qfw_buffer_len = 0;

	/* Resolve the destination server */
	hints.ai_family = AF_UNSPEC;	/* return IPv4 or IPv6 address */
	hints.ai_socktype = SOCK_DGRAM;	/* require UDP socket */
	hints.ai_flags = 0;
	hints.ai_protocol = 0;

	snprintf(port_str, 16, "%d", qfw_port);

	if (getaddrinfo(qfw_server, port_str, &hints, &server_addrs) != 0)
	{
		DEBUG_MSG("Failed to resolve %s", qfw_server);
		server_addrs = NULL;
	}

	addr_it = server_addrs;

	while (addr_it != NULL)
	{
		if ((addr_it->ai_family == AF_INET) || (addr_it->ai_family == AF_INET6))
		{
			memcpy(&qfw_sockaddr, addr_it->ai_addr, sizeof(struct sockaddr));
			qfw_addrlen = addr_it->ai_addrlen;

			/* Attempt to open a socket */
			qfw_socket = socket(addr_it->ai_family, SOCK_DGRAM, 0);

			if (qfw_socket == -1)
			{
				ERROR_MSG("Failed to open a socket");

				continue;
			}

			break;
		}

		addr_it = addr_it->ai_next;
	}

	freeaddrinfo(server_addrs);

	eemo_dnsqfw_aggr_transmit(qfw_start_transmission, 8);
}

/* Uninitialise DNS query forwarding */
void eemo_dnsqfw_aggr_uninit(eemo_conf_free_string_array_fn free_strings)
{
	/* Close the socket */
	if (qfw_socket >= 0)
	{
		close(qfw_socket);
	}

	(free_strings)(qfw_ips, qfw_ipcount);
	free(qfw_server);
}

/* Handle DNS query packets */
eemo_rv eemo_dnsqfw_aggr_handleq(eemo_ip_packet_info ip_info, u_short qclass, u_short qtype, u_short flags, char* qname, int is_tcp)
{
	int i = 0;
	int ip_match = 0;

	/* Check if this query is directed at the server we're supposed to monitor */
	for (i = 0; i < qfw_ipcount; i++)
	{
		if (!strcmp(qfw_ips[i], ip_info.ip_dst) || !strcmp(qfw_ips[i], IP_ANY))
		{
			ip_match = 1;
			break;
		}
	}

	if (!ip_match)
	{
		return ERV_SKIPPED;
	}

	/* Add data to aggregation buffer */
	eemo_dnsqfw_aggr_add(qclass, qtype, qname, is_tcp);

	return ERV_HANDLED;
}

