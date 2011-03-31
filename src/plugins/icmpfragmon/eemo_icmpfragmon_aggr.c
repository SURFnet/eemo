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
 * ICMP fragment reassembly time-out monitoring
 */

#include "config.h"
#include "eemo.h"
#include "eemo_log.h"
#include "eemo_icmpfragmon_aggr.h"
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

/* Configuration */
char*	ifm_server		= NULL;
int	ifm_port		= 0;
int	ifm_max_packet_size	= 0;
int	ifm_sensor_id		= 0;

/* Communication socket */
int		ifm_socket	= -1;
struct sockaddr	ifm_sockaddr;
socklen_t	ifm_addrlen	= 0;

/* UDP assembly buffer */
unsigned char	ifm_buffer[65536];
size_t		ifm_buffer_len	= 0;

/* Transmit an UDP packet to the server */
void eemo_icmpfragmon_aggr_transmit(const unsigned char* send_buf, size_t buf_len)
{
	if (ifm_socket != -1)
	{
		ssize_t sent = sendto(ifm_socket, (const void*) send_buf, buf_len, 0, &ifm_sockaddr, ifm_addrlen);

		DEBUG_MSG("Transmitted %d byte(s)", sent);
	}
}

/* Initialise the message buffer */
void eemo_icmpfragmon_aggr_init_msg(void)
{
	/* Clear the buffer */
	memset(ifm_buffer, 0, ifm_max_packet_size);
	ifm_buffer_len = 0;
	
	/* Set the sensor ID */
	ifm_buffer[ifm_buffer_len++] = (ifm_sensor_id & 0xff000000) >> 24;
	ifm_buffer[ifm_buffer_len++] = (ifm_sensor_id & 0x00ff0000) >> 16;
	ifm_buffer[ifm_buffer_len++] = (ifm_sensor_id & 0x0000ff00) >> 8;
	ifm_buffer[ifm_buffer_len++] = (ifm_sensor_id & 0x000000ff);

	/* Set the message type */
	ifm_buffer[ifm_buffer_len++] = IFM_MSG_FRAGDATA;
}

/* Aggregate ICMP monitoring data */
void eemo_icmpfragmon_aggr_add(const char* client_ip)
{
	size_t to_add = 0;
	size_t ip_len = strlen(client_ip) & 0xff;

	/* Calculate size to add */
	to_add += ip_len;
	to_add += 1; /* ip addr len */
	
	if ((ifm_buffer_len + to_add) > ifm_max_packet_size)
	{
		/* Emit the current buffer */
		eemo_icmpfragmon_aggr_transmit(ifm_buffer, ifm_buffer_len);

		/* Reset the buffer */
		eemo_icmpfragmon_aggr_init_msg();
	}

	/* Append the new data in network byte order */
	ifm_buffer[ifm_buffer_len++] = (ip_len & 0x00ff);

	memcpy(&ifm_buffer[ifm_buffer_len], client_ip, ip_len);

	ifm_buffer_len += ip_len;

	DEBUG_MSG("Buffer is now filled with %d byte(s) of data", ifm_buffer_len);
}

/* Initialise ICMP monitoring */
void eemo_icmpfragmon_aggr_init(char* server, int port, int max_packet_size, int sensor_id)
{
	struct addrinfo* server_addrs = NULL;
	struct addrinfo* addr_it = NULL;
	struct addrinfo hints;
	char port_str[16];

	ifm_max_packet_size = (max_packet_size > 65536) ? 65536 : max_packet_size;
	ifm_sensor_id = sensor_id;

	INFO_MSG("Initialising sensor with ID 0x%08X", sensor_id);

	INFO_MSG("Maximum forwarding packet size is %d bytes", ifm_max_packet_size);

	ifm_server = server;
	ifm_port = port;

	INFO_MSG("Sending data to %s:%d", ifm_server, ifm_port);

	/* Clear data buffer */
	eemo_icmpfragmon_aggr_init_msg();

	/* Resolve the destination server */
	hints.ai_family = AF_UNSPEC;	/* return IPv4 or IPv6 address */
	hints.ai_socktype = SOCK_DGRAM;	/* require UDP socket */
	hints.ai_flags = 0;
	hints.ai_protocol = 0;

	snprintf(port_str, 16, "%d", ifm_port);

	if (getaddrinfo(ifm_server, port_str, &hints, &server_addrs) != 0)
	{
		ERROR_MSG("Failed to resolve %s", ifm_server);
		server_addrs = NULL;
	}

	addr_it = server_addrs;

	while (addr_it != NULL)
	{
		if ((addr_it->ai_family == AF_INET) || (addr_it->ai_family == AF_INET6))
		{
			memcpy(&ifm_sockaddr, addr_it->ai_addr, sizeof(struct sockaddr));
			ifm_addrlen = addr_it->ai_addrlen;

			/* Attempt to open a socket */
			ifm_socket = socket(addr_it->ai_family, SOCK_DGRAM, 0);

			if (ifm_socket == -1)
			{
				ERROR_MSG("Failed to open a socket");

				continue;
			}

			INFO_MSG("Transmitting data over IPv%d", (addr_it->ai_family == AF_INET) ? 4 : 6);

			break;
		}

		addr_it = addr_it->ai_next;
	}

	freeaddrinfo(server_addrs);
}

/* Uninitialise ICMP monitoring */
void eemo_icmpfragmon_aggr_uninit(eemo_conf_free_string_array_fn free_strings)
{
	/* Close the socket */
	if (ifm_socket >= 0)
	{
		close(ifm_socket);
	}

	free(ifm_server);
}

/* Handle ICMP packets */
eemo_rv eemo_icmpfragmon_handle_icmp(eemo_packet_buf* icmp_data, eemo_ip_packet_info ip_info, u_char icmp_type, u_char icmp_code)
{
	/* Add this host to the list of people with fragment reassembly issues */
	eemo_icmpfragmon_aggr_add(ip_info.ip_src);

	return ERV_HANDLED;
}

