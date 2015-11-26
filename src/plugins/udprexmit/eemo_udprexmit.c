/*
 * Copyright (c) 2010-2015 SURFnet bv
 * Copyright (c) 2015 Roland van Rijswijk-Deij
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
 * UDP re-transmission from capture
 */

#include "config.h"
#include <stdlib.h>
#include "eemo.h"
#include "eemo_api.h"
#include "eemo_plugin_log.h"
#include "udp_handler.h"
#include "tcp_handler.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>

const static char* plugin_description = "EEMO UDP retransmission plugin " PACKAGE_VERSION;

/* TCP and UDP handler handles */
static unsigned long 		udp_handler_handle 	= 0;

/* Counters */
static unsigned long long	udp_counter		= 0;
static unsigned long long	udpv4_counter		= 0;
static unsigned long long	udpv6_counter		= 0;

/* Destination port and IP traffic to which needs to be retransmitted locally */
static int			cap_dst_port		= 0;
static char**			cap_dst_ips		= NULL;
static int			cap_dst_ips_count	= 0;

/* Local destination address */
static struct sockaddr_storage	local_addr;
static socklen_t		local_addr_len		= 0;
static int			local_socket		= -1;

/* Sample UDP handler */
eemo_rv eemo_udprexmit_udp_handler(const eemo_packet_buf* pkt, eemo_ip_packet_info ip_info, u_short srcport, u_short dstport, u_short length)
{
	int	i		= 0;
	int	ip_match	= 0;

	for (i = 0; i < cap_dst_ips_count; i++)
	{
		if (strcmp(cap_dst_ips[i], ip_info.ip_dst) == 0)
		{
			ip_match = 1;
			break;
		}
	}

	if (!ip_match)
	{
		/* Packet is not for us */
		return ERV_SKIPPED;
	}

	/* Retransmit packet */
	if (sendto(local_socket, pkt->data, pkt->len, 0, (struct sockaddr*) &local_addr, local_addr_len) < 0)
	{
		ERROR_MSG("Failed to retransmit UDP packet to local socket (%s)", strerror(errno));
	}

	/* Keep tally */
	udp_counter++;

	if (ip_info.ip_type == 4)
	{
		udpv4_counter++;
	}
	else
	{
		udpv6_counter++;
	}

	return ERV_HANDLED;
}

/* Plugin initialisation */
eemo_rv eemo_udprexmit_init(eemo_export_fn_table_ptr eemo_fn, const char* conf_base_path)
{
	char*			local_dst	= NULL;
	int			local_port	= -1;
	struct addrinfo*	local_addrs	= NULL;
	struct addrinfo*	addr_it		= NULL;
	struct addrinfo		hints;
	char			port_str[16]	= { 0 };

	/* Initialise logging for the plugin */
	eemo_init_plugin_log(eemo_fn->log);

	INFO_MSG("Initialising udprexmit plugin");

	/* Read configuration */
	if ((eemo_fn->conf_get_string)(conf_base_path, "local_dst", &local_dst, "localhost") != ERV_OK)
	{
		ERROR_MSG("Failed to read local destination from the configuration");

		return ERV_CONFIG_ERROR;
	}

	if (((eemo_fn->conf_get_int)(conf_base_path, "local_port", &local_port, -1) != ERV_OK) || (local_port <= 0))
	{
		ERROR_MSG("Failed to read local destination port from the configuration");

		free(local_dst);

		return ERV_CONFIG_ERROR;
	}

	/* Attempt to open the local destination socket */
	hints.ai_family		= AF_UNSPEC;
	hints.ai_socktype	= SOCK_DGRAM;
	hints.ai_flags		= 0;
	hints.ai_protocol	= 0;

	snprintf(port_str, 16, "%d", local_port);

	if (getaddrinfo(local_dst, port_str, &hints, &local_addrs) != 0)
	{
		ERROR_MSG("Unable to resolve local destination %s", local_dst);

		free(local_dst);

		return ERV_GENERAL_ERROR;
	}

	addr_it = local_addrs;
	local_socket = -1;

	while(addr_it != NULL)
	{
		if ((addr_it->ai_family == AF_INET) || (addr_it->ai_family == AF_INET6))
		{
			char	ip_str[INET6_ADDRSTRLEN]	= { 0 };

			local_socket = socket(addr_it->ai_family, SOCK_DGRAM, 0);

			memcpy(&local_addr, addr_it->ai_addr, addr_it->ai_addrlen);
			local_addr_len = addr_it->ai_addrlen;

			if (addr_it->ai_family == AF_INET)
			{
				struct sockaddr_in*	addr	= (struct sockaddr_in*) addr_it->ai_addr;

				if (inet_ntop(AF_INET, &addr->sin_addr, ip_str, INET6_ADDRSTRLEN) != NULL)
				{
					INFO_MSG("Sending traffic to local destination %s:%d", ip_str, local_port);
				}
			}
			else
			{
				struct sockaddr_in6*	addr	= (struct sockaddr_in6*) addr_it->ai_addr;

				if (inet_ntop(AF_INET6, &addr->sin6_addr, ip_str, INET6_ADDRSTRLEN) != NULL)
				{
					INFO_MSG("Sending traffic to local destination %s:%d", ip_str, local_port);
				}
			}

			break;
		}

		addr_it = addr_it->ai_next;
	}

	freeaddrinfo(local_addrs);
	free(local_dst);

	if (local_socket < 0)
	{
		ERROR_MSG("Unable to open a local destination socket");

		return ERV_GENERAL_ERROR;
	}

	if (((eemo_fn->conf_get_string_array)(conf_base_path, "dst_ips", &cap_dst_ips, &cap_dst_ips_count) != ERV_OK) || (cap_dst_ips_count == 0))
	{
		ERROR_MSG("Unable to retrieve the destination IP(s) from the capture stream to retransmit");

		return ERV_CONFIG_ERROR;
	}

	if (((eemo_fn->conf_get_int)(conf_base_path, "dst_port", &cap_dst_port, -1) != ERV_OK) || (cap_dst_port <= 0))
	{
		ERROR_MSG("Unable to retrieve valid destination port from the capture stream to retransmit");

		(eemo_fn->conf_free_string_array)(cap_dst_ips, cap_dst_ips_count);

		return ERV_CONFIG_ERROR;
	}

	/* Register UDP handler */
	if ((eemo_fn->reg_udp_handler)(UDP_ANY_PORT, cap_dst_port, &eemo_udprexmit_udp_handler, &udp_handler_handle) != ERV_OK)
	{
		ERROR_MSG("Failed to register udprexmit UDP handler");

		return ERV_GENERAL_ERROR;
	}

	INFO_MSG("udprexmit plugin initialisation complete");

	return ERV_OK;
}

/* Plugin uninitialisation */
eemo_rv eemo_udprexmit_uninit(eemo_export_fn_table_ptr eemo_fn)
{
	INFO_MSG("Uninitialising udprexmit plugin");

	INFO_MSG("Retransmitted %llu UDP packets (%llu UDPv4 / %llu UDPv6)", udp_counter, udpv4_counter, udpv6_counter);

	/* Unregister UDP handler */
	if ((eemo_fn->unreg_udp_handler)(udp_handler_handle) != ERV_OK)
	{
		ERROR_MSG("Failed to unregister udprexmit UDP handler");
	}

	/* Close local destination socket */
	close(local_socket);

	if (cap_dst_ips != NULL)
	{
		(eemo_fn->conf_free_string_array)(cap_dst_ips, cap_dst_ips_count);
	}

	INFO_MSG("Finished uninitialising udprexmit plugin");

	return ERV_OK;
}

/* Retrieve plugin description */
const char* eemo_udprexmit_getdescription(void)
{
	return plugin_description;
}

/* Retrieve plugin status */
eemo_rv eemo_udprexmit_status(void)
{
	return ERV_OK;
}

/* Plugin function table */
static eemo_plugin_fn_table udprexmit_fn_table =
{
	EEMO_PLUGIN_FN_VERSION,
	&eemo_udprexmit_init,
	&eemo_udprexmit_uninit,
	&eemo_udprexmit_getdescription,
	&eemo_udprexmit_status
};

/* Entry point for retrieving plugin function table */
eemo_rv eemo_plugin_get_fn_table(eemo_plugin_fn_table_ptrptr fn_table)
{
	if (fn_table == NULL)
	{
		return ERV_PARAM_INVALID;
	}

	*fn_table = &udprexmit_fn_table;

	return ERV_OK;
}

