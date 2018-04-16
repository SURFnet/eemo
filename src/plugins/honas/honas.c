/*
 * Copyright (c) 2010-2018 SURFnet bv
 * Copyright (c) 2018 Gijs Rijnders
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
 * DNS query Honas (Bloom Filter) exporter
 */

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <pthread.h>
#include "eemo.h"
#include "eemo_api.h"
#include "eemo_plugin_log.h"
#include "dns_handler.h"
#include "dns_parser.h"
#include "uthash.h"
#include <errno.h>

// The output log format that Honas takes.
#define DEBUGGING_LOG_FORMAT "%s %s/%i/%i"

const static char* plugin_description = "Honas (Bloom Filter) DNS query exporter plugin " PACKAGE_VERSION;

/* Handles */
static unsigned long dns_handler_handle	= 0;
struct sockaddr_un addr = { 0 };
int socket_fd = 0;

// Destination addresses of DNS name server, must be configured.
static struct in_addr v4_dst; /* IPv4 query destination */
static int v4_dst_set = 0;
static struct in6_addr v6_dst; /* IPv6 query destination */
static int v6_dst_set  = 0;

/** IPv4/IPv6 address
 *
 * When the `af` field is set to AF_INET then the `in.addr4` field is to be used.
 *
 * When the `af` field is set to AF_INET6 then the `in.addr6` field is to be used.
 */
struct in_addr46 {
        sa_family_t af;
        union {
                struct in_addr addr4;
                struct in6_addr addr6;
        } in;
};

// The DNS query data structure that is passed via the Unix socket.
struct dns_query_socket_t
{
	struct in_addr46 ipaddress;
	char domainname[256];
	unsigned short domain_length;
	unsigned short dnsclass;
	unsigned short dnsrecordtype;
};

/* Query handler */
eemo_rv eemo_honas_dns_handler(eemo_ip_packet_info ip_info, int is_tcp, const eemo_dns_packet* pkt)
{
	eemo_rv rv = ERV_SKIPPED;

	// Look at valid queries, which include questions and a domain name.
	if (!pkt->qr_flag && !pkt->is_partial && pkt->questions && pkt->questions->qname)
	{
		int dst_match = 0;

                /* Check if the query is directed toward the resolver we're monitoring */
                if ((ip_info.ip_type == IP_TYPE_V4) && v4_dst_set)
                {
                        if (memcmp(&ip_info.dst_addr.v4, &v4_dst, sizeof(struct in_addr)) == 0)
                        {
                                dst_match = 1;
                        }
                }
                else if ((ip_info.ip_type == IP_TYPE_V6) && v6_dst_set)
                {
                        if (memcmp(&ip_info.dst_addr.v6, &v6_dst, sizeof(struct in6_addr)) == 0)
                        {
                                dst_match = 1;
                        }
                }

		// Is the packet targeted at the configured DNS resolver?
		if (dst_match)
		{
			// The output variables.
			struct in_addr46 ip_address;

			// Check whether we are dealing with an IPv4 packet.
			if (ip_info.ip_type == IP_TYPE_V4)
			{
				ip_address.af = AF_INET;
				memcpy(&ip_address.in.addr4, &ip_info.dst_addr.v4, sizeof(struct in_addr));
			}
			// Are we dealing with IPv6 instead?
			else if (ip_info.ip_type == IP_TYPE_V6)
			{
				ip_address.af = AF_INET6;
				memcpy(&ip_address.in.addr6, &ip_info.dst_addr.v6, sizeof(struct in6_addr));
			}

			// Iterate the queries in the packet.
			const eemo_dns_query* next = pkt->questions;
			do
			{
				// Store the DNS query in a socket buffer for sending.
				struct dns_query_socket_t dnsquery;
				memcpy(&dnsquery.ipaddress, &ip_address, sizeof(struct in_addr46));
				dnsquery.domain_length = strlen(next->qname);
				strncpy(dnsquery.domainname, next->qname, dnsquery.domain_length);
				dnsquery.dnsclass = next->qclass;
				dnsquery.dnsrecordtype = next->qtype;

				// Write the query buffer to the Honas Unix socket.
				const ssize_t bytes_written = sendto(socket_fd, &dnsquery, sizeof(struct dns_query_socket_t), 0
					, (struct sockaddr*)&addr, sizeof(struct sockaddr_un));
				if (bytes_written == -1)
				{
					ERROR_MSG("Failed to write %zu bytes to the Unix socket! Error code: %i", bytes_written, errno);
				}
				else
				{
					rv = ERV_HANDLED;
				}

				// Set the next question to be processed.
				next = pkt->questions->next;
			}
			while (next);
		}
	}

	return rv;
}

/* Plugin initialisation */
eemo_rv eemo_honas_init(eemo_export_fn_table_ptr eemo_fn, const char* conf_base_path)
{
	char* dstfilename = NULL;
	char* v4_dst_str = NULL;
	char* v6_dst_str = NULL;

	/* Initialise logging for the plugin */
	eemo_init_plugin_log(eemo_fn->log);

	INFO_MSG("Initializing honas plugin");

	/* Retrieve configuration */
	if ((eemo_fn->conf_get_string)(conf_base_path, "socket_file", &dstfilename, NULL) != ERV_OK
		|| !dstfilename)
	{
		ERROR_MSG("Could not find configuration entry 'socket_file'!");
		return ERV_CONFIG_ERROR;
	}

        if ((eemo_fn->conf_get_string)(conf_base_path, "v4_dst", &v4_dst_str, NULL) != ERV_OK)
        {
                ERROR_MSG("Failed to retrieve IPv4 resolver destination address from the configuration");

                return ERV_CONFIG_ERROR;
        }

        if (v4_dst_str != NULL)
        {
                /* Convert string to IPv4 address */
                if (inet_pton(AF_INET, v4_dst_str, &v4_dst) != 1)
                {
                        ERROR_MSG("Configured value %s is not a valid IPv4 address", v4_dst_str);

                        return ERV_CONFIG_ERROR;
                }

                free(v4_dst_str);
                v4_dst_set = 1;
        }
        else
        {
                WARNING_MSG("No IPv4 resolver destination address specified, will not tally queries over IPv4!");
        }

        if ((eemo_fn->conf_get_string)(conf_base_path, "v6_dst", &v6_dst_str, NULL) != ERV_OK)
        {
                ERROR_MSG("Failed to retrieve IPv6 resolver destination address from the configuration");

                return ERV_CONFIG_ERROR;
        }

        if (v6_dst_str != NULL)
        {
                /* Convert string to IPv6 address */
                if (inet_pton(AF_INET6, v6_dst_str, &v6_dst) != 1)
                {
                        ERROR_MSG("Configured value %s is not a valid IPv6 address", v6_dst_str);

                        return ERV_CONFIG_ERROR;
                }

                free(v6_dst_str);
                v6_dst_set = 1;
        }
        else
        {
                WARNING_MSG("No IPv6 resolver destination address specified, will not tally queries over IPv6!");
        }

	/* Register DNS handler */
	if ((eemo_fn->reg_dns_handler)(&eemo_honas_dns_handler, PARSE_QUERY | PARSE_CANONICALIZE_NAME, &dns_handler_handle) != ERV_OK)
	{
		ERROR_MSG("Failed to register querypop DNS handler");
		(eemo_fn->unreg_dns_handler)(dns_handler_handle);
		return ERV_GENERAL_ERROR;
	}

	// Open the destination output socket.
	socket_fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (socket_fd == -1)
	{
		ERROR_MSG("Could not open Unix socket!");
		return ERV_CONFIG_ERROR;
	}

	const int bufsize = 8388608; // 8MB
	if (setsockopt(socket_fd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize)) == -1)
	{
		WARNING_MSG("Failed to increase the socket send buffer size!");
	}

	// Create the address structure for the Honas socket.
	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, dstfilename, sizeof(addr.sun_path) - 1);

	// Free the destination output file name if necessary.
	if (dstfilename)
	{
		free(dstfilename);
	}

	INFO_MSG("honas plugin initialization complete");

	return ERV_OK;
}

/* Plugin uninitialisation */
eemo_rv eemo_honas_uninit(eemo_export_fn_table_ptr eemo_fn)
{
	INFO_MSG("Uninitialising honas plugin");

	/* Unregister DNS handler */
	if ((eemo_fn->unreg_dns_handler)(dns_handler_handle) != ERV_OK)
	{
		ERROR_MSG("Failed to unregister honas DNS handler");
	}

	// Close destination output file.
	if (socket_fd)
	{
		close(socket_fd);
		INFO_MSG("Closing Honas Unix socket...");
	}

	INFO_MSG("Finished uninitializing honas plugin");

	return ERV_OK;
}

/* Retrieve plugin description */
const char* eemo_honas_getdescription(void)
{
	return plugin_description;
}

/* Retrieve plugin status */
eemo_rv eemo_honas_status(void)
{
	return ERV_OK;
}

/* Plugin function table */
static eemo_plugin_fn_table honas_fn_table =
{
	EEMO_PLUGIN_FN_VERSION,
	&eemo_honas_init,
	&eemo_honas_uninit,
	&eemo_honas_getdescription,
	&eemo_honas_status
};

/* Entry point for retrieving plugin function table */
eemo_rv eemo_plugin_get_fn_table(eemo_plugin_fn_table_ptrptr fn_table)
{
	if (fn_table == NULL)
	{
		return ERV_PARAM_INVALID;
	}

	*fn_table = &honas_fn_table;

	return ERV_OK;
}
