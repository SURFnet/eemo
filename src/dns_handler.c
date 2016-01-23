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
 * DNS query packet handling
 */

#include "config.h"
#include <stdlib.h>
#include <string.h>
#include "eemo.h"
#include "utlist.h"
#include "eemo_handlefactory.h"
#include "eemo_log.h"
#include "udp_handler.h"
#include "tcp_handler.h"
#include "dns_handler.h"
#include "dns_parser.h"
#include "dns_types.h"

/* The linked list of DNS query handlers */
static eemo_dns_handler*	dns_handlers			= NULL;

/* UDP and TCP DNS handler handles */
static unsigned long		udp_dns_in_handler_handle	= 0;
static unsigned long		udp_dns_out_handler_handle	= 0;
static unsigned long		tcp_dns_in_handler_handle	= 0;
static unsigned long		tcp_dns_out_handler_handle	= 0;

/* DNS parser flags */
static unsigned long 		dns_parser_flags		= 0;

/* Handle DNS payload */
eemo_rv eemo_handle_dns_payload(const eemo_packet_buf* packet, eemo_ip_packet_info ip_info, int is_tcp, unsigned short srcport, unsigned short dstport, unsigned short udp_len, int is_fragmented)
{
	eemo_rv			rv 		= ERV_SKIPPED;
	eemo_dns_handler*	handler_it 	= NULL;
	eemo_dns_packet		dns_packet;

	/* Parse the packet */
	rv = eemo_parse_dns_packet(packet, &dns_packet, dns_parser_flags, udp_len, is_fragmented);

	dns_packet.srcport = srcport;
	dns_packet.dstport = dstport;

	if ((rv == ERV_OK) || (rv == ERV_PARTIAL))
	{
		/* Call the registerd handlers with this packet */
		LL_FOREACH(dns_handlers, handler_it)
		{
			eemo_rv handler_rv = ERV_SKIPPED;

			handler_rv = (handler_it->handler_fn)(ip_info, is_tcp, &dns_packet);

			if (rv != ERV_HANDLED)
			{
				rv = handler_rv;
			}
		}
	}
	else
	{
		switch(rv)
		{
		case ERV_DNS_NAME_LOOPS:
			WARNING_MSG("DNS message from %s to %s contains a looping DNS name", ip_info.ip_src, ip_info.ip_dst);
			break;
		default:
			break;
		}
	}

	eemo_free_dns_packet(&dns_packet);
	
	return rv;
}

/* Handle a UDP DNS packet */
eemo_rv eemo_handle_dns_udp_packet(const eemo_packet_buf* packet, eemo_ip_packet_info ip_info, u_short srcport, u_short dstport, u_short length)
{
	/* Skip packets that are not coming from or going to port 53 */
	if ((srcport != DNS_PORT) && (dstport != DNS_PORT)) return ERV_SKIPPED;

	return eemo_handle_dns_payload(packet, ip_info, 0, srcport, dstport, length, ip_info.is_fragment);
}

/* Handle a TCP DNS packet */
eemo_rv eemo_handle_dns_tcp_packet(const eemo_packet_buf* packet, eemo_ip_packet_info ip_info, eemo_tcp_packet_info tcp_info)
{
	eemo_packet_buf	dns_data	= { NULL, 0 };
	eemo_rv		rv		= ERV_OK;
	u_short		dns_length	= 0;

	/* Skip packets that are not coming from or going to port 53 */
	if ((tcp_info.srcport != DNS_PORT) && (tcp_info.dstport != DNS_PORT)) return ERV_SKIPPED;

	/* Skip SYN, RST and FIN packets */
	if (FLAG_SET(tcp_info.flags, TCP_SYN) ||
	    FLAG_SET(tcp_info.flags, TCP_RST) ||
	    FLAG_SET(tcp_info.flags, TCP_FIN))
	{
		return ERV_SKIPPED;
	}

	/* Check minimal length */
	if (packet->len < 2)
	{
		/* Malformed packet */
		return ERV_MALFORMED;
	}

	/* Take length field */
	dns_length = ntohs(*((u_short*) packet->data));

	/* Check length */
	if ((packet->len - 2) != dns_length)
	{
		/* Packet data is truncated and we currently don't do reassembly */
		return ERV_MALFORMED;
	}

	eemo_pbuf_shrink(&dns_data, packet, 2);

	rv = eemo_handle_dns_payload(&dns_data, ip_info, 1, tcp_info.srcport, tcp_info.dstport, 0, 0);

	return rv;
}

/* Register a DNS handler */
eemo_rv eemo_reg_dns_handler(eemo_dns_handler_fn handler_fn, unsigned long parser_flags, unsigned long* handle)
{
	eemo_dns_handler* new_handler = NULL;

	/* Check parameters */
	if ((handler_fn == NULL) || (handle == NULL))
	{
		return ERV_PARAM_INVALID;
	}

	/* Create a new handler entry */
	new_handler = (eemo_dns_handler*) malloc(sizeof(eemo_dns_handler));

	if (new_handler == NULL)
	{
		/* Not enough memory */
		return ERV_MEMORY;
	}

	new_handler->handler_fn = handler_fn;
	new_handler->handle = eemo_get_new_handle();

	/* Update parser flags */
	dns_parser_flags |= parser_flags;

	/* Register the new handler */
	LL_APPEND(dns_handlers, new_handler);

	*handle = new_handler->handle;

	DEBUG_MSG("Registered DNS handler with handle 0x%08X and handler function at 0x%08X", *handle, handler_fn);

	return ERV_OK;
}

/* Unregister a DNS handler */
eemo_rv eemo_unreg_dns_handler(unsigned long handle)
{
	eemo_dns_handler* to_delete = NULL;

	LL_SEARCH_SCALAR(dns_handlers, to_delete, handle, handle);

	if (to_delete != NULL)
	{
		LL_DELETE(dns_handlers, to_delete);

		DEBUG_MSG("Unregistered DNS handler with handle 0x%08X and handler function at 0x%08X", handle, to_delete->handler_fn);

		free(to_delete);

		eemo_recycle_handle(handle);

		return ERV_OK;
	}
	else
	{
		return ERV_NOT_FOUND;
	}
}

/* Initialise DNS query handling */
eemo_rv eemo_init_dns_handler(void)
{
	eemo_rv rv = ERV_OK;
	dns_handlers = NULL;
	dns_parser_flags = 0;

	/* Register UDP packet handlers */
	rv = eemo_reg_udp_handler(UDP_ANY_PORT, UDP_ANY_PORT, &eemo_handle_dns_udp_packet, &udp_dns_in_handler_handle);

	if (rv != ERV_OK)
	{
		return rv;
	}

	/* Register DNS packet handler */
	rv = eemo_reg_tcp_handler(TCP_ANY_PORT, TCP_ANY_PORT, &eemo_handle_dns_tcp_packet, &tcp_dns_in_handler_handle);

	if (rv != ERV_OK)
	{
		eemo_unreg_udp_handler(udp_dns_in_handler_handle);
		eemo_unreg_udp_handler(udp_dns_out_handler_handle);
		
		return rv;
	}

	INFO_MSG("Initialised DNS query handling");

	return rv;
}

/* Clean up */
void eemo_dns_handler_cleanup(void)
{
	eemo_dns_handler* handler_it = NULL; 
	eemo_dns_handler* handler_tmp = NULL;

	/* Clean up list of DNS query handlers */
	LL_FOREACH_SAFE(dns_handlers, handler_it, handler_tmp)
	{
		LL_DELETE(dns_handlers, handler_it);

		free(handler_it);
	}

	/* Unregister the DNS UDP and TCP handler */
	eemo_unreg_udp_handler(udp_dns_in_handler_handle);
	eemo_unreg_udp_handler(udp_dns_out_handler_handle);
	eemo_unreg_tcp_handler(tcp_dns_in_handler_handle);
	eemo_unreg_tcp_handler(tcp_dns_out_handler_handle);

	INFO_MSG("Uninitialised DNS query handling");
}

