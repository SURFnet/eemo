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
static eemo_dns_qhandler* dns_qhandlers = NULL;

/* UDP and TCP DNS handler handles */
static unsigned long udp_dns_in_handler_handle = 0;
static unsigned long udp_dns_out_handler_handle = 0;
static unsigned long tcp_dns_in_handler_handle = 0;
static unsigned long tcp_dns_out_handler_handle = 0;

/* Handle DNS payload */
eemo_rv eemo_handle_dns_payload(eemo_packet_buf* packet, eemo_ip_packet_info ip_info, int is_tcp)
{
	eemo_rv			rv 		= ERV_SKIPPED;
	/*eemo_dns_qhandler*	handler_it 	= NULL;*/
	eemo_dns_packet		dns_packet;

	/* Parse the packet */
	if ((rv = eemo_parse_dns_packet(packet, &dns_packet)) == ERV_OK)
	{
		/* Do something useful */
	}

	/* See if there are query handlers for this query class & type */
	/*LL_FOREACH(dns_qhandlers, handler_it)
	{
		if ((handler_it->handler_fn != NULL) &&
		    ((handler_it->qclass == DNS_QCLASS_UNSPECIFIED) || (handler_it->qclass == qclass)) &&
		    ((handler_it->qtype == DNS_QTYPE_UNSPECIFIED) || (handler_it->qtype == qtype)))
		{
			eemo_rv handler_rv = ERV_SKIPPED;
			
			handler_rv = (handler_it->handler_fn)(ip_info, qclass, qtype, hdr->dns_flags, query_name, is_tcp);

			if (rv != ERV_HANDLED)
			{
				rv = handler_rv;
			}
		}
	}*/

	eemo_free_dns_packet(&dns_packet);
	
	return rv;
}

/* Handle a UDP DNS packet */
eemo_rv eemo_handle_dns_udp_packet(eemo_packet_buf* packet, eemo_ip_packet_info ip_info, u_short srcport, u_short dstport)
{
	return eemo_handle_dns_payload(packet, ip_info, 0);
}

/* Handle a TCP DNS packet */
eemo_rv eemo_handle_dns_tcp_packet(eemo_packet_buf* packet, eemo_ip_packet_info ip_info, eemo_tcp_packet_info tcp_info)
{
	eemo_packet_buf* dns_data = NULL;
	eemo_rv rv = ERV_OK;
	u_short dns_length = 0;

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

	dns_data = eemo_pbuf_new(&packet->data[2], packet->len - 2);

	if (dns_data == NULL)
	{
		/* Out of memory! */
		return ERV_MEMORY;
	}

	rv = eemo_handle_dns_payload(dns_data, ip_info, 1);

	eemo_pbuf_free(dns_data);

	return rv;
}

/* Register a DNS handler */
eemo_rv eemo_reg_dns_qhandler(u_short qclass, u_short qtype, eemo_dns_qhandler_fn handler_fn, unsigned long* handle)
{
	eemo_dns_qhandler* new_handler = NULL;

	/* Check parameters */
	if ((handler_fn == NULL) || (handle == NULL))
	{
		return ERV_PARAM_INVALID;
	}

	/* Create a new handler entry */
	new_handler = (eemo_dns_qhandler*) malloc(sizeof(eemo_dns_qhandler));

	if (new_handler == NULL)
	{
		/* Not enough memory */
		return ERV_MEMORY;
	}

	new_handler->qclass = qclass;
	new_handler->qtype = qtype;
	new_handler->handler_fn = handler_fn;
	new_handler->handle = eemo_get_new_handle();

	/* Register the new handler */
	LL_APPEND(dns_qhandlers, new_handler);

	*handle = new_handler->handle;

	DEBUG_MSG("Registered DNS query handler with handle 0x%08X and handler function at 0x%08X", *handle, handler_fn);

	return ERV_OK;
}

/* Unregister a DNS handler */
eemo_rv eemo_unreg_dns_qhandler(unsigned long handle)
{
	eemo_dns_qhandler* to_delete = NULL;

	LL_SEARCH_SCALAR(dns_qhandlers, to_delete, handle, handle);

	if (to_delete != NULL)
	{
		LL_DELETE(dns_qhandlers, to_delete);

		DEBUG_MSG("Unregistered DNS query handler with handle 0x%08X and handler function at 0x%08X", handle, to_delete->handler_fn);

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
eemo_rv eemo_init_dns_qhandler(void)
{
	eemo_rv rv = ERV_OK;
	dns_qhandlers = NULL;

	/* Register UDP packet handlers */
	rv = eemo_reg_udp_handler(UDP_ANY_PORT, DNS_PORT, &eemo_handle_dns_udp_packet, &udp_dns_in_handler_handle);

	if (rv != ERV_OK)
	{
		return rv;
	}

	rv = eemo_reg_udp_handler(DNS_PORT, UDP_ANY_PORT, &eemo_handle_dns_udp_packet, &udp_dns_out_handler_handle);

	if (rv != ERV_OK)
	{
		eemo_unreg_udp_handler(udp_dns_in_handler_handle);
		return rv;
	}

	/* Register DNS packet handler */
	rv = eemo_reg_tcp_handler(TCP_ANY_PORT, DNS_PORT, &eemo_handle_dns_tcp_packet, &tcp_dns_in_handler_handle);

	if (rv != ERV_OK)
	{
		eemo_unreg_udp_handler(udp_dns_in_handler_handle);
		eemo_unreg_udp_handler(udp_dns_out_handler_handle);
		
		return rv;
	}

	rv = eemo_reg_tcp_handler(TCP_ANY_PORT, DNS_PORT, &eemo_handle_dns_tcp_packet, &tcp_dns_out_handler_handle);

	if (rv != ERV_OK)
	{
		eemo_unreg_udp_handler(udp_dns_in_handler_handle);
		eemo_unreg_udp_handler(udp_dns_out_handler_handle);
		eemo_unreg_udp_handler(tcp_dns_in_handler_handle);
		
		return rv;
	}

	INFO_MSG("Initialised DNS query handling");

	return rv;
}

/* Clean up */
void eemo_dns_qhandler_cleanup(void)
{
	eemo_dns_qhandler* qhandler_it = NULL; 
	eemo_dns_qhandler* qhandler_tmp = NULL;

	/* Clean up list of DNS query handlers */
	LL_FOREACH_SAFE(dns_qhandlers, qhandler_it, qhandler_tmp)
	{
		LL_DELETE(dns_qhandlers, qhandler_it);

		free(qhandler_it);
	}

	/* Unregister the DNS UDP and TCP handler */
	eemo_unreg_udp_handler(udp_dns_in_handler_handle);
	eemo_unreg_udp_handler(udp_dns_out_handler_handle);
	eemo_unreg_tcp_handler(tcp_dns_in_handler_handle);
	eemo_unreg_tcp_handler(tcp_dns_out_handler_handle);

	INFO_MSG("Uninitialised DNS query handling");
}

