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
 * ICMP packet handling
 */

#include "config.h"
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "eemo.h"
#include "utlist.h"
#include "eemo_handlefactory.h"
#include "eemo_log.h"
#include "ip_handler.h"
#include "icmp_handler.h"

/* Handle for the registered IP handler */
static unsigned long icmp_ip4_handler_handle = 0;
static unsigned long icmp_ip6_handler_handle = 0;

/* The linked list of IP packet handlers */
static eemo_icmp_handler* icmp_handlers = NULL;

/* Convert ICMP packet header to host byte order */
void eemo_icmp_ntoh(eemo_hdr_icmp* hdr)
{
	hdr->icmp_chksum = ntohs(hdr->icmp_chksum);
}

/* Handle an ICMP packet */
eemo_rv eemo_handle_icmp_packet(eemo_packet_buf* packet, eemo_ip_packet_info ip_info)
{
	eemo_hdr_icmp* hdr = NULL;
	eemo_icmp_handler* handler_it = NULL;
	eemo_rv rv = ERV_SKIPPED;

	/* Check minimum length */
	if (packet->len < sizeof(eemo_hdr_icmp))
	{
		/* ICMP packet is malformed */
		return ERV_MALFORMED;
	}

	/* Take the header from the packet */
	hdr = (eemo_hdr_icmp*) packet->data;

	/* Convert the header to host byte order */
	eemo_icmp_ntoh(hdr);

	/* See if there is a handler given the type, code and IP type of this packet */
	LL_FOREACH(icmp_handlers, handler_it)
	{
		eemo_rv handler_rv = ERV_SKIPPED;

		if ((handler_it->handler_fn != NULL) &&
		    (handler_it->icmp_type == hdr->icmp_type) &&
		    (handler_it->icmp_code == hdr->icmp_code) &&
		    (handler_it->iptype == ip_info.ip_type))
		{
			eemo_packet_buf* icmp_data = 
				eemo_pbuf_new(&packet->data[sizeof(eemo_hdr_icmp)], packet->len - sizeof(eemo_hdr_icmp));
	
			if (icmp_data == NULL)
			{
				return ERV_MEMORY;
			}
	
			handler_rv = (handler_it->handler_fn)(icmp_data, ip_info, hdr->icmp_type, hdr->icmp_code);
	
			eemo_pbuf_free(icmp_data);
		}

		if (rv != ERV_HANDLED)
		{
			rv = handler_rv;
		}
	}

	return rv;
}

/* Register an ICMP handler */
eemo_rv eemo_reg_icmp_handler(u_char icmp_type, u_char icmp_code, unsigned char iptype, eemo_icmp_handler_fn handler_fn, unsigned long* handle)
{
	eemo_icmp_handler* new_handler = NULL;

	/* Check parameters */
	if ((handler_fn == NULL) || (handle == NULL))
	{
		return ERV_PARAM_INVALID;
	}

	/* Create a new handler entry */
	new_handler = (eemo_icmp_handler*) malloc(sizeof(eemo_icmp_handler));

	if (new_handler == NULL)
	{
		/* Not enough memory */
		return ERV_MEMORY;
	}

	new_handler->icmp_type = icmp_type;
	new_handler->icmp_code = icmp_code;
	new_handler->iptype = iptype;
	new_handler->handler_fn = handler_fn;
	new_handler->handle = eemo_get_new_handle();

	/* Register the new handler */
	LL_APPEND(icmp_handlers, new_handler);

	*handle = new_handler->handle;

	DEBUG_MSG("Registered ICMP handler with handle 0x%08X and handler function at 0x%08X", *handle, handler_fn);

	return ERV_OK;
}

/* Unregister an ICMP handler */
eemo_rv eemo_unreg_icmp_handler(unsigned long handle)
{
	eemo_icmp_handler* to_delete = NULL;

	LL_SEARCH_SCALAR(icmp_handlers, to_delete, handle, handle);

	if (to_delete != NULL)
	{
		LL_DELETE(icmp_handlers, to_delete);

		DEBUG_MSG("Unregistered ICMP handler with handle 0x%08X and handler function at 0x%08X", handle, to_delete->handler_fn);

		free(to_delete);

		eemo_recycle_handle(handle);

		return ERV_OK;
	}
	else
	{
		return ERV_NOT_FOUND;
	}
}

/* Initialise ICMP handling */
eemo_rv eemo_init_icmp_handler(void)
{
	icmp_handlers = NULL;

	/* Register ICMPv4 packet handler */
	if (eemo_reg_ip_handler(IP_ICMPv4, &eemo_handle_icmp_packet, &icmp_ip4_handler_handle) != ERV_OK)
	{
		ERROR_MSG("Failed to register ICMPv4 packet handler");

		return ERV_GENERAL_ERROR;
	}

	INFO_MSG("Initialised ICMPv4 handling");

	/* Register ICMPv6 packet handler */
	if (eemo_reg_ip_handler(IP_ICMPv6, &eemo_handle_icmp_packet, &icmp_ip6_handler_handle) != ERV_OK)
	{
		ERROR_MSG("Failed to register ICMPv6 packet handler");

		eemo_unreg_ip_handler(icmp_ip4_handler_handle);

		return ERV_GENERAL_ERROR;
	}

	INFO_MSG("Initialised ICMPv6 handling");

	return ERV_OK;
}

/* Clean up */
void eemo_icmp_handler_cleanup(void)
{
	eemo_icmp_handler* handler_it = NULL;
	eemo_icmp_handler* handler_tmp = NULL;

	/* Clean up the list of ICMP packet handlers */
	LL_FOREACH_SAFE(icmp_handlers, handler_it, handler_tmp)
	{
		LL_DELETE(icmp_handlers, handler_it);

		free(handler_it);
	}

	/* Unregister the IP handler for ICMPv4 packets */
	eemo_unreg_ip_handler(icmp_ip4_handler_handle);

	INFO_MSG("Uninitialised ICMPv4 handling");

	/* Unregister the IP handler for ICMPv6 packets */
	eemo_unreg_ip_handler(icmp_ip6_handler_handle);

	INFO_MSG("Uninitialised ICMPv6 handling");
}


