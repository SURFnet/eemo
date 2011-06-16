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
#include "eemo_list.h"
#include "eemo_log.h"
#include "ip_handler.h"
#include "icmp_handler.h"

/* The linked list of IP packet handlers */
static eemo_ll_entry* icmp_handlers = NULL;

/* ICMP handler entry comparison type */
typedef struct
{
	u_char		icmp_type;
	u_char		icmp_code;
	unsigned char	iptype;
}
eemo_icmp_handler_comp_t;

/* ICMP handler entry comparison */
int eemo_icmp_handler_compare(void* elem_data, void* comp_data)
{
	eemo_icmp_handler* elem = (eemo_icmp_handler*) elem_data;
	eemo_icmp_handler_comp_t* comp = (eemo_icmp_handler_comp_t*) comp_data;

	if ((elem_data == NULL) || (comp_data == NULL))
	{
		return 0;
	}

	if ((elem->icmp_type == comp->icmp_type) &&
	    (elem->icmp_code == comp->icmp_code) &&
	    (elem->iptype == comp->iptype))
	{
		return 1;
	}

	return 0;
}

/* Find an ICMP handler */
eemo_icmp_handler* eemo_find_icmp_handler(u_char icmp_type, u_char icmp_code, unsigned char iptype)
{
	eemo_icmp_handler* rv = NULL;
	eemo_icmp_handler_comp_t comp = { icmp_type, icmp_code, iptype };

	if (eemo_ll_find(icmp_handlers, (void*) &rv, &eemo_icmp_handler_compare, (void*) &comp) != ERV_OK)
	{
		/* FIXME: log this */
	}

	return rv;
}

/* Convert ICMP packet header to host byte order */
void eemo_icmp_ntoh(eemo_hdr_icmp* hdr)
{
	hdr->icmp_chksum = ntohs(hdr->icmp_chksum);
}

/* Handle an ICMP packet */
eemo_rv eemo_handle_icmp_packet(eemo_packet_buf* packet, eemo_ip_packet_info ip_info)
{
	eemo_hdr_icmp* hdr = NULL;
	eemo_icmp_handler* handler = NULL;

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
	handler = eemo_find_icmp_handler(hdr->icmp_type, hdr->icmp_code, ip_info.ip_type);

	if ((handler != NULL) && (handler->handler_fn != NULL))
	{
		eemo_rv rv = ERV_OK;
		eemo_packet_buf* icmp_data = 
			eemo_pbuf_new(&packet->data[sizeof(eemo_hdr_icmp)], packet->len - sizeof(eemo_hdr_icmp));

		if (icmp_data == NULL)
		{
			return ERV_MEMORY;
		}

		rv = (handler->handler_fn)(icmp_data, ip_info, hdr->icmp_type, hdr->icmp_code);

		eemo_pbuf_free(icmp_data);

		return rv;
	}

	return ERV_SKIPPED;
}

/* Register an ICMP handler */
eemo_rv eemo_reg_icmp_handler(u_char icmp_type, u_char icmp_code, unsigned char iptype, eemo_icmp_handler_fn handler_fn)
{
	eemo_icmp_handler* new_handler = NULL;
	eemo_rv rv = ERV_OK;

	/* Check if a handler for the specified type already exists */
	if (eemo_find_icmp_handler(icmp_type, icmp_code, iptype) != NULL)
	{
		/* A handler for this type has already been registered */
		return ERV_HANDLER_EXISTS;
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

	/* Register the new handler */
	if ((rv = eemo_ll_append(&icmp_handlers, (void*) new_handler)) != ERV_OK)
	{
		/* FIXME: log this */
		free(new_handler);
	}

	return rv;
}

/* Unregister an ICMP handler */
eemo_rv eemo_unreg_icmp_handler(u_char icmp_type, u_char icmp_code, unsigned char iptype)
{
	eemo_icmp_handler_comp_t comp = { icmp_type, icmp_code, iptype };

	return eemo_ll_remove(&icmp_handlers, &eemo_icmp_handler_compare, (void*) &comp);
}

/* Initialise ICMP handling */
eemo_rv eemo_init_icmp_handler(void)
{
	icmp_handlers = NULL;

	/* Register ICMPv4 packet handler */
	if (eemo_reg_ip_handler(IP_ICMPv4, &eemo_handle_icmp_packet) != ERV_OK)
	{
		ERROR_MSG("Failed to register ICMPv4 packet handler");

		return ERV_GENERAL_ERROR;
	}

	INFO_MSG("Initialised ICMPv4 handling");

	/* Register ICMPv6 packet handler */
	if (eemo_reg_ip_handler(IP_ICMPv6, &eemo_handle_icmp_packet) != ERV_OK)
	{
		ERROR_MSG("Failed to register ICMPv6 packet handler");

		eemo_unreg_ip_handler(IP_ICMPv4);

		return ERV_GENERAL_ERROR;
	}

	INFO_MSG("Initialised ICMPv6 handling");

	return ERV_OK;
}

/* Clean up */
void eemo_icmp_handler_cleanup(void)
{
	/* Clean up the list of ICMP packet handlers */
	if (eemo_ll_free(&icmp_handlers) != ERV_OK)
	{
		ERROR_MSG("Failed to free the list of ICMP handlers");
	}

	/* Unregister the IP handler for ICMPv4 packets */
	eemo_unreg_ip_handler(IP_ICMPv4);

	INFO_MSG("Uninitialised ICMPv4 handling");

	/* Unregister the IP handler for ICMPv6 packets */
	eemo_unreg_ip_handler(IP_ICMPv6);

	INFO_MSG("Uninitialised ICMPv6 handling");
}


