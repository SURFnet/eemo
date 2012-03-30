/* $Id$ */

/*
 * Copyright (c) 2010-2012 SURFnet bv
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
 * UDP packet handling
 */

#include "config.h"
#include <stdlib.h>
#include <string.h>
#include "eemo.h"
#include "utlist.h"
#include "eemo_handlefactory.h"
#include "eemo_log.h"
#include "ip_handler.h"
#include "udp_handler.h"

/* The handle for the UDP IP packet handler */
static unsigned long udp_ip_handler_handle = 0;

/* The linked list of UDP packet handlers */
static eemo_udp_handler* udp_handlers = NULL;

/* Convert UDP packet header to host byte order */
void eemo_udp_ntoh(eemo_hdr_udp* hdr)
{
	hdr->udp_srcport = ntohs(hdr->udp_srcport);
	hdr->udp_dstport = ntohs(hdr->udp_dstport);
	hdr->udp_len	 = ntohs(hdr->udp_len);
	hdr->udp_chksum	 = ntohs(hdr->udp_chksum);
}

/* Handle an UDP packet */
eemo_rv eemo_handle_udp_packet(eemo_packet_buf* packet, eemo_ip_packet_info ip_info)
{
	eemo_hdr_udp* hdr = NULL;
	eemo_udp_handler* handler_it = NULL;
	eemo_rv rv = ERV_SKIPPED;

	/* Check minimum length */
	if (packet->len < sizeof(eemo_hdr_udp))
	{
		/* UDP packet is malformed */
		return ERV_MALFORMED;
	}

	/* Take the header from the packet */
	hdr = (eemo_hdr_udp*) packet->data;

	/* Convert the header to host byte order */
	eemo_udp_ntoh(hdr);

	/* See if there is a handler given the source and destination port for this packet */
	LL_FOREACH(udp_handlers, handler_it)
	{
		eemo_rv handler_rv = ERV_SKIPPED;

		if ((handler_it->handler_fn != NULL) &&
		    ((handler_it->srcport == UDP_ANY_PORT) || (handler_it->srcport == hdr->udp_srcport)) &&
		    ((handler_it->dstport == UDP_ANY_PORT) || (handler_it->dstport == hdr->udp_dstport)))
		     
		{
			eemo_packet_buf* udp_data = 
				eemo_pbuf_new(&packet->data[sizeof(eemo_hdr_udp)], packet->len - sizeof(eemo_hdr_udp));

			if (udp_data == NULL)
			{
				return ERV_MEMORY;
			}

			handler_rv = (handler_it->handler_fn)(udp_data, ip_info, hdr->udp_srcport, hdr->udp_dstport);

			eemo_pbuf_free(udp_data);
		}

		if (rv != ERV_HANDLED)
		{
			rv = handler_rv;
		}
	}

	return rv;
}

/* Register a UDP handler */
eemo_rv eemo_reg_udp_handler(u_short srcport, u_short dstport, eemo_udp_handler_fn handler_fn, unsigned long* handle)
{
	eemo_udp_handler* new_handler = NULL;

	/* Check parameters */
	if ((handler_fn == NULL) || (handle == NULL))
	{
		return ERV_PARAM_INVALID;
	}

	/* Create a new handler entry */
	new_handler = (eemo_udp_handler*) malloc(sizeof(eemo_udp_handler));

	if (new_handler == NULL)
	{
		/* Not enough memory */
		return ERV_MEMORY;
	}

	new_handler->srcport = srcport;
	new_handler->dstport = dstport;
	new_handler->handler_fn = handler_fn;
	new_handler->handle = eemo_get_new_handle();

	/* Register the new handler */
	LL_APPEND(udp_handlers, new_handler);

	*handle = new_handler->handle;

	DEBUG_MSG("Registered UDP handler with handle 0x%08X and handler function at 0x%08X", *handle, handler_fn);

	return ERV_OK;
}

/* Unregister a UDP handler */
eemo_rv eemo_unreg_udp_handler(unsigned long handle)
{
	eemo_udp_handler* to_delete = NULL;

	LL_SEARCH_SCALAR(udp_handlers, to_delete, handle, handle);

	if (to_delete != NULL)
	{
		LL_DELETE(udp_handlers, to_delete);

		DEBUG_MSG("Unregistered UDP handler with handle 0x%08x and handler function at 0x%08X", handle, to_delete->handler_fn);

		free(to_delete);

		eemo_recycle_handle(handle);

		return ERV_OK;
	}
	else
	{
		return ERV_NOT_FOUND;
	}
}

/* Initialise UDP handling */
eemo_rv eemo_init_udp_handler(void)
{
	udp_handlers = NULL;

	/* Register UDP packet handler */
	if (eemo_reg_ip_handler(IP_UDP, &eemo_handle_udp_packet, &udp_ip_handler_handle) != ERV_OK)
	{
		ERROR_MSG("Failed to register UDP packet handler");

		return ERV_GENERAL_ERROR;
	}

	INFO_MSG("Initialised UDP handling");

	return ERV_OK;
}

/* Clean up */
void eemo_udp_handler_cleanup(void)
{
	eemo_udp_handler* handler_it = NULL;
	eemo_udp_handler* handler_tmp = NULL;

	/* Clean up the list of UDP packet handlers */
	LL_FOREACH_SAFE(udp_handlers, handler_it, handler_tmp)
	{
		LL_DELETE(udp_handlers, handler_it);

		free(handler_it);
	}

	/* Unregister the IP handler for UDP packets */
	eemo_unreg_ip_handler(udp_ip_handler_handle);

	INFO_MSG("Uninitialised UDP handling");
}

