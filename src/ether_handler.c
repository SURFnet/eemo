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
 * Ethernet packet handling
 */

#include "config.h"
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "eemo.h"
#include "eemo_log.h"
#include "ether_handler.h"
#include "eemo_handlefactory.h"
#include "utlist.h"

/* The linked list of Ethernet packet handlers */
eemo_ether_handler* ether_handlers = NULL;

/* Register an Ethernet handler */
eemo_rv eemo_reg_ether_handler(u_short which_eth_type, eemo_ether_handler_fn handler_fn, unsigned long* handle)
{
	eemo_ether_handler* new_handler = NULL;

	/* Check parameters */
	if ((handler_fn == NULL) || (handle == NULL))
	{
		return ERV_PARAM_INVALID;
	}

	/* Create a new handler entry */
	new_handler = (eemo_ether_handler*) malloc(sizeof(eemo_ether_handler));

	if (new_handler == NULL)
	{
		/* Not enough memory */
		return ERV_MEMORY;
	}

	new_handler->which_eth_type = which_eth_type;
	new_handler->handler_fn = handler_fn;
	new_handler->handle = eemo_get_new_handle();

	/* Register the new handler */
	LL_APPEND(ether_handlers, new_handler);

	*handle = new_handler->handle;

	DEBUG_MSG("Registered Ethernet handler with handle 0x%08X and handler function at 0x%08X", *handle, handler_fn);

	return ERV_OK;
}

/* Unregister an Ethernet handler */
eemo_rv eemo_unreg_ether_handler(unsigned long handle)
{
	eemo_ether_handler* to_delete = NULL;

	LL_SEARCH_SCALAR(ether_handlers, to_delete, handle, handle);

	if (to_delete != NULL)
	{
		LL_DELETE(ether_handlers, to_delete);

		DEBUG_MSG("Unregistered Ethernet handler with handle 0x%08X and handler function at 0x%08X", handle, to_delete->handler_fn);

		free(to_delete);
		
		eemo_recycle_handle(handle);

		return ERV_OK;
	}
	else
	{
		return ERV_NOT_FOUND;
	}
}

/* Convert the packet from network to host byte order */
void eemo_ether_ntoh(eemo_hdr_raw_ether* hdr)
{
	hdr->eth_type = ntohs(hdr->eth_type);
}

/* Handle an Ethernet packet */
eemo_rv eemo_handle_ether_packet(eemo_packet_buf* packet)
{
	eemo_hdr_raw_ether* hdr = NULL;
	eemo_ether_packet_info packet_info;
	eemo_ether_handler* handler_it = NULL;
	eemo_rv rv = ERV_SKIPPED;

	/* Check the packet size */
	if (packet->len < sizeof(eemo_hdr_raw_ether))
	{
		/* Packet is malformed */
		return ERV_MALFORMED;
	}

	/* Take the header from the packet */
	hdr = (eemo_hdr_raw_ether*) packet->data;

	/* Convert to host byte order */
	eemo_ether_ntoh(hdr);

	/* Retrieve source and destination from the packet */
	memset(packet_info.eth_source, 0, 18);
	memset(packet_info.eth_dest, 0, 18);

	snprintf(packet_info.eth_source, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
		hdr->eth_source[0],
		hdr->eth_source[1],
		hdr->eth_source[2],
		hdr->eth_source[3],
		hdr->eth_source[4],
		hdr->eth_source[5]);
	snprintf(packet_info.eth_dest, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
		hdr->eth_dest[0],
		hdr->eth_dest[1],
		hdr->eth_dest[2],
		hdr->eth_dest[3],
		hdr->eth_dest[4],
		hdr->eth_dest[5]);

	/* Handle the packet */
	LL_FOREACH(ether_handlers, handler_it)
	{
		eemo_rv handler_rv = ERV_SKIPPED;

		if ((handler_it->handler_fn != NULL) && (handler_it->which_eth_type == hdr->eth_type))
		{
			eemo_packet_buf* ether_data =
				eemo_pbuf_new(&packet->data[sizeof(eemo_hdr_raw_ether)], packet->len - sizeof(eemo_hdr_raw_ether));

			if (ether_data != NULL)
			{
				handler_rv = (handler_it->handler_fn)(ether_data, packet_info);

				eemo_pbuf_free(ether_data);
			}
			else
			{
				handler_rv = ERV_MEMORY;
			}
		}

		if (rv != ERV_HANDLED)
		{
			rv = handler_rv;
		}
	}

	return rv;
}

/* Initialise Ethernet handling */
eemo_rv eemo_init_ether_handler(void)
{
	ether_handlers = NULL;

	INFO_MSG("Initialised Ethernet handling");

	return ERV_OK;
}

/* Clean up */
void eemo_ether_handler_cleanup(void)
{
	eemo_ether_handler* handler_it = NULL;
	eemo_ether_handler* handler_tmp = NULL;

	/* Clean up the list of Ethernet packet handlers */
	LL_FOREACH_SAFE(ether_handlers, handler_it, handler_tmp)
	{
		LL_DELETE(ether_handlers, handler_it);

		free(handler_it);
	}

	INFO_MSG("Uninitialised Ethernet handling");
}

