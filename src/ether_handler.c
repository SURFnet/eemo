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
#include "eemo_list.h"
#include "eemo_log.h"
#include "ether_handler.h"

/* The linked list of Ethernet packet handlers */
static eemo_ll_entry* ether_handlers = NULL;

/* Ethernet handler cloning */
void* eemo_ether_handler_clone(const void* elem_data)
{
	const eemo_ether_handler* elem = (const eemo_ether_handler*) elem_data;
	eemo_ether_handler* new_elem = NULL;

	if (elem_data == NULL)
	{
		return NULL;
	}

	new_elem = (eemo_ether_handler*) malloc(sizeof(eemo_ether_handler));

	if (new_elem != NULL)
	{
		/* Clone element, no deep copy required in this case */
		memcpy(new_elem, elem, sizeof(eemo_ether_handler));
	}

	return (void*) new_elem;
}

/* Ethernet handler comparison */
int eemo_ether_handler_compare(void* elem_data, void* comp_data)
{
	eemo_ether_handler* elem = (eemo_ether_handler*) elem_data;
	u_short which_eth_type = 0;

	if ((elem_data == NULL) || (comp_data == NULL))
	{
		return 0;
	}

	which_eth_type = *((u_short*) comp_data);

	if (elem->which_eth_type == which_eth_type)
	{
		return 1;
	}
	
	return 0;
}

/* Find an Ethernet handler for the specified type */
eemo_ll_entry* eemo_find_ether_handlers(u_short which_eth_type)
{
	eemo_ll_entry* rv = NULL;

	if (eemo_ll_find_multi(ether_handlers, &rv, &eemo_ether_handler_compare, (void*) &which_eth_type, &eemo_ether_handler_clone) != ERV_OK)
	{
		/* FIXME: log this */
	}

	return rv;
}

/* Register an Ethernet handler */
eemo_rv eemo_reg_ether_handler(u_short which_eth_type, eemo_ether_handler_fn handler_fn)
{
	eemo_ether_handler* new_handler = NULL;
	eemo_rv rv = ERV_OK;

	/* Check if a handler for the specified type already exists */

	/* RvR: disabled this check, multiple handlers can be registered. Note that
	 *      this does mean that unregistering a handler may unregister the handler
	 *      registered by someone else, so this should only be done when exiting
	 *      the program!
	 *

	if (eemo_find_ether_handler(which_eth_type) != NULL)
	{
		return ERV_HANDLER_EXISTS;
	}
	 */

	/* Create a new handler entry */
	new_handler = (eemo_ether_handler*) malloc(sizeof(eemo_ether_handler));

	if (new_handler == NULL)
	{
		/* Not enough memory */
		return ERV_MEMORY;
	}

	new_handler->which_eth_type = which_eth_type;
	new_handler->handler_fn = handler_fn;

	/* Register the new handler */
	if ((rv = eemo_ll_append(&ether_handlers, (void*) new_handler)) != ERV_OK)
	{
		/* FIXME: log this */
		free(new_handler);
	}

	return rv;
}

/* Unregister an Ethernet handler */
eemo_rv eemo_unreg_ether_handler(u_short which_eth_type)
{
	return eemo_ll_remove(&ether_handlers, &eemo_ether_handler_compare, (void*) &which_eth_type);
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
	eemo_ll_entry* handlers = NULL;
	eemo_ll_entry* handler_it = NULL;
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

	/* See if there are any handlers for this type of packet */
	handlers = eemo_find_ether_handlers(hdr->eth_type);
	handler_it = handlers;

	while (handler_it != NULL)
	{
		eemo_ether_handler* handler = (eemo_ether_handler*) handler_it->elem_data;

		if (handler != NULL)
		{
			eemo_rv handler_rv = ERV_SKIPPED;

			if (handler->handler_fn != NULL)
			{
				eemo_packet_buf* ether_data =
					eemo_pbuf_new(&packet->data[sizeof(eemo_hdr_raw_ether)], packet->len - sizeof(eemo_hdr_raw_ether));

				if (ether_data != NULL)
				{
					handler_rv = (handler->handler_fn)(ether_data, packet_info);

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

		handler_it = handler_it->next;
	}

	eemo_ll_free(&handlers);

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
	/* Clean up the list of Ethernet packet handlers */
	if (eemo_ll_free(&ether_handlers) != ERV_OK)
	{
		ERROR_MSG("Failed to free list of Ethernet handlers");
	}

	INFO_MSG("Uninitialised Ethernet handling");
}

