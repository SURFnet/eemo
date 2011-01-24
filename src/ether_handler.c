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

#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "eemo.h"
#include "ether_handler.h"

/* The linked list of Ethernet packet handlers */
eemo_ether_handler* ether_handlers = NULL;

/* Find an Ethernet handler for the specified type */
eemo_ether_handler* eemo_find_ether_handler(u_short which_eth_type)
{
	eemo_ether_handler* current = ether_handlers;

	while (current != NULL)
	{
		if (current->which_eth_type == which_eth_type)
		{
			return current;
		}

		current = current->next;
	}

	return NULL;
}

/* Register an Ethernet handler */
eemo_rv eemo_reg_ether_handler(u_short which_eth_type, eemo_ether_handler_fn handler_fn)
{
	/* Check if a handler for the specified type already exists */
	if (eemo_find_ether_handler(which_eth_type) != NULL)
	{
		/* A handler for this type has already been registered */
		return ERV_HANDLER_EXISTS;
	}

	/* Create a new handler entry */
	eemo_ether_handler* new_handler = (eemo_ether_handler*) malloc(sizeof(eemo_ether_handler));

	if (new_handler == NULL)
	{
		/* Not enough memory */
		return ERV_MEMORY;
	}

	new_handler->which_eth_type = which_eth_type;
	new_handler->handler_fn = handler_fn;
	new_handler->next = NULL;

	/* Register the new handler */
	eemo_ether_handler* current = ether_handlers;

	if (current == NULL)
	{
		/* This is the first registered handler */
		ether_handlers = new_handler;
	}
	else
	{
		/* Append this handler to the list */
		while (current->next != NULL) current = current->next;

		current->next = new_handler;
	}

	return ERV_OK;
}

/* Unregister an Ethernet handler */
eemo_rv eemo_unreg_ether_handler(u_short which_eth_type)
{
	eemo_ether_handler* current = ether_handlers;
	eemo_ether_handler* prev = NULL;

	while (current != NULL)
	{
		if (current->which_eth_type == which_eth_type)
		{
			/* Found the handler to delete, remove it from the chain */
			if (prev == NULL)
			{
				ether_handlers = current->next;
			}
			else
			{
				prev->next = current->next;
			}

			free(current);

			return ERV_OK;
		}

		prev = current;
		current = current->next;
	}

	/* No such handler exists */
	return ERV_NO_HANDLER;
}

/* Convert the packet from network to host byte order */
void eemo_ether_ntoh(eemo_hdr_raw_ether* hdr)
{
	hdr->eth_type = ntohs(hdr->eth_type);
}

/* Handle an Ethernet packet */
eemo_rv eemo_handle_ether_packet(eemo_packet_buf* packet)
{
	/* Check the packet size */
	if (packet->len < sizeof(eemo_hdr_raw_ether))
	{
		/* Packet is malformed */
		return ERV_MALFORMED;
	}

	/* Take the header from the packet */
	eemo_hdr_raw_ether* hdr = (eemo_hdr_raw_ether*) packet->data;

	/* Convert to host byte order */
	eemo_ether_ntoh(hdr);

	/* Retrieve source and destination from the packet */
	eemo_ether_packet_info packet_info;

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

	/* See if there is a handler for this type of packet */
	eemo_ether_handler* handler = eemo_find_ether_handler(hdr->eth_type);

	if ((handler != NULL) && (handler->handler_fn != NULL))
	{
		eemo_packet_buf* ether_data = 
			eemo_pbuf_new(&packet->data[sizeof(eemo_hdr_raw_ether)], packet->len - sizeof(eemo_hdr_raw_ether));

		if (ether_data == NULL)
		{
			return ERV_MEMORY;
		}

		eemo_rv rv = (handler->handler_fn)(ether_data, packet_info);

		eemo_pbuf_free(ether_data);

		return rv;
	}

	return ERV_SKIPPED;
}

/* Clean up */
void eemo_ether_handler_cleanup(void)
{
	/* Clean up the list of Ethernet packet handlers */
	eemo_ether_handler* to_delete = NULL;
	eemo_ether_handler* current = ether_handlers;
	ether_handlers = NULL;

	while (current != NULL)
	{
		to_delete = current;
		current = current->next;

		to_delete->next = NULL;
		free(to_delete);
	}
}

