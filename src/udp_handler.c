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
 * UDP packet handling
 */

#include <stdlib.h>
#include <string.h>
#include "eemo.h"
#include "ip_handler.h"
#include "udp_handler.h"

/* The linked list of UDP packet handlers */
eemo_udp_handler* udp_handlers = NULL;

/* Find an IP handler for the specified type */
eemo_udp_handler* eemo_find_udp_handler(u_short srcport, u_short dstport)
{
	eemo_udp_handler* current = udp_handlers;

	while (current != NULL)
	{
		if (((current->srcport == UDP_ANY_PORT) || (current->srcport == srcport)) &&
		    ((current->dstport == UDP_ANY_PORT) || (current->dstport == dstport)))
		{
			return current;
		}

		current = current->next;
	}

	return NULL;
}

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
	eemo_udp_handler* handler = eemo_find_udp_handler(hdr->udp_srcport, hdr->udp_dstport);

	if ((handler != NULL) && (handler->handler_fn != NULL))
	{
		eemo_rv rv = ERV_OK;
		eemo_packet_buf* udp_data = 
			eemo_pbuf_new(&packet->data[sizeof(eemo_hdr_udp)], packet->len - sizeof(eemo_hdr_udp));

		if (udp_data == NULL)
		{
			return ERV_MEMORY;
		}

		rv = (handler->handler_fn)(udp_data, ip_info, hdr->udp_srcport, hdr->udp_dstport);

		eemo_pbuf_free(udp_data);

		return rv;
	}

	return ERV_SKIPPED;
}

/* Register an UDP handler */
eemo_rv eemo_reg_udp_handler(u_short srcport, u_short dstport, eemo_udp_handler_fn handler_fn)
{
	eemo_udp_handler* new_handler = NULL;

	/* Check if a handler for the specified ports already exists */
	if (eemo_find_udp_handler(srcport, dstport) != NULL)
	{
		/* A handler for this type has already been registered */
		return ERV_HANDLER_EXISTS;
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
	new_handler->next = NULL;

	/* Register the new handler */
	eemo_udp_handler* current = udp_handlers;

	if (current == NULL)
	{
		/* This is the first registered handler */
		udp_handlers = new_handler;
	}
	else
	{
		/* Append this handler to the list */
		while (current->next != NULL) current = current->next;

		current->next = new_handler;
	}

	return ERV_OK;
}

/* Unregister an UDP handler */
eemo_rv eemo_unreg_udp_handler(u_short srcport, u_short dstport)
{
	eemo_udp_handler* current = udp_handlers;
	eemo_udp_handler* prev = NULL;

	while (current != NULL)
	{
		if (((current->srcport == UDP_ANY_PORT) || (current->srcport == srcport)) &&
		    ((current->dstport == UDP_ANY_PORT) || (current->dstport == dstport)))
		{
			/* Found the handler to delete, remove it from the chain */
			if (prev == NULL)
			{
				udp_handlers = current->next;
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

/* Initialise IP handling */
eemo_rv eemo_init_udp_handler(void)
{
	/* Register UDP packet handler */
	return eemo_reg_ip_handler(IP_UDP, &eemo_handle_udp_packet);
}

/* Clean up */
void eemo_udp_handler_cleanup(void)
{
	/* Clean up the list of UDP packet handlers */
	eemo_udp_handler* to_delete = NULL;
	eemo_udp_handler* current = udp_handlers;
	udp_handlers = NULL;

	while (current != NULL)
	{
		to_delete = current;
		current = current->next;

		to_delete->next = NULL;
		free(to_delete);
	}

	/* Unregister the IP handler for UDP packets */
	eemo_unreg_ip_handler(IP_UDP);
}

