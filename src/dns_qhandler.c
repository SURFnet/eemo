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

#include <stdlib.h>
#include <string.h>
#include "eemo.h"
#include "udp_handler.h"
#include "tcp_handler.h"
#include "dns_qhandler.h"
#include "dns_types.h"

/* The linked list of DNQ query handlers */
eemo_dns_qhandler* dns_qhandlers = NULL;

/* Find an IP handler for the specified type */
eemo_dns_qhandler* eemo_find_dns_qhandler(u_short qclass, u_short qtype)
{
	eemo_dns_qhandler* current = dns_qhandlers;

	while (current != NULL)
	{
		if (((current->qclass == DNS_QCLASS_UNSPECIFIED) || (current->qclass == qclass)) &&
		    ((current->qtype == DNS_QTYPE_UNSPECIFIED) || (current->qtype == qtype)))
		{
			return current;
		}

		current = current->next;
	}

	return NULL;
}

/* Convert DNS packet header to host byte order */
void eemo_dns_ntoh(eemo_hdr_dns* hdr)
{
	hdr->dns_qid		= ntohs(hdr->dns_qid);
	hdr->dns_flags		= ntohs(hdr->dns_flags);
	hdr->dns_qdcount	= ntohs(hdr->dns_qdcount);
	hdr->dns_ancount	= ntohs(hdr->dns_ancount);
	hdr->dns_nscount	= ntohs(hdr->dns_nscount);
	hdr->dns_arcount	= ntohs(hdr->dns_arcount);
}

/* Handle DNS payload */
eemo_rv eemo_handle_dns_qpayload(eemo_packet_buf* packet, eemo_ip_packet_info ip_info, int is_tcp)
{
	eemo_hdr_dns* 		hdr 			= NULL;
	size_t 			ofs 			= 0;
	size_t 			qname_len 		= 0;
	size_t 			qdata_len 		= packet->len - sizeof(eemo_hdr_dns);
	size_t 			qname_ofs 		= 0;
	u_char* 		qdata 			= NULL;
	int 			root_label_found 	= 0;
	char* 			query_name 		= NULL;
	eemo_dns_qhandler* 	handler 		= NULL;
	u_short			qclass			= DNS_QCLASS_UNSPECIFIED;
	u_short			qtype			= DNS_QTYPE_UNSPECIFIED;

	/* Check minimum length */
	if (packet->len < sizeof(eemo_hdr_dns))
	{
		/* UDP packet is malformed */
		return ERV_MALFORMED;
	}

	qdata = &packet->data[sizeof(eemo_hdr_dns)];

	/* Take the header from the packet */
	hdr = (eemo_hdr_dns*) packet->data;

	/* Convert the header to host byte order */
	eemo_dns_ntoh(hdr);

	/* Parse the DNS packet */
	if (FLAG_SET(hdr->dns_flags, DNS_QRFLAG))
	{
		/* This is a response packet(!) */
		return ERV_SKIPPED;
	}

	if (((DNS_OPCODE(hdr->dns_flags) != 0) && (DNS_OPCODE(hdr->dns_flags) != 1)) ||
	      FLAG_SET(hdr->dns_flags, DNS_AAFLAG) ||
	      FLAG_SET(hdr->dns_flags, DNS_TCFLAG) ||
	      FLAG_SET(hdr->dns_flags, DNS_RAFLAG) ||
	      (DNS_RCODE(hdr->dns_flags) != 0) ||
	      (hdr->dns_qdcount != 1) || /* according to Alan Clegg, *everybody* does it this way ;-) */
	      (hdr->dns_ancount > 0) ||
	      (hdr->dns_nscount > 0) ||
	      (hdr->dns_arcount > 1)) /* has to accept 1 for EDNS buffer size */
	{
		return ERV_MALFORMED;
	}

	/* Determine the length of the query name */
	ofs = 0;

	do
	{
		if (qdata[ofs] == 0)
		{
			root_label_found = 1;
			break;
		}

		qname_len += qdata[ofs] + 1;
		ofs += qdata[ofs];
	}
	while (++ofs < qdata_len);

	if (!root_label_found)
	{
		return ERV_MALFORMED;
	}
	
	qname_len++; /* space for \0 */
	query_name = (char*) malloc(qname_len * sizeof(char));
	memset(query_name, 0, qname_len);

	/* Retrieve the query name */
	ofs = 0;

	do
	{
		int elem_len = qdata[ofs++];

		if (elem_len == 0) break; /* root label */

		while ((elem_len > 0) && (ofs < qdata_len))
		{
			query_name[qname_ofs++] = qdata[ofs++];
			elem_len--;
		}

		query_name[qname_ofs++] = '.';
	}
	while (ofs < qdata_len);

	/* Retrieve the query type and class */
	if ((qdata_len - ofs) < 4)
	{
		free(query_name);

		return ERV_MALFORMED;
	}

	qtype = ntohs(*((u_short*) &qdata[ofs]));
	ofs += 2;
	qclass = ntohs(*((u_short*) &qdata[ofs]));

	/* See if there is a handler given the source and destination port for this packet */
	handler = eemo_find_dns_qhandler(qclass, qtype); 

	if ((handler != NULL) && (handler->handler_fn != NULL))
	{
		eemo_rv rv = (handler->handler_fn)(ip_info, qclass, qtype, hdr->dns_flags, query_name, is_tcp);

		free(query_name);

		return rv;
	}

	return ERV_SKIPPED;
}

/* Handle a UDP DNS packet */
eemo_rv eemo_handle_dns_udp_qpacket(eemo_packet_buf* packet, eemo_ip_packet_info ip_info, u_short srcport, u_short dstport)
{
	return eemo_handle_dns_qpayload(packet, ip_info, 0);
}

/* Handle a TCP DNS packet */
eemo_rv eemo_handle_dns_tcp_qpacket(eemo_packet_buf* packet, eemo_ip_packet_info ip_info, eemo_tcp_packet_info tcp_info)
{
	eemo_packet_buf* dns_data = NULL;
	eemo_rv rv = ERV_OK;

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
	u_short dns_length = ntohs(*((u_short*) packet->data));

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

	rv = eemo_handle_dns_qpayload(dns_data, ip_info, 1);

	eemo_pbuf_free(dns_data);

	return rv;
}

/* Register an DNS handler */
eemo_rv eemo_reg_dns_qhandler(u_short qclass, u_short qtype, eemo_dns_qhandler_fn handler_fn)
{
	eemo_dns_qhandler* new_handler = NULL;

	/* Check if a handler for the specified ports already exists */
	if (eemo_find_dns_qhandler(qclass, qtype) != NULL)
	{
		/* A handler for this type has already been registered */
		return ERV_HANDLER_EXISTS;
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
	new_handler->next = NULL;

	/* Register the new handler */
	eemo_dns_qhandler* current = dns_qhandlers;

	if (current == NULL)
	{
		/* This is the first registered handler */
		dns_qhandlers = new_handler;
	}
	else
	{
		/* Append this handler to the list */
		while (current->next != NULL) current = current->next;

		current->next = new_handler;
	}

	return ERV_OK;
}

/* Unregister an DNS handler */
eemo_rv eemo_unreg_dns_qhandler(u_short qclass, u_short qtype)
{
	eemo_dns_qhandler* current = dns_qhandlers;
	eemo_dns_qhandler* prev = NULL;

	while (current != NULL)
	{
		if (((current->qclass == DNS_QCLASS_UNSPECIFIED) || (current->qclass == qclass)) &&
		    ((current->qtype == DNS_QTYPE_UNSPECIFIED) || (current->qtype == qtype)))
		{
			/* Found the handler to delete, remove it from the chain */
			if (prev == NULL)
			{
				dns_qhandlers = current->next;
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
eemo_rv eemo_init_dns_qhandler(void)
{
	eemo_rv rv = ERV_OK;

	/* Register UDP packet handler */
	rv = eemo_reg_udp_handler(UDP_ANY_PORT, DNS_PORT, &eemo_handle_dns_udp_qpacket);

	if (rv != ERV_OK)
	{
		return rv;
	}

	/* Register DNS packet handler */
	rv = eemo_reg_tcp_handler(TCP_ANY_PORT, DNS_PORT, &eemo_handle_dns_tcp_qpacket);

	if (rv != ERV_OK)
	{
		eemo_unreg_udp_handler(UDP_ANY_PORT, DNS_PORT);
		
		return rv;
	}

	return rv;
}

/* Clean up */
void eemo_dns_qhandler_cleanup(void)
{
	/* Clean up the list of TCP packet handlers */
	eemo_dns_qhandler* to_delete = NULL;
	eemo_dns_qhandler* current = dns_qhandlers;
	dns_qhandlers = NULL;

	while (current != NULL)
	{
		to_delete = current;
		current = current->next;

		to_delete->next = NULL;
		free(to_delete);
	}

	/* Unregister the DNS UDP and TCP handler */
	eemo_unreg_udp_handler(UDP_ANY_PORT, DNS_PORT);
	eemo_unreg_tcp_handler(TCP_ANY_PORT, DNS_PORT);
}

