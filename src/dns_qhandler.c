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
#include "eemo_list.h"
#include "eemo_log.h"
#include "udp_handler.h"
#include "tcp_handler.h"
#include "dns_qhandler.h"
#include "dns_types.h"

/* The linked list of DNS query handlers */
static eemo_ll_entry* dns_qhandlers = NULL;

/* DNS query handler entry comparison type */
typedef struct
{
	u_short qclass;
	u_short qtype;
}
eemo_dns_qhandler_comp_t;

/* DNS query handler entry comparison */
int eemo_dns_qhandler_compare(void* elem_data, void* comp_data)
{
	eemo_dns_qhandler* elem = (eemo_dns_qhandler*) elem_data;
	eemo_dns_qhandler_comp_t* comp = (eemo_dns_qhandler_comp_t*) comp_data;

	if ((elem_data == NULL) || (comp_data == NULL))
	{
		return 0;
	}

	if (((elem->qclass == DNS_QCLASS_UNSPECIFIED) || (elem->qclass == comp->qclass)) &&
	    ((elem->qtype == DNS_QTYPE_UNSPECIFIED) || (elem->qtype == comp->qtype)))
	{
		return 1;
	}

	return 0;
}

/* DNS query handler entry comparison with exact match */
int eemo_dns_qhandler_compare_exact(void* elem_data, void* comp_data)
{
	eemo_dns_qhandler* elem = (eemo_dns_qhandler*) elem_data;
	eemo_dns_qhandler_comp_t* comp = (eemo_dns_qhandler_comp_t*) comp_data;

	if ((elem_data == NULL) || (comp_data == NULL))
	{
		return 0;
	}

	if ((elem->qclass == comp->qclass) && (elem->qtype == comp->qtype))
	{
		return 1;
	}

	return 0;
}

/* DNS query handler entry cloning */
void* eemo_dns_qhandler_clone(const void* elem_data)
{
	const eemo_dns_qhandler* elem = (const eemo_dns_qhandler*) elem_data;
	eemo_dns_qhandler* new_elem = NULL;

	if (elem_data == NULL)
	{
		return NULL;
	}

	new_elem = (eemo_dns_qhandler*) malloc(sizeof(eemo_dns_qhandler));

	if (new_elem != NULL)
	{
		/* Clone element, no deep copy required in this case */
		memcpy(new_elem, elem, sizeof(eemo_dns_qhandler));
	}

	return (void*) new_elem;
}

/* Find DNS query handlers for the specified type */
eemo_ll_entry* eemo_find_dns_qhandlers(u_short qclass, u_short qtype)
{
	eemo_ll_entry* rv = NULL;
	eemo_dns_qhandler_comp_t comp;

	comp.qclass = qclass;
	comp.qtype = qtype;

	eemo_ll_find_multi(dns_qhandlers, &rv, &eemo_dns_qhandler_compare, &comp, &eemo_dns_qhandler_clone);

	return rv;
}

/* Check if a handler exists for the specified type/class */
int eemo_dns_qhandler_exists(u_short qclass, u_short qtype)
{
	void* rv = NULL;
	eemo_dns_qhandler_comp_t comp;

	comp.qclass = qclass;
	comp.qtype = qtype;

	return (eemo_ll_find(dns_qhandlers, &rv, &eemo_dns_qhandler_compare_exact, &comp) != ERV_NOT_FOUND);
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
	eemo_ll_entry* 		handlers 		= NULL;
	eemo_ll_entry*		handler_it		= NULL;
	u_short			qclass			= DNS_QCLASS_UNSPECIFIED;
	u_short			qtype			= DNS_QTYPE_UNSPECIFIED;
	eemo_rv			rv			= ERV_SKIPPED;

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

	/* See if there are query handlers for this query class & type */
	handlers = eemo_find_dns_qhandlers(qclass, qtype); 
	handler_it = handlers;

	while (handler_it != NULL)
	{
		eemo_dns_qhandler* handler = (eemo_dns_qhandler*) handler_it->elem_data;

		if (handler != NULL)
		{
			eemo_rv handler_rv = ERV_SKIPPED;
			
			if (handler->handler_fn != NULL)
			{
				handler_rv = (handler->handler_fn)(ip_info, qclass, qtype, hdr->dns_flags, query_name, is_tcp);
			}

			if (rv != ERV_HANDLED)
			{
				rv = handler_rv;
			}
		}

		handler_it = handler_it->next;
	}

	eemo_ll_free(&handlers);
	free(query_name);

	return rv;
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

	rv = eemo_handle_dns_qpayload(dns_data, ip_info, 1);

	eemo_pbuf_free(dns_data);

	return rv;
}

/* Register an DNS handler */
eemo_rv eemo_reg_dns_qhandler(u_short qclass, u_short qtype, eemo_dns_qhandler_fn handler_fn)
{
	eemo_dns_qhandler* new_handler = NULL;
	eemo_rv rv = ERV_OK;

	/* Check if a handler for the specified ports already exists */

	/* RvR: disabled this check, multiple handlers can be registered. Note that
	 *      this does mean that unregistering a handler may unregister the handler
	 *      registered by someone else, so this should only be done when exiting
	 *      the program!
	 *
	if (eemo_dns_qhandler_exists(qclass, qtype))
	{
		return ERV_HANDLER_EXISTS;
	}
	 */

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

	/* Register the new handler */
	if ((rv = eemo_ll_append(&dns_qhandlers, (void*) new_handler)) != ERV_OK)
	{
		free(new_handler);
	}

	return rv;
}

/* Unregister an DNS handler */
eemo_rv eemo_unreg_dns_qhandler(u_short qclass, u_short qtype)
{
	eemo_dns_qhandler_comp_t comp;
	
	comp.qclass = qclass;
	comp.qtype = qtype;

	return eemo_ll_remove(&dns_qhandlers, &eemo_dns_qhandler_compare, &comp);
}

/* Initialise DNS query handling */
eemo_rv eemo_init_dns_qhandler(void)
{
	eemo_rv rv = ERV_OK;
	dns_qhandlers = NULL;

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

	INFO_MSG("Initialised DNS query handling");

	return rv;
}

/* Clean up */
void eemo_dns_qhandler_cleanup(void)
{
	/* Clean up list of DNS query handlers */
	if (eemo_ll_free(&dns_qhandlers) != ERV_OK)
	{
		ERROR_MSG("Failed to free list of DNS query handlers");
	}

	/* Unregister the DNS UDP and TCP handler */
	eemo_unreg_udp_handler(UDP_ANY_PORT, DNS_PORT);
	eemo_unreg_tcp_handler(TCP_ANY_PORT, DNS_PORT);

	INFO_MSG("Uninitialised DNS query handling");
}

