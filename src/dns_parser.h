/*
 * Copyright (c) 2010-2015 SURFnet bv
 * Copyright (c) 2015 Roland van Rijswijk-Deij
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
 * The Extensible IP Monitor (EEMO)
 * DNS packet parsing
 */

#ifndef _EEMO_DNS_PARSER_H
#define _EEMO_DNS_PARSER_H

#include "config.h"
#include "utlist.h"
#include "eemo.h"
#include "eemo_packet.h"
#include "dns_types.h"
#include <arpa/inet.h>

/* EDNS0 field macros */
#define EDNS0_VERSION(rr) 	((rr->ttl & 0xff000000) >> 24)
#define EDNS0_EXT_RCODE(rr)	((rr->ttl & 0x00ff0000) >> 16)
#define EDNS0_BUFSIZE(rr)	(rr->class)
#define EDNS0_DO_SET(rr)	((rr->ttl & 0x00008000) == 0x00008000)

/* Query type */
typedef struct eemo_dns_query
{
	char*			qname;
	unsigned short		qtype;
	unsigned short 		qclass;

	/* Administrativia */
	struct eemo_dns_query*	next;
}
eemo_dns_query;

/* TXT RDATA type */
typedef struct txt_rdata
{
	char*			string;
	struct txt_rdata*	next;
}
txt_rdata;

/* Generic DNS RR type */
typedef struct eemo_dns_rr
{
	char*			name;
	unsigned short		type;
	unsigned short		class;
	int			ttl;
	unsigned short		rdata_len;	/* Size 0 indicates that the data has been parsed or is not present */
	void*			rdata;
	char*			rdata_txt;

	/* Administrativia */
	struct eemo_dns_rr*	next;
}
eemo_dns_rr;

/* DNS packet type */
typedef struct eemo_dns_packet
{
	unsigned char		is_valid;
	unsigned char		is_partial;
	unsigned short		srcport;
	unsigned short		dstport;
	unsigned short 		query_id;
	unsigned short		udp_len;
	int			is_fragmented;
	unsigned char		qr_flag;
	unsigned char		aa_flag;
	unsigned char		tc_flag;
	unsigned char		ra_flag;
	unsigned char		rd_flag;
	unsigned char		opcode;
	unsigned char		rcode;
	eemo_dns_query*		questions;
	eemo_dns_rr*		answers;
	eemo_dns_rr*		authorities;
	eemo_dns_rr*		additionals;
	unsigned short		ans_count;
	unsigned short		aut_count;
	unsigned short		add_count;
	int			has_edns0;
	int			edns0_version;
	unsigned short		edns0_max_size;
	unsigned char		edns0_do;
	int			has_edns0_client_subnet;
	int			edns0_client_subnet_src_scope;
	int			edns0_client_subnet_res_scope;
	char			edns0_client_subnet_ip[INET6_ADDRSTRLEN];
	int			has_edns0_exp_opt;
	char*			edns0_client_subnet_as_short;
	char*			edns0_client_subnet_as_full;
	char*			edns0_client_subnet_geo_ip;
}
eemo_dns_packet;

/* Parser flags */
#define PARSE_NONE			0x00000000	/* Do not performing any parsing on DNS packets */
#define PARSE_QUERY			0x00000001	/* Parse the data in query messages */
#define PARSE_RESPONSE			0x00000002	/* Parse the data in response messages */
#define PARSE_RDATA_TO_STR		0x00000004	/* Convert parsed query/response RDATA to a string representation */
#define PARSE_CANONICALIZE_NAME		0x00000008	/* Canonicalize all names to lower case */

/* Parse a DNS packet */
eemo_rv eemo_parse_dns_packet(const eemo_packet_buf* packet, eemo_dns_packet* dns_packet, unsigned long parser_flags, unsigned short udp_len, int is_fragmented);

/* Free a DNS packet structure */
void eemo_free_dns_packet(eemo_dns_packet* dns_packet);

#endif /* !_EEMO_DNS_PARSER_H */

