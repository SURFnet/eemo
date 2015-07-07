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
 * IP packet handling
 */

#ifndef _EEMO_IP_HANDLER_H
#define _EEMO_IP_HANDLER_H

#include "config.h"
#include <pcap.h>
#include <netdb.h>
#include <arpa/inet.h>
#include "eemo.h"
#include "eemo_packet.h"

#define ETHER_IPV4	0x0800
#define ETHER_IPV6	0x86DD

/* IP header definition */
#define IP_VER(ver) ((ver & 0xf0) >> 4)
#define IP_HDRLEN(len) (len & 0x0f)

/* IPv4 header definition */
#define IPV4_DONTFRAG	0x4000
#define IPV4_MOREFRAG	0x2000
#define IPV4_FRAGMASK	0x1fff


#pragma pack(push, 1)
/* IPv4 packet header */
typedef struct
{
	u_char		ip4_ver_hl;	/* header length + version */
	u_char		ip4_tos;	/* type-of-service */
	u_short		ip4_len;	/* total length */
	u_short		ip4_id;		/* packet ID */
	u_short		ip4_ofs;	/* fragment offset */
	u_char		ip4_ttl;	/* time-to-live */
	u_char		ip4_proto;	/* protocol */
	u_short		ip4_chksum;	/* packet checksum */
	u_char		ip4_src[4];	/* source address */
	u_char		ip4_dst[4];	/* destination address */
}
eemo_hdr_ipv4;

/* IPv6 packet header */
typedef struct
{
	u_char		ip6_ver_tc;	/* version + upper 4 bits of traffic class */
	u_char		ip6_tc_fl;	/* lower 4 bits of traffic class + upper 4 bits of flow label */
	u_char		ip6_fl[2];	/* lower 16 bits of flow label */
	u_short		ip6_len;	/* payload length */
	u_char		ip6_next_hdr;	/* next header */
	u_char		ip6_hop_lmt;	/* hop limit */
	u_short		ip6_src[8];	/* source address */
	u_short		ip6_dst[8];	/* destination address */
}
eemo_hdr_ipv6;
#pragma pack(pop)

/* IP packet info */
#define IP_TYPE_V4	4
#define IP_TYPE_V6	6

typedef struct
{
	char 		ip_src[INET6_ADDRSTRLEN];	/* source address */
	char 		ip_dst[INET6_ADDRSTRLEN];	/* destination address */
	unsigned char 	ip_type;			/* protocol v4 or v6 */
	unsigned char 	is_fragment;			/* is this a fragment? */
	unsigned char	more_frags;			/* are there more fragments to follow? */
	u_short 	fragment_ofs;			/* fragment offset */
	u_short		ip_id;				/* IP packet identifier */
	union
	{
		u_int	v4;				/* caution: network byte order! */
		u_short	v6[8];				/* caution: network byte order! */
	}		src_addr;			/* binary source address */
	union
	{
		u_int	v4;				/* caution: network byte order! */
		u_short	v6[8];				/* caution: network byte order! */
	}		dst_addr;			/* binary destination address */
	u_char		ttl;				/* time-to-live (or hop limit for v6) */
	struct timeval	ts;				/* capture timestamp */
	char*		src_as_short;			/* Short AS for source IP */
	char*		src_as_full;			/* Full AS for source IP */
	char*		src_geo_ip;			/* Geo IP info for source IP */
	char*		dst_as_short;			/* Short AS for destination IP */
	char*		dst_as_full;			/* Full AS for destination IP */
	char*		dst_geo_ip;			/* Geo IP info for destination IP */
}
eemo_ip_packet_info;

/* Defines a handler for IP packets */
typedef eemo_rv (*eemo_ip_handler_fn) (const eemo_packet_buf*, eemo_ip_packet_info);

/* Defines an IP handler record */
typedef struct eemo_ip_handler
{
	u_short			which_ip_proto;	/* which IP protocol is handled by this module */
	eemo_ip_handler_fn	handler_fn;	/* handler function */

	/* Administrativia */
	unsigned long		handle;		/* handler handle */
	struct eemo_ip_handler*	next;		/* single LL next element */
}
eemo_ip_handler;

/* Register an IP handler */
typedef eemo_rv (*eemo_reg_ip_handler_fn) (u_short, eemo_ip_handler_fn, unsigned long*);

eemo_rv eemo_reg_ip_handler(u_short which_ip_proto, eemo_ip_handler_fn handler_fn, unsigned long* handle);

/* Unregister an IP handler */
typedef eemo_rv (*eemo_unreg_ip_handler_fn) (unsigned long);

eemo_rv eemo_unreg_ip_handler(unsigned long handle);

/* Initialise IP handling */
eemo_rv eemo_init_ip_handler(void);

/* Clean up */
void eemo_ip_handler_cleanup(void);

#endif /* !_EEMO_IP_HANDLER_H */

