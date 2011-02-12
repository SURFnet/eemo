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
 * The Extensible IP Monitor (EEMO)
 * UDP packet handling
 */

#ifndef _EEMO_UDP_HANDLER_H
#define _EEMO_UDP_HANDLER_H

#include "config.h"
#include <pcap.h>
#include <netdb.h>
#include "eemo.h"
#include "eemo_packet.h"
#include "ip_handler.h"

#define IP_UDP	0x0011

#pragma pack(push, 1)
/* UDP packet header */
typedef struct
{
	u_short	udp_srcport;	/* source port */
	u_short udp_dstport;	/* destination port */
	u_short	udp_len;	/* datagram length */
	u_short udp_chksum;	/* checksum */
}
eemo_hdr_udp;
#pragma pack(pop)

/* Defines a handler for UDP packets */
typedef eemo_rv (*eemo_udp_handler_fn) (eemo_packet_buf*, eemo_ip_packet_info, u_short srcport, u_short dstport);

/* Defines an UDP handler record */
#define UDP_ANY_PORT		0

typedef struct eemo_udp_handler
{
	u_short				srcport;	/* which source port, 0 = any */
	u_short				dstport;	/* which destination port, 0 = any */
	eemo_udp_handler_fn		handler_fn;	/* handler function */
	struct eemo_udp_handler*	next;		/* next handler in the list */
}
eemo_udp_handler;

/* Register an UDP handler */
eemo_rv eemo_reg_udp_handler(u_short srcport, u_short dstport, eemo_udp_handler_fn handler_fn);

/* Unregister an UDP handler */
eemo_rv eemo_unreg_udp_handler(u_short srcport, u_short dstport);

/* Initialise UDP handling */
eemo_rv eemo_init_udp_handler(void);

/* Clean up */
void eemo_udp_handler_cleanup(void);

#endif /* !_EEMO_UDP_HANDLER_H */

