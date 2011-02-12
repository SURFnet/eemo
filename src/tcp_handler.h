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
 * TCP packet handling
 */

#ifndef _EEMO_TCP_HANDLER_H
#define _EEMO_TCP_HANDLER_H

#include "config.h"
#include <pcap.h>
#include <netdb.h>
#include "eemo.h"
#include "eemo_packet.h"
#include "ip_handler.h"

#define IP_TCP	0x0006

#pragma pack(push, 1)
/* TCP packet header */
typedef struct
{
	u_short	tcp_srcport;	/* source port */
	u_short tcp_dstport;	/* destination port */
	u_int   tcp_seqno;	/* sequence number */
	u_int	tcp_ackno;	/* acknowledgement number */
	u_char	tcp_ofs;	/* data offset */
	u_char	tcp_flags;	/* flags */
	u_short	tcp_win;	/* window size */
	u_short tcp_chksum;	/* checksum */
	u_short	tcp_urgent;	/* urgent pointer */
}
eemo_hdr_tcp;
#pragma pack(pop)

/* TCP flags */
#define TCP_CWR		0x80
#define TCP_ECE		0x40
#define TCP_URG		0x20
#define TCP_ACK		0x10
#define TCP_PSH		0x08
#define TCP_RST		0x04
#define TCP_SYN		0x02
#define TCP_FIN		0x01

/* TCP packet information */
typedef struct
{
	u_short	srcport;	/* source port */
	u_short	dstport;	/* destination port */
	u_int	seqno;		/* sequence number */
	u_int	ackno;		/* acknowledgement number */
	u_char	flags;		/* flags */
	u_short	winsize;	/* window size */
	u_short	urgptr;		/* urgent pointer */
}
eemo_tcp_packet_info;

/* Defines a handler for TCP packets */
typedef eemo_rv (*eemo_tcp_handler_fn) (eemo_packet_buf*, eemo_ip_packet_info, eemo_tcp_packet_info);

/* Defines an TCP handler record */
#define TCP_ANY_PORT		0

typedef struct eemo_tcp_handler
{
	u_short				srcport;	/* which source port, 0 = any */
	u_short				dstport;	/* which destination port, 0 = any */
	eemo_tcp_handler_fn		handler_fn;	/* handler function */
	struct eemo_tcp_handler*	next;		/* next handler in the list */
}
eemo_tcp_handler;

/* Register an TCP handler */
eemo_rv eemo_reg_tcp_handler(u_short srcport, u_short dstport, eemo_tcp_handler_fn handler_fn);

/* Unregister an TCP handler */
eemo_rv eemo_unreg_tcp_handler(u_short srcport, u_short dstport);

/* Initialise TCP handling */
eemo_rv eemo_init_tcp_handler(void);

/* Clean up */
void eemo_tcp_handler_cleanup(void);

#endif /* !_EEMO_TCP_HANDLER_H */

