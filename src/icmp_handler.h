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
 * ICMP packet handling
 */

#ifndef _EEMO_ICMP_HANDLER_H
#define _EEMO_ICMP_HANDLER_H

#include "config.h"
#include <pcap.h>
#include <netdb.h>
#include "eemo.h"
#include "eemo_packet.h"
#include "ip_handler.h"

#define IP_ICMPv4		1
#define IP_ICMPv6		58

#pragma pack(push, 1)
/* ICMP packet header; this header is the same for ICMPv4 and ICMPv6 */
typedef struct
{
	u_char	icmp_type;	/* ICMP message type */
	u_char	icmp_code;	/* ICMP message code */
	u_short	icmp_chksum;	/* ICMP checksum */
}
eemo_hdr_icmp;
#pragma pack(pop)

/* Defines an ICMP packet handler */
typedef eemo_rv (*eemo_icmp_handler_fn) (eemo_packet_buf*, eemo_ip_packet_info, u_char /*type*/, u_char /*code*/); 

/* Defines an ICMP handler record */
typedef struct eemo_icmp_handler
{
	u_char			icmp_type;	/* ICMP message type handled */
	u_char			icmp_code;	/* ICMP message code handled */
	unsigned char		iptype;		/* IP type (v4 or v6) */
	eemo_icmp_handler_fn	handler_fn;	/* Handler function */

	/* Administrativia */
	unsigned long		handle;		/* Handler handle */
	struct eemo_icmp_handler* next;		/* Single LL next element */
}
eemo_icmp_handler;

/* Register an ICMP handler */
typedef eemo_rv (*eemo_reg_icmp_handler_fn) (u_char, u_char, unsigned char, eemo_icmp_handler_fn, unsigned long*);

eemo_rv eemo_reg_icmp_handler(u_char icmp_type, u_char icmp_code, unsigned char iptype, eemo_icmp_handler_fn handler_fn, unsigned long* handle);

/* Unregister an ICMP handler */
typedef eemo_rv (*eemo_unreg_icmp_handler_fn) (unsigned long);

eemo_rv eemo_unreg_icmp_handler(unsigned long handle);

/* Initialise ICMP handling */
eemo_rv eemo_init_icmp_handler(void);

/* Clean up */
void eemo_icmp_handler_cleanup(void);

#endif /* !_EEMO_ICMP_HANDLER_H */

