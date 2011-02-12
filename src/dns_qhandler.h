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
 * DNS query packet handling
 */

#ifndef _EEMO_DNS_QHANDLER_H
#define _EEMO_DNS_QHANDLER_H

#include <pcap.h>
#include <netdb.h>
#include "eemo.h"
#include "eemo_packet.h"
#include "ip_handler.h"

#pragma pack(push, 1)
/* DNS query packet header */
typedef struct
{
	u_short	dns_qid;	/* query ID */
	u_short dns_flags;	/* query flags */;
	u_short dns_qdcount;	/* number of queries in packet */
	u_short	dns_ancount;	/* number of answers in packet */
	u_short	dns_nscount;	/* number of authority answers in packet */
	u_short	dns_arcount;	/* number of additional records in packet */
}
eemo_hdr_dns;
#pragma pack(pop)

/* Defines a DNS query handler */
typedef eemo_rv (*eemo_dns_qhandler_fn) (eemo_ip_packet_info, u_short /*qclass*/, u_short /*qtype*/, u_short /*flags*/, char* /*qname*/, int /*is_tcp*/);

/* Defines a DNS query handler record */
typedef struct eemo_dns_qhandler
{
	u_short				qclass;		/* query class */
	u_short				qtype;		/* query type */
	eemo_dns_qhandler_fn		handler_fn;	/* handler function */
	struct eemo_dns_qhandler*	next;		/* next handler */
}
eemo_dns_qhandler;

/* Register a DNS query handler */
eemo_rv eemo_reg_dns_qhandler(u_short qclass, u_short qtype, eemo_dns_qhandler_fn handler_fn);

/* Unregister a DNS query handler */
eemo_rv eemo_unreg_dns_qhandler(u_short qclass, u_short qtype);

/* Initialise DNS handling */
eemo_rv eemo_init_dns_qhandler(void);

/* Clean up */
void eemo_dns_handler_cleanup(void);

#endif /* !_EEMO_DNS_QHANDLER_H */

