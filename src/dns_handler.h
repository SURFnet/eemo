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

#include "config.h"
#include <pcap.h>
#include <netdb.h>
#include "eemo.h"
#include "eemo_packet.h"
#include "dns_parser.h"
#include "ip_handler.h"

/* Defines a DNS query handler */
typedef eemo_rv (*eemo_dns_handler_fn) (eemo_ip_packet_info, int /*is_tcp*/, const eemo_dns_packet*);

/* Defines a DNS handler record */
typedef struct eemo_dns_handler
{
	eemo_dns_handler_fn		handler_fn;	/* handler function */

	/* Administrativia */
	unsigned long			handle;		/* handler handle */
	struct eemo_dns_handler*	next;		/* single LL next element */
}
eemo_dns_handler;

/* Register a DNS handler */
typedef eemo_rv (*eemo_reg_dns_handler_fn) (eemo_dns_handler_fn, unsigned long, unsigned long*);

eemo_rv eemo_reg_dns_handler(eemo_dns_handler_fn handler_fn, unsigned long parser_flags, unsigned long* handle);

/* Unregister a DNS query handler */
typedef eemo_rv (*eemo_unreg_dns_handler_fn) (unsigned long);

eemo_rv eemo_unreg_dns_handler(unsigned long handle);

/* Initialise DNS handling */
eemo_rv eemo_init_dns_handler(void);

/* Clean up */
void eemo_dns_handler_cleanup(void);

#endif /* !_EEMO_DNS_QHANDLER_H */

