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
 * Ethernet packet handling
 */

#ifndef _EEMO_ETHER_HANDLER_H
#define _EEMO_ETHER_HANDLER_H

#include <pcap.h>
#include "eemo.h"
#include "eemo_packet.h"

/* Raw Ethernet packet header */
#pragma pack(push, 1)
typedef struct
{
	u_char 	eth_dest[6];
	u_char	eth_source[6];
	u_short	eth_type;
}
eemo_hdr_raw_ether;
#pragma pack(pop)

/* Ethernet packet info */
typedef struct
{
	char eth_source[18];
	char eth_dest[18];
}
eemo_ether_packet_info;

/* Defines a handler for raw Ethernet packets */
typedef eemo_rv (*eemo_ether_handler_fn) (eemo_packet_buf*, eemo_ether_packet_info);

/* Defines an Ethernet handler record */
typedef struct eemo_ether_handler
{
	u_short				which_eth_type; /* which Ethernet types are handled by this module */
	eemo_ether_handler_fn		handler_fn;	/* handler function */
	struct eemo_ether_handler*	next;		/* next handler in the list */
}
eemo_ether_handler;

/* Register an Ethernet handler */
eemo_rv eemo_reg_ether_handler(u_short which_eth_type, eemo_ether_handler_fn handler_fn);

/* Unregister an Ethernet handler */
eemo_rv eemo_unreg_ether_handler(u_short which_eth_type);

/* Handle an Ethernet packet */
eemo_rv eemo_handle_ether_packet(eemo_packet_buf* packet);

/* Clean up */
void eemo_ether_handler_cleanup(void);

#endif /* !_EEMO_ETHER_HANDLER_H */

