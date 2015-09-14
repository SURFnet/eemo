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
 * The Extensible Ethernet Monitor (EEMO)
 * Raw packet handling
 */

#ifndef _EEMO_RAW_HANDLER_H
#define _EEMO_RAW_HANDLER_H

#include "config.h"
#include <pcap.h>
#include "eemo.h"
#include "eemo_packet.h"

/* Defines a handler for raw packets */
typedef eemo_rv (*eemo_raw_handler_fn) (const eemo_packet_buf* packet, struct timeval ts);

/* Defines a raw packet handler record */
typedef struct eemo_raw_handler
{
	eemo_raw_handler_fn		handler_fn;	/* handler function */

	/* Administrativia */
	unsigned long			handle;		/* handle for this entry */
	struct eemo_raw_handler*	next;		/* to create a linked list */
}
eemo_raw_handler;

/* Register a raw packet handler */
typedef eemo_rv (*eemo_reg_raw_handler_fn) (eemo_raw_handler_fn, unsigned long*);

eemo_rv eemo_reg_raw_handler(eemo_raw_handler_fn handler_fn, unsigned long* handle);

/* Unregister a raw handler */
typedef eemo_rv (*eemo_unreg_raw_handler_fn) (unsigned long);

eemo_rv eemo_unreg_raw_handler(unsigned long handle);

/* Handle a raw packet */
eemo_rv eemo_handle_raw_packet(const eemo_packet_buf* packet, struct timeval ts);

/* Initialise raw packet handling */
eemo_rv eemo_init_raw_handler(void);

/* Clean up */
void eemo_raw_handler_cleanup(void);

#endif /* !_EEMO_RAW_HANDLER_H */

