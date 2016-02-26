/*
 * Copyright (c) 2015 SURFnet bv
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
 * CIDR block based IP matching
 */

#ifndef _CIDRMATCH_H
#define _CIDRMATCH_H

#include "config.h"
#include "eemo.h"
#include <pcap.h>

/* Function pointer definitions */
typedef eemo_rv (*eemo_cm_add_block_fn)(const char*, const char*);
typedef eemo_rv (*eemo_cm_match_v4_fn)(const u_int, const char**);
typedef eemo_rv (*eemo_cm_match_v6_fn)(const u_short[8], const char**);

/* Initialise the CIDR matching module */
eemo_rv eemo_cm_init(void);

/* Uninitialise the CIDR matching module */
eemo_rv eemo_cm_finalize(void);

/* Add a block for matching */
eemo_rv eemo_cm_add_block(const char* block_str, const char* block_desc);

/* Match an IPv4 address (input address should be in network byte order!) */
eemo_rv eemo_cm_match_v4(const u_int v4addr, const char** block_desc);

/* Match an IPv6 address (input address should be in network byte order!) */
eemo_rv eemo_cm_match_v6(const u_short v6addr[8], const char** block_desc);

#endif /* !_CIDRMATCH_H */

