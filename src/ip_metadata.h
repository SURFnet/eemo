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
 * IP metadata functions
 */

#ifndef _IP_METADATA_H
#define _IP_METADATA_H

#include "config.h"
#include "eemo.h"
#include <arpa/inet.h>
#include <netinet/in.h>

/* Initialise metadata module */
eemo_rv eemo_md_init(void);

/* Uninitialise metadata module */
eemo_rv eemo_md_finalize(void);

/* Look up the AS for an IPv4 address */
eemo_rv eemo_md_lookup_as_v4(struct in_addr* addr, char** AS_short, char** AS_full);

/* Look up the AS for an IPv6 address */
eemo_rv eemo_md_lookup_as_v6(struct in6_addr* addr, char** AS_short, char** AS_full);

/* Look up Geo IP for an IPv4 address */
eemo_rv eemo_md_lookup_geoip_v4(struct in_addr* addr, char** country);

/* Look up Geo IP for an IPv6 address */
eemo_rv eemo_md_lookup_geoip_v6(struct in6_addr* addr, char** country);

#endif /* !_IP_METADATA_H */

