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
 * Local Ethernet interface address database
 */

#ifndef _EEMO_IFADDR_LOOKUP_H
#define _EEMO_IFADDR_LOOKUP_H

#include <netdb.h>

#define IFADDR_TYPE_V4		4	/* this is an IPv4 address */
#define IFADDR_TYPE_V6		6	/* this is an IPv6 address */

/* Interface address information structure */
typedef struct eemo_ifaddr_info
{
	unsigned char			ifaddr_type;
	char				ifaddr_addr[NI_MAXHOST];
	struct eemo_ifaddr_info*	next;
}
eemo_ifaddr_info;

/* Retrieve address information for the specified interface */
eemo_ifaddr_info* eemo_get_ifaddr_info(const char* interface);

/* Clean up address information */
void eemo_ifaddr_info_free(eemo_ifaddr_info* info);

#endif /* !_EEMO_IFADDR_LOOKUP_H */

