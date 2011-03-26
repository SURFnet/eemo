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
 * The Extensible Ethernet Monitor (EEMO)
 * DNS statistics plug-in query counter code
 */

#ifndef _EEMO_DNSQFW_AGGR_H
#define _EEMO_DNSQFW_AGGR_H

#include "config.h"
#include "eemo.h"
#include "eemo_log.h"
#include "eemo_api.h"
#include "dns_qhandler.h"
#include "dns_types.h"

/* Maximum UDP packet size for forwarding */
#define QFW_UDP_MAXSIZE		2048

/* Initialise the DNS query counter module */
void eemo_dnsqfw_aggr_init(char** ips, int ip_count, char* server, int port, int max_packet_size);

/* Uninitialise the DNS query counter module */
void eemo_dnsqfw_aggr_uninit(eemo_conf_free_string_array_fn free_strings);

/* Handle DNS query packets and log the statistics */
eemo_rv eemo_dnsqfw_aggr_handleq(eemo_ip_packet_info ip_info, u_short qclass, u_short qtype, u_short flags, char* qname, int is_tcp);

#endif /* !_EEMO_DNSQFW_AGGR_H */

