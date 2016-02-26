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
 * The Extensible IP Monitor (EEMO)
 * IP reassembly
 */

#ifndef _EEMO_IP_REASSEMBLE_H
#define _EEMO_IP_REASSEMBLE_H

#include "config.h"
#include "eemo.h"
#include "eemo_packet.h"
#include <pcap.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

/* Initialise reassembly module */
eemo_rv eemo_reasm_init(void);

/* Uninitialise reassembly module */
eemo_rv eemo_reasm_finalize(void);

/*
 * Process an IPv4 fragment; will return ERV_NEED_MORE_FRAGS if more
 * fragments are needed to reassemble the packet, and ERV_OK if a full
 * packet was reassembled (in which case <pkt> contains the packet
 * data. Caller must release reassembled packets with the appropriate
 * call below!
 */
eemo_rv eemo_reasm_v4_fragment(const struct in_addr* src, const struct in_addr* dst, const u_char ip_proto, const u_short ip_id, const u_short ip_ofs, const eemo_packet_buf* fragment, const int is_last, eemo_packet_buf* pkt);

/* Process an IPv6 fragment; semantics of parameters same as for IPv4 */
eemo_rv eemo_reasm_v6_fragment(const struct in6_addr* src, const struct in6_addr* dst, const u_int ip_id, const u_short ip_ofs, const eemo_packet_buf* fragment, const int is_last, eemo_packet_buf* pkt);

/* Discard a reassembled IPv4 packet */
void eemo_reasm_v4_free(const struct in_addr* src, const struct in_addr* dst, const u_char ip_proto, const u_short ip_id);

/* Discard a reassembled IPv6 packet */
void eemo_reasm_v6_free(const struct in6_addr* src, const struct in6_addr* dst, const u_int ip_id);

#endif /* !_EEMO_IP_REASSEMBLE_H */

