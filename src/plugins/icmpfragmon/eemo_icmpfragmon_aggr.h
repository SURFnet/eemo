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
 * ICMP fragment reassembly time-out monitoring
 */

#ifndef _EEMO_ICMPFRAGMON_AGGR_H
#define _EEMO_ICMPFRAGMON_AGGR_H

#include "config.h"
#include "eemo.h"
#include "eemo_log.h"
#include "eemo_api.h"
#include "icmp_handler.h"

/* Maximum UDP packet size for forwarding */
#define IFM_UDP_MAXSIZE		2048

/* Message types */
#define IFM_MSG_FRAGDATA	2		/* This message contains a list of hosts that returned ICMP fragmentation errors */

/* ICMP types & codes*/
#define ICMPv4_TYPE_TIME_EXCEEDED	11
#define ICMPv4_CODE_REASSEMBLY_FAIL	1

#define ICMPv6_TYPE_TIME_EXCEEDED	3
#define ICMPv6_CODE_REASSEMBLY_FAIL	1

/* Initialise the module */
void eemo_icmpfragmon_aggr_init(char* server, int port, int max_packet_size, int sensor_id);

/* Uninitialise the module */
void eemo_icmpfragmon_aggr_uninit(eemo_conf_free_string_array_fn free_strings);

/* Handle ICMP messages */
eemo_rv eemo_icmpfragmon_handle_icmp(const eemo_packet_buf* icmp_data, eemo_ip_packet_info ip_info, u_char icmp_type, u_char icmp_code);

#endif /* !_EEMO_ICMPFRAGMON_AGGR_H */

