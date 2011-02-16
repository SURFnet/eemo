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

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include "eemo.h"
#include "eemo_api.h"
#include "eemo_packet.h"
#include "ip_handler.h"
#include "udp_handler.h"
#include "tcp_handler.h"
#include "dns_qhandler.h"
#include "dns_types.h"
#include "ifaddr_lookup.h"
#include "ether_capture.h"

eemo_rv handle_any_dns_query(eemo_ip_packet_info ip_info, u_short qclass, u_short qtype, u_short flags, char* qname, int is_tcp)
{
	printf("%s DNS query from %s for ", is_tcp ? "TCP" : "UDP", ip_info.ip_src);

	switch(qclass)
	{
	case DNS_QCLASS_UNSPECIFIED:
		printf("UNSPEC CLASS ");
		break;
	case DNS_QCLASS_IN:
		printf("IN ");
		break;
	case DNS_QCLASS_CS:
		printf("CS ");
		break;
	case DNS_QCLASS_CH:
		printf("CH ");
		break;
	case DNS_QCLASS_HS:
		printf("HS ");
		break;
	case DNS_QCLASS_ANY:
		printf("ANY ");
		break;
	default:
		printf("UNKNOWN CLASS ");
	}

	switch(qtype)
	{
	case DNS_QTYPE_UNSPECIFIED:
		printf("UNSPEC CLASS ");
		break;
	case DNS_QTYPE_A:
		printf("A ");
		break;
	case DNS_QTYPE_AAAA:
		printf("AAAA ");
		break;
	case DNS_QTYPE_AFSDB:
		printf("AFSDB ");
		break;
	case DNS_QTYPE_APL:
		printf("APL ");
		break;
	case DNS_QTYPE_CERT:
		printf("CERT ");
		break;
	case DNS_QTYPE_CNAME:
		printf("CNAME ");
		break;
	case DNS_QTYPE_DHCID:
		printf("DHCID ");
		break;
	case DNS_QTYPE_DLV:
		printf("DLV ");
		break;
	case DNS_QTYPE_DNAME:
		printf("DNAME ");
		break;
	case DNS_QTYPE_DNSKEY:
		printf("DNSKEY ");
		break;
	case DNS_QTYPE_DS:
		printf("DS ");
		break;
	case DNS_QTYPE_HIP:
		printf("HIP ");
		break;
	case DNS_QTYPE_IPSECKEY:
		printf("IPSECKEY");
		break;
	case DNS_QTYPE_KEY:
		printf("KEY ");
		break;
	case DNS_QTYPE_KX:
		printf("KX ");
		break;
	case DNS_QTYPE_LOC:
		printf("LOC ");
		break;
	case DNS_QTYPE_MX:
		printf("MX ");
		break;
	case DNS_QTYPE_NAPTR:
		printf("NAPTR ");
		break;
	case DNS_QTYPE_NS:
		printf("NS ");
		break;
	case DNS_QTYPE_NSEC:
		printf("NSEC ");
		break;
	case DNS_QTYPE_NSEC3:
		printf("NSEC3 ");
		break;
	case DNS_QTYPE_NSEC3PARAM:
		printf("NSEC3PARAM ");
		break;
	case DNS_QTYPE_PTR:
		printf("PTR ");
		break;
	case DNS_QTYPE_RRSIG:
		printf("RRSIG ");
		break;
	case DNS_QTYPE_RP:
		printf("RP ");
		break;
	case DNS_QTYPE_SIG:
		printf("SIG ");
		break;
	case DNS_QTYPE_SOA:
		printf("SOA ");
		break;
	case DNS_QTYPE_SPF:
		printf("SPF ");
		break;
	case DNS_QTYPE_SRV:
		printf("SRV ");
		break;
	case DNS_QTYPE_SSHFP:
		printf("SSHFP ");
		break;
	case DNS_QTYPE_TA:
		printf("TA ");
		break;
	case DNS_QTYPE_TKEY:
		printf("TKEY ");
		break;
	case DNS_QTYPE_TSIG:
		printf("TSIG ");
		break;
	case DNS_QTYPE_TXT:
		printf("TXT ");
		break;
	case DNS_QTYPE_ANY:
		printf("ANY ");
		break;
	case DNS_QTYPE_AXFR:
		printf("AXFR ");
		break;
	case DNS_QTYPE_IXFR:
		printf("IXFR ");
		break;
	case DNS_QTYPE_OPT:
		printf("OPT ");
		break;
	default:
		printf("UNKNOWN TYPE ");
	}

	printf("%s\n", qname);

	return ERV_OK;
}

int main(int argc, char* argv[])
{
	if (eemo_init_ip_handler() != ERV_OK)
	{
		fprintf(stderr, "Failed to initialise the IP packet handler\n");

		return -1;
	}

	if (eemo_init_udp_handler() != ERV_OK)
	{
		fprintf(stderr, "Failed to initialise the UDP packet handler\n");
	}

	if (eemo_init_tcp_handler() != ERV_OK)
	{
		fprintf(stderr, "Failed to initialise the TCP packet handler\n");
	}

	if (eemo_init_dns_qhandler() != ERV_OK)
	{
		fprintf(stderr, "Failed to initialise the DNS query handler\n");
	}

	if (eemo_reg_dns_qhandler(DNS_QCLASS_UNSPECIFIED, DNS_QTYPE_UNSPECIFIED, &handle_any_dns_query) != ERV_OK)
	{
		fprintf(stderr, "Failed to register generic DNS query handler\n");

		return -1;
	}

	if (eemo_capture_and_handle(NULL, -1, NULL) != ERV_OK)
	{
		fprintf(stderr, "Failed to start packet capture\n");

		return -1;
	}

	return 0;
}

