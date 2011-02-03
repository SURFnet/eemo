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
 */

#include <stdio.h>
#include <stdlib.h>
#include "eemo_packet.h"
#include "ip_handler.h"
#include "udp_handler.h"
#include "tcp_handler.h"
#include "ifaddr_lookup.h"
#include "ether_capture.h"

eemo_rv handle_udp_any(eemo_packet_buf* packet, eemo_ip_packet_info info, u_short srcport, u_short dstport)
{
	printf("UDPv%d packet of %d bytes from %s:%d to %s:%d\n", info.ip_type, packet->len, info.ip_src, srcport, info.ip_dst, dstport);

	return ERV_OK;
}

eemo_rv handle_tcp_any(eemo_packet_buf* packet, eemo_ip_packet_info ip_info, eemo_tcp_packet_info tcp_info)
{
	printf("TCPv%d packet of %d bytes from %s:%d to %s:%d (", ip_info.ip_type, packet->len, ip_info.ip_src, tcp_info.srcport, ip_info.ip_dst, tcp_info.dstport);
	printf("SEQ %u, WIN %u", tcp_info.seqno, tcp_info.winsize);

	if (FLAG_SET(tcp_info.flags, TCP_CWR)) printf(" CWR");
	if (FLAG_SET(tcp_info.flags, TCP_ECE)) printf(" ECE");
	if (FLAG_SET(tcp_info.flags, TCP_URG)) printf(" URG(0x%04X)", tcp_info.urgptr);
	if (FLAG_SET(tcp_info.flags, TCP_ACK)) printf(" ACK (%u)", tcp_info.ackno);
	if (FLAG_SET(tcp_info.flags, TCP_PSH)) printf(" PSH");
	if (FLAG_SET(tcp_info.flags, TCP_RST)) printf(" RST");
	if (FLAG_SET(tcp_info.flags, TCP_SYN)) printf(" SYN");
	if (FLAG_SET(tcp_info.flags, TCP_FIN)) printf(" FIN");

	printf("\n");

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

	if (eemo_reg_udp_handler(UDP_ANY_PORT, UDP_ANY_PORT, &handle_udp_any) != ERV_OK)
	{
		fprintf(stderr, "Failed to register generic UDP handler\n");

		return -1;
	};

	if (eemo_reg_tcp_handler(TCP_ANY_PORT, TCP_ANY_PORT, &handle_tcp_any) != ERV_OK)
	{
		fprintf(stderr, "Failed to register generic TCP handler\n");

		return -1;
	}

	if (eemo_capture_and_handle(NULL, -1, NULL) != ERV_OK)
	{
		fprintf(stderr, "Failed to start packet capture\n");

		return -1;
	}

	return 0;
}

