/*
 * Copyright (c) 2010 SURFnet bv
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
#include "ifaddr_lookup.h"
#include "ether_capture.h"

eemo_rv handle_udp(eemo_packet_buf* packet, eemo_ip_packet_info info)
{
	printf("UDPv%d packet from %s to %s\n", info.ip_type, info.ip_src, info.ip_dst);

	return ERV_OK;
}

eemo_rv handle_tcp(eemo_packet_buf* packet, eemo_ip_packet_info info)
{
	printf("TCPv%d packet from %s to %s\n", info.ip_type, info.ip_src, info.ip_dst);

	return ERV_OK;
}

int main(int argc, char* argv[])
{
	if (eemo_init_ip_handler() != ERV_OK)
	{
		fprintf(stderr, "Failed to initialise the IP packet handler\n");

		return -1;
	}

	if (eemo_reg_ip_handler(0x0011, &handle_udp) != ERV_OK)
	{
		fprintf(stderr, "Failed to register generic UDP handler\n");

		return -1;
	};

	if (eemo_reg_ip_handler(0x0006, &handle_tcp) != ERV_OK)
	{
		fprintf(stderr, "Failed to register generic TCP handler\n");

		return -1;
	};

	if (eemo_capture_and_handle(NULL, -1, NULL) != ERV_OK)
	{
		fprintf(stderr, "Failed to start packet capture\n");

		return -1;
	}

	return 0;
}

