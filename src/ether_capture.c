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
 * Ethernet packet capturing
 */

#include "ether_capture.h"
#include "ether_handler.h"
#include <stdio.h>

#define SNAPLEN		65535

/* PCAP callback handler */
void eemo_pcap_callback(u_char* user_ptr, const struct pcap_pkthdr* hdr, const u_char* capture_data)
{
	eemo_rv rv;

	/* Copy the captured data */
	eemo_packet_buf* packet = eemo_pbuf_new((u_char*) capture_data, hdr->len);

	/* Run it through the Ethernet handlers */
	rv = eemo_handle_ether_packet(packet);

	/* Free the packet data */
	eemo_pbuf_free(packet);
}

/* Capture and handle the specified number of packets on the specified interface, optionally using a filter */
eemo_rv eemo_capture_and_handle(const char* interface, int packet_count, const char* net_filter)
{
	const char* cap_if = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = NULL;
	struct bpf_program packet_filter;

	/* Determine the default interface if none was specified */
	cap_if = (interface == NULL) ? pcap_lookupdev(errbuf) : interface;

	if (cap_if == NULL)
	{
		/* No capture interface available or specified */
		return ERV_ETH_NOT_EXIST;
	}

	/* Open the device in promiscuous mode */
	handle = pcap_open_live(cap_if, SNAPLEN, 1, 1000, errbuf);

	if (handle == NULL)
	{
		/* Failed to open interface for capturing */
		return ERV_NO_ACCESS;
	}

	/* Compile and apply packet filter */
	if (net_filter != NULL)
	{
		if (pcap_compile(handle, &packet_filter, (char*) net_filter, 0, 0) == -1)
		{
			/* Failed to compile packet filter */
			pcap_close(handle);

			return ERV_INVALID_FILTER;
		}

		if (pcap_setfilter(handle, &packet_filter) == -1)
		{
			/* Failed to apply packet filter */
			pcap_freecode(&packet_filter);
			pcap_close(handle);

			return ERV_INVALID_FILTER;
		}
	}

	/* Capture the specified number of packets */
	if (pcap_loop(handle, packet_count, &eemo_pcap_callback, NULL) == -1)
	{
		pcap_freecode(&packet_filter);
		pcap_close(handle);

		return ERV_CAPTURE_ERROR;
	}

	pcap_freecode(&packet_filter);
	pcap_close(handle);

	return ERV_OK;
}

