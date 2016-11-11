/*
 * Copyright (c) 2010-2011 SURFnet bv
 * Copyright (c) 2014-2016 Roland van Rijswijk-Deij
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
 * Ethernet packet capturing
 */

#include "config.h"
#include "eemo_log.h"
#include "ether_capture.h"
#include "raw_handler.h"
#include "eemo_config.h"
#include "eemo_packet.h"
#include <stdio.h>
#include <signal.h>
#include <pcap.h>
#include <time.h>

#define SNAPLEN			65536
#define DEBUG_PACKET_FILE	"/tmp/eemo.packet"

/* Global PCAP handle */
static pcap_t* handle = NULL;

/* Total packet counter */
static unsigned long long capture_ctr = 0;

/* Handled packet counter */
static unsigned long long handled_ctr = 0;

/* Interval between logging of statistics */
static int capture_stats_interval = 0;

/* Last time statistics were logged */
static time_t last_capture_stats = 0;

/* Should we log the packet currently being handled to file? */
static int log_current_packet = 0;

/* Capture buffer size in megabytes */
static int cap_buf_size = 32;

/* PCAP dump headers for packet file, makes for easy reading by e.g. Wireshark */
#pragma pack(push,1)
static struct
{
	uint32_t magic_number;
	uint16_t version_major;
	uint16_t version_minor;
	int32_t thiszone;
	uint32_t sigfigs;
	uint32_t snaplen;
	uint32_t network;
}
pcap_header
=
{
	0xa1b2c3d4,
	2,
	4,
	0,
	0,
	SNAPLEN,
	1
};

static struct
{
	uint32_t ts_sec;
	uint32_t ts_usec;
	uint32_t incl_len;
	uint32_t orig_len;
}
pcap_cap_header = { 0, 0, 0, 0};

static unsigned char blankbuf[2048] = { 0 };
#pragma pack(pop)

/* File for debug packet dumping */
static FILE* debug_packet_file = NULL;

/* Signal handler for exit signal */
static void stop_signal_handler(int signum)
{
	INFO_MSG("Received request to exit");

	pcap_breakloop(handle);
}

/* PCAP callback handler */
static void eemo_pcap_callback(u_char* user_ptr, const struct pcap_pkthdr* hdr, const u_char* capture_data)
{
	eemo_rv		rv	= ERV_OK;
	eemo_packet_buf	packet	= { (u_char*) capture_data, hdr->len };

	/* Count the packet */
	capture_ctr++;

	/* Log the packet to file if necessary */
	if (log_current_packet)
	{
		/* Write packet and flush */
		rewind(debug_packet_file);
		fwrite(&blankbuf[0], 1, sizeof(blankbuf), debug_packet_file);
		rewind(debug_packet_file);
		fwrite(&pcap_header, 1, sizeof(pcap_header), debug_packet_file);

		pcap_cap_header.incl_len = hdr->len;
		pcap_cap_header.orig_len = hdr->len;
		fwrite(&pcap_cap_header, 1, sizeof(pcap_cap_header), debug_packet_file);

		fwrite(capture_data, 1, hdr->len, debug_packet_file);
		fflush(debug_packet_file);
	}

	/* Run it through the handlers */
	rv = eemo_handle_raw_packet(&packet, hdr->ts);

	/* Conditionally increment the handled packet counter */
	if (rv == ERV_HANDLED)
	{
		handled_ctr++;
	}

	/* Check if we need to emit statistics */
	if (capture_stats_interval > 0)
	{
		if ((time(NULL) - last_capture_stats) >= capture_stats_interval)
		{
			last_capture_stats = time(NULL);

			INFO_MSG("Captured %llu packets %llu of which were handled by a plug-in", capture_ctr, handled_ctr);
		}
	}
}

/* Initialise direct capturing */
eemo_rv eemo_ether_capture_init(const char* interface)
{
	const char*		cap_if				= NULL;
	char 			errbuf[PCAP_ERRBUF_SIZE]	= { 0 };
	char*			capture_filter			= NULL;
	struct bpf_program	packet_filter;
	
	handle = NULL;

	/* Reset counters */
	capture_ctr = handled_ctr = 0;
	last_capture_stats = time(NULL);

	/* Retrieve configuration */
	eemo_conf_get_int("capture", "stats_interval", &capture_stats_interval, 0);
	eemo_conf_get_bool("capture", "debug_log_packet", &log_current_packet, 0);
	eemo_conf_get_int("capture", "bufsize", &cap_buf_size, 32);
	eemo_conf_get_string("capture", "filter", &capture_filter, NULL);

	if (capture_stats_interval > 0)
	{
		INFO_MSG("Emitting capture statistics every %ds", capture_stats_interval);
	}

	if (log_current_packet)
	{
		INFO_MSG("Logging packet being handled to %s for debugging purposes", DEBUG_PACKET_FILE);

		debug_packet_file = fopen(DEBUG_PACKET_FILE, "w");

		if (debug_packet_file == NULL)
		{
			ERROR_MSG("Failed to open %s for writing", DEBUG_PACKET_FILE);

			log_current_packet = 0;
		}
	}

	/* Determine the default interface if none was specified */
	cap_if = (interface == NULL) ? pcap_lookupdev(errbuf) : interface;

	if (cap_if == NULL)
	{
		/* No capture interface available or specified */
		ERROR_MSG("Unable to find a valid capturing interface");

		return ERV_ETH_NOT_EXIST;
	}

	INFO_MSG("Opening device %s for packet capture", cap_if);

	if ((handle = pcap_create(cap_if, errbuf)) == NULL)
	{
		ERROR_MSG("Failed to open capture handle");

		return ERV_ETH_NOT_EXIST;
	}

	if (pcap_set_snaplen(handle, 65536) != 0)
	{
		ERROR_MSG("Failed to set snap length for capture, giving up");

		pcap_close(handle);

		return ERV_GENERAL_ERROR;
	}

	if (pcap_set_promisc(handle, 1) != 0)
	{
		ERROR_MSG("Failed to set promiscuous mode on network device, giving up");

		pcap_close(handle);

		return ERV_GENERAL_ERROR;
	}

	if (pcap_set_timeout(handle, 1000) != 0)
	{
		ERROR_MSG("Failed to set timeout on capture, giving up");

		pcap_close(handle);

		return ERV_GENERAL_ERROR;
	}

	/* Set capture buffer size */
	if (pcap_set_buffer_size(handle, cap_buf_size*1024*1024) != 0)
	{
		WARNING_MSG("Failed to change capture buffer size");
	}
	else
	{
		INFO_MSG("Set capture buffer size to %d bytes", cap_buf_size*1024*1024);
	}

	/* Activate capture */
	if (pcap_activate(handle) != 0)
	{
		ERROR_MSG("Failed to activate packet capture, giving up");

		pcap_close(handle);

		return ERV_GENERAL_ERROR;
	}
	else
	{
		INFO_MSG("Activated capture");
	}

	/* Compile and set capture filter if configured */
	if (capture_filter != NULL)
	{
		INFO_MSG("Compiling capture packet filter rule '%s'", capture_filter);

		if (pcap_compile(handle, &packet_filter, capture_filter, 0, 0) == -1)
		{
			ERROR_MSG("Failed to compile the filter expression, giving up");

			pcap_close(handle);

			return ERV_INVALID_FILTER;
		}

		if (pcap_setfilter(handle, &packet_filter) == -1)
		{
			ERROR_MSG("Failed to activate capture filter, giving up");

			pcap_freecode(&packet_filter);
			pcap_close(handle);

			return ERV_INVALID_FILTER;
		}

		pcap_freecode(&packet_filter);

		INFO_MSG("Capture packet filter activated");
	}

	INFO_MSG("%s configured for capturing", cap_if);

	INFO_MSG("Live capture initialised successfully");

	return ERV_OK;
}

/* Uninitialise direct capturing */
eemo_rv eemo_ether_capture_finalize(void)
{
	INFO_MSG("Uninitialised live capture");

	return ERV_OK;
}

/* Run the direct capture */
void eemo_ether_capture_run(void)
{
	/* Register the signal handler for termination */
	signal(SIGINT, stop_signal_handler);
	signal(SIGHUP, stop_signal_handler);
	signal(SIGTERM, stop_signal_handler);

	/* Capture the specified number of packets */
	INFO_MSG("Starting packet capture");

	if (pcap_loop(handle, 0, &eemo_pcap_callback, NULL) == -1)
	{
		ERROR_MSG("pcap_loop(..) returned an error (%s)", pcap_geterr(handle));
	}

	signal(SIGINT, SIG_DFL);
	signal(SIGHUP, SIG_DFL);
	signal(SIGTERM, SIG_DFL);

	/* Close last packet dump file if open */
	if (log_current_packet && debug_packet_file)
	{
		fclose(debug_packet_file);
	}

	INFO_MSG("Packet capture ended, captured %llu packets of which %llu were handled", capture_ctr, handled_ctr);

	pcap_close(handle);

	handle = NULL;
}

