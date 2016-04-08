/*
 * Copyright (c) 2010-2016 SURFnet bv
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
 * PCAP file processing
 */

#include "config.h"
#include "eemo_log.h"
#include "ether_capture.h"
#include "raw_handler.h"
#include "eemo_config.h"
#include "eemo_packet.h"
#include <stdio.h>
#include <signal.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <zlib.h>

/* Total packet counter */
static unsigned long long capture_ctr = 0;

/* Handled packet counter */
static unsigned long long handled_ctr = 0;

/* Interval between logging of statistics */
static int capture_stats_interval = 0;

/* Last time statistics were logged */
static time_t last_capture_stats = 0;

/* PCAP headers */
#pragma pack(push,1)
typedef struct
{
	uint32_t	pcap_magic;
	uint16_t	pcap_major;
	uint16_t	pcap_minor;
	int32_t		pcap_utc_ofs;
	uint32_t	pcap_ts_acc;
	uint32_t	pcap_snaplen;
	uint32_t	pcap_linktype;
}
pcap_file_hdr;

typedef struct
{
	uint32_t	pkt_ts_sec;
	uint32_t	pkt_ts_usec;
	uint32_t	pkt_sav_len;
	uint32_t	pkt_cap_len;
}
pcap_pkt_hdr;
#pragma pack(pop)

#define PCAP_MAGIC_DEFAULT	0xa1b2c3d4
#define PCAP_MAGIC_OTHER_ENDIAN	0xd4c3b2a1
#define PCAP_MAGIC_NSEC		0xa1b23c4d
#define PCAP_MAGIC_NSEC_ENDIAN	0x4d3cb2a1

/* Invert endianess of PCAP headers? */
static int	invert_endian	= 0;
static int	use_ntoh	= 0; 

/* PCAP precision */
static int	is_nsec_pcap	= 0;

/* Should we exit? */
static int	capture_exit	= 0;

/* PCAP file handle */
static FILE*	pcap_fd		= NULL;
static gzFile	zpcap_fd	= NULL;

/* Signal handler for exit signal */
static void stop_signal_handler(int signum)
{
	INFO_MSG("Received request to exit");

	capture_exit = 1;
}

static uint16_t eemo_pcap_int_flip_uint16(const uint16_t in)
{
	return use_ntoh ? ntohs(in) : htons(in);
}

static int32_t eemo_pcap_int_flip_int32(const int32_t in)
{
	return (int32_t) (use_ntoh ? ntohl((uint32_t) in) : htonl((uint32_t) in));
}

static uint32_t eemo_pcap_int_flip_uint32(const uint32_t in)
{
	return use_ntoh ? ntohl(in) : htonl(in);
}

static void eemo_pcap_int_pkt_hdr_endian(pcap_pkt_hdr* hdr)
{
	if (invert_endian)
	{
		hdr->pkt_ts_sec		= eemo_pcap_int_flip_uint32(hdr->pkt_ts_sec);
		hdr->pkt_ts_usec	= eemo_pcap_int_flip_uint32(hdr->pkt_ts_usec);
		hdr->pkt_sav_len	= eemo_pcap_int_flip_uint32(hdr->pkt_sav_len);
		hdr->pkt_cap_len	= eemo_pcap_int_flip_uint32(hdr->pkt_cap_len);
	}
}

static void eemo_pcap_int_file_hdr_endian(pcap_file_hdr* hdr)
{
	if (invert_endian)
	{
		hdr->pcap_major		= eemo_pcap_int_flip_uint16(hdr->pcap_major);
		hdr->pcap_minor		= eemo_pcap_int_flip_uint16(hdr->pcap_minor);
		hdr->pcap_utc_ofs	= eemo_pcap_int_flip_int32(hdr->pcap_utc_ofs);
		hdr->pcap_ts_acc	= eemo_pcap_int_flip_uint32(hdr->pcap_ts_acc);
		hdr->pcap_snaplen	= eemo_pcap_int_flip_uint32(hdr->pcap_snaplen);
		hdr->pcap_linktype	= eemo_pcap_int_flip_uint32(hdr->pcap_linktype);
	}
}

/* PCAP callback handler */
static void eemo_pcap_int_handle_one(const uint32_t ts_sec, const uint32_t ts_usec, const uint8_t* data, const size_t data_len)
{
	eemo_rv 	rv	= ERV_OK;
	eemo_packet_buf	packet	= { (u_char*) data, data_len };
	struct timeval	tv	= { ts_sec, ts_usec };

	/* Count the packet */
	capture_ctr++;

	/* Run it through the handlers */
	rv = eemo_handle_raw_packet(&packet, tv);

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
eemo_rv eemo_file_capture_init(const char* savefile)
{
	char*		open_file	= NULL;
	FILE*		tmp_fd		= NULL;
	uint8_t		gz_magic[2]	= { 0, 0 };
	pcap_file_hdr	pcap_hdr;
	
	capture_exit = 0;
	use_ntoh = (ntohl(0x12345678) == 0x12345678) ? 0 : 1;

	/* Reset counters */
	capture_ctr = handled_ctr = 0;
	last_capture_stats = time(NULL);

	/* Retrieve configuration */
	eemo_conf_get_int("capture", "stats_interval", &capture_stats_interval, 0);

	if (savefile == NULL)
	{
		if ((eemo_conf_get_string("capture", "file", &open_file, NULL) != ERV_OK) || (open_file == NULL))
		{
			ERROR_MSG("Failed to retrieve name of PCAP file from the configuration");

			return ERV_CONFIG_ERROR;
		}
	}
	else
	{
		open_file = strdup(savefile);
	}

	if (capture_stats_interval > 0)
	{
		INFO_MSG("Emitting capture statistics every %ds", capture_stats_interval);
	}

	/* Try to open the file */
	tmp_fd = fopen(open_file, "r");

	if (tmp_fd == NULL)
	{
		ERROR_MSG("Failed to open capture file %s", open_file);
		
		free(open_file);

		return ERV_NO_ACCESS;
	}

	/* Check if the file is gzipped */
	if ((fread(gz_magic, 1, 2, tmp_fd) == 2) &&
	    (gz_magic[0] == 0x1f) &&
	    (gz_magic[1] == 0x8b))
	{
		/* Assume this file is GZipped */
		fclose(tmp_fd);

		zpcap_fd = gzopen(open_file, "r");

		if (zpcap_fd == NULL)
		{
			ERROR_MSG("Failed to open %s as gzip stream", open_file);

			free(open_file);
			
			return ERV_NO_ACCESS;
		}

		INFO_MSG("Opened %s as gzipped PCAP stream", open_file);
	}
	else
	{
		/* This file is not GZipped */
		rewind(tmp_fd);

		pcap_fd = tmp_fd;

		INFO_MSG("Opened %s for reading as plain PCAP", open_file);
	}

	/* Read PCAP header */
	if (pcap_fd != NULL)
	{
		if (fread(&pcap_hdr, 1, sizeof(pcap_file_hdr), pcap_fd) != sizeof(pcap_file_hdr))
		{
			fclose(pcap_fd);
			pcap_fd = NULL;

			ERROR_MSG("Failed to read PCAP header from %s", open_file);
		}
	}
	else
	{
		if (gzread(zpcap_fd, &pcap_hdr, sizeof(pcap_file_hdr)) != sizeof(pcap_file_hdr))
		{
			gzclose(zpcap_fd);
			zpcap_fd = NULL;

			ERROR_MSG("Failed to read PCAP header from %s", open_file);
		}
	}
	
	/* Check header integrity */
	switch(pcap_hdr.pcap_magic)
	{
	case PCAP_MAGIC_DEFAULT:
		INFO_MSG("%s is a standard PCAP file in local endian format", open_file);

		invert_endian = 0;
		is_nsec_pcap = 0;

		break;
	case PCAP_MAGIC_NSEC:
		INFO_MSG("%s is a PCAP file with nano-second precision in local endian format", open_file);
	
		invert_endian = 0;
		is_nsec_pcap = 1;

		break;
	case PCAP_MAGIC_OTHER_ENDIAN:
		INFO_MSG("%s is a standard PCAP file in a different endian format", open_file);

		invert_endian = 1;
		is_nsec_pcap = 0;

		break;
	case PCAP_MAGIC_NSEC_ENDIAN:
		INFO_MSG("%s is a PCAP file with nano-second precision in a different endian format", open_file);

		invert_endian = 1;
		is_nsec_pcap = 1;
		
		break;
	default:
		ERROR_MSG("Invalid magic word (0x%08X) found in PCAP file %s", pcap_hdr.pcap_magic, open_file);

		if (pcap_fd != NULL)
		{
			fclose(pcap_fd);
			pcap_fd = NULL;
		}
		else
		{
			gzclose(zpcap_fd);
			zpcap_fd = NULL;
		}

		free(open_file);
		return ERV_GENERAL_ERROR;
	}

	/* Correct the rest of the header for local endianess if required */
	eemo_pcap_int_file_hdr_endian(&pcap_hdr);

	INFO_MSG("PCAP file has version %u.%u", pcap_hdr.pcap_major, pcap_hdr.pcap_minor);
	INFO_MSG("PCAP snap length %d bytes", pcap_hdr.pcap_snaplen);
	INFO_MSG("PCAP link type 0x%08X", pcap_hdr.pcap_linktype);

	INFO_MSG("PCAP processing initialised successfully");

	free(open_file);

	return ERV_OK;
}

/* Uninitialise direct capturing */
eemo_rv eemo_file_capture_finalize(void)
{
	/* Close files */
	if (pcap_fd != NULL)
	{
		fclose(pcap_fd);
		pcap_fd = NULL;

		INFO_MSG("Closed regular PCAP file stream");
	}

	if (zpcap_fd != NULL)
	{
		gzclose(zpcap_fd);
		zpcap_fd = NULL;

		INFO_MSG("Closed gzipped PCAP file stream");
	}

	INFO_MSG("PCAP processing uninitialised");

	return ERV_OK;
}

/* Run the direct capture */
void eemo_file_capture_run(void)
{
	pcap_pkt_hdr	pkt_hdr;
	int		nread		= 0;
	static uint8_t	buf[65536]	= { 0 };

	/* Register the signal handler for termination */
	signal(SIGINT, stop_signal_handler);
	signal(SIGHUP, stop_signal_handler);
	signal(SIGTERM, stop_signal_handler);

	/* Capture the specified number of packets */
	INFO_MSG("Starting packet playback");

	while (!capture_exit)
	{
		/* Read header */
		if (pcap_fd != NULL)
		{
			nread = fread(&pkt_hdr, 1, sizeof(pcap_pkt_hdr), pcap_fd);
		}
		else
		{
			nread = gzread(zpcap_fd, &pkt_hdr, sizeof(pcap_pkt_hdr));
		}

		if (nread != sizeof(pcap_pkt_hdr))
		{
			if (nread == 0)
			{
				INFO_MSG("Reached end of PCAP stream");
			}
			else if (nread < 0)
			{
				ERROR_MSG("Error reading PCAP stream");
			}
			else
			{
				ERROR_MSG("Truncated PCAP stream, read %d bytes, expected %d", nread, sizeof(pcap_pkt_hdr));
			}

			capture_exit = 1;
			continue;
		}
	
		/* Convert header to local endianess if necessary */
		eemo_pcap_int_pkt_hdr_endian(&pkt_hdr);

		if (pkt_hdr.pkt_sav_len > 65536)
		{
			ERROR_MSG("Unsupported packet size of %u bytes, giving up on this PCAP stream", pkt_hdr.pkt_sav_len);

			capture_exit = 1;
			continue;
		}

		if (pkt_hdr.pkt_sav_len == 0)
		{
			WARNING_MSG("Zero-length packet in PCAP stream");
			continue;
		}

		/* Read the packet from the stream */
		if (pcap_fd != NULL)
		{
			nread = fread(buf, 1, pkt_hdr.pkt_sav_len, pcap_fd);
		}
		else
		{
			nread = gzread(zpcap_fd, buf, pkt_hdr.pkt_sav_len);
		}

		if (nread != pkt_hdr.pkt_sav_len)
		{
			if (nread == 0)
			{
				WARNING_MSG("Unexpected end of PCAP stream");
			}
			else if (nread < 0)
			{
				ERROR_MSG("Error reading PCAP stream");
			}
			else
			{
				ERROR_MSG("Truncated PCAP stream, read %d bytes, expected %d", nread, pkt_hdr.pkt_sav_len);
			}

			capture_exit = 1;
			continue;
		}

		/* Adjust time if necessary */
		if (is_nsec_pcap) pkt_hdr.pkt_ts_usec /= 1000;
	
		/* Process the packet */
		eemo_pcap_int_handle_one(pkt_hdr.pkt_ts_sec, pkt_hdr.pkt_ts_usec, buf, pkt_hdr.pkt_sav_len);
	}

	signal(SIGINT, SIG_DFL);
	signal(SIGHUP, SIG_DFL);
	signal(SIGTERM, SIG_DFL);

	INFO_MSG("Packet playback ended, read %llu packets of which %llu were handled", capture_ctr, handled_ctr);
}

