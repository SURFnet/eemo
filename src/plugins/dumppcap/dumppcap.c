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
 * Dump packets to a PCAP file
 */

#include "config.h"
#include <stdlib.h>
#include <pcap.h>
#include <time.h>
#include <string.h>
#include <signal.h>
#include "eemo.h"
#include "eemo_api.h"
#include "eemo_plugin_log.h"
#include "raw_handler.h"

const static char* plugin_description = "EEMO PCAP dump plugin " PACKAGE_VERSION;

static unsigned long		raw_handler_handle	= 0;

static int			capture_time		= -1;
static int			capture_count		= -1;
static int			counted			= 0;
static pcap_t*			capture_pcap		= NULL;
static pcap_dumper_t*		capture_out		= NULL;
static int			capture_start		= 0;

/* Raw packet handler */
eemo_rv eemo_dumppcap_handle_pkt(const eemo_packet_buf* pkt, struct timeval ts)
{
	struct pcap_pkthdr	hdr;
	time_t			now	= time(NULL);

	if ((capture_time > 0) && ((now - capture_start) > capture_time))
	{
		INFO_MSG("Reached maximum capture time of %d seconds", capture_time);

		raise(SIGTERM);

		return ERV_HANDLED;
	}

	memcpy(&hdr.ts, &ts, sizeof(struct timeval));
	hdr.caplen = pkt->len;
	hdr.len = pkt->len;

	pcap_dump((u_char*) capture_out, &hdr, pkt->data);

	counted++;

	if ((capture_count > 0) && (counted >= capture_count))
	{
		INFO_MSG("Reached maximum capture count of %d packets", capture_count);

		raise(SIGTERM);

		return ERV_HANDLED;
	}
	
	return ERV_HANDLED;
}

/* Plugin initialisation */
eemo_rv eemo_dumppcap_init(eemo_export_fn_table_ptr eemo_fn, const char* conf_base_path)
{
	char*	capture_file	= NULL;

	/* Initialise logging for the plugin */
	eemo_init_plugin_log(eemo_fn->log);

	INFO_MSG("Initialising PCAP dump plugin");

	/* Register raw packet handler */
	if ((eemo_fn->reg_raw_handler)(&eemo_dumppcap_handle_pkt, &raw_handler_handle) != ERV_OK)
	{
		ERROR_MSG("Failed to register raw packet handler");

		return ERV_GENERAL_ERROR;
	}

	/* Read configuration */
	if (((eemo_fn->conf_get_string)(conf_base_path, "pcap_file", &capture_file, NULL) != ERV_OK) || (capture_file == NULL))
	{
		ERROR_MSG("Failed to retrieve the PCAP output file name from the configuration");

		return ERV_CONFIG_ERROR;
	}

	if ((eemo_fn->conf_get_int)(conf_base_path, "cap_time", &capture_time, -1) != ERV_OK)
	{
		ERROR_MSG("Failed to retrieve the capture time interval from the configuration");

		return ERV_CONFIG_ERROR;
	}

	if ((eemo_fn->conf_get_int)(conf_base_path, "cap_count", &capture_count, -1) != ERV_OK)
	{
		ERROR_MSG("Failed to retrieve the number of packets to capture from the configuration");

		return ERV_CONFIG_ERROR;
	}

	/* Attempt to open the dumping file */
	capture_pcap = pcap_open_dead(DLT_EN10MB, 65536);

	if (capture_pcap == NULL)
	{
		ERROR_MSG("Failed to set up dummy PCAP header");

		return ERV_GENERAL_ERROR;
	}

	capture_out = pcap_dump_open(capture_pcap, capture_file);

	if (capture_out == NULL)
	{
		ERROR_MSG("Failed to open PCAP output file %s", capture_file);

		return ERV_GENERAL_ERROR;
	}

	free(capture_file);

	INFO_MSG("PCAP dump plugin initialisation complete");

	capture_start = time(NULL);

	return ERV_OK;
}

/* Plugin uninitialisation */
eemo_rv eemo_dumppcap_uninit(eemo_export_fn_table_ptr eemo_fn)
{
	INFO_MSG("Uninitialising PCAP dump plugin");

	/* Unregister raw packet handler */
	if ((eemo_fn->unreg_raw_handler)(raw_handler_handle) != ERV_OK)
	{
		ERROR_MSG("Failed to unregister raw packet handler");
	}

	if (capture_out != NULL)
	{
		pcap_dump_close(capture_out);
	}

	if (capture_pcap != NULL)
	{
		pcap_close(capture_pcap);
	}

	INFO_MSG("Finished uninitialising PCAP dump plugin");

	return ERV_OK;
}

/* Retrieve plugin description */
const char* eemo_dumppcap_getdescription(void)
{
	return plugin_description;
}

/* Retrieve plugin status */
eemo_rv eemo_dumppcap_status(void)
{
	return ERV_OK;
}

/* Plugin function table */
static eemo_plugin_fn_table dumppcap_fn_table =
{
	EEMO_PLUGIN_FN_VERSION,
	&eemo_dumppcap_init,
	&eemo_dumppcap_uninit,
	&eemo_dumppcap_getdescription,
	&eemo_dumppcap_status
};

/* Entry point for retrieving plugin function table */
eemo_rv eemo_plugin_get_fn_table(eemo_plugin_fn_table_ptrptr fn_table)
{
	if (fn_table == NULL)
	{
		return ERV_PARAM_INVALID;
	}

	*fn_table = &dumppcap_fn_table;

	return ERV_OK;
}

