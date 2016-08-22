/*
 * Copyright (c) 2010-2016 SURFnet bv
 * Copyright (c) 2016 Roland van Rijswijk-Deij
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
 * DNS query client and name population size measurements
 */

#include "config.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <time.h>
#include <pthread.h>
#include "eemo.h"
#include "eemo_api.h"
#include "eemo_plugin_log.h"
#include "dns_handler.h"
#include "dns_parser.h"
#include "uthash.h"

const static char* plugin_description = "EEMO SLD query popularity measurement plugin " PACKAGE_VERSION;

/* Handles */
static unsigned long		dns_handler_handle	= 0;

/* Configuration */
static char*			sld_to_monitor		= NULL;
static int			dump_interval		= 0;
static char*			stats_file		= NULL;

/* State */
static unsigned long long	current_interval_count	= 0;
static time_t			last_dump_time		= 0;

/* Query handler */
eemo_rv eemo_sldpop_dns_handler(eemo_ip_packet_info ip_info, int is_tcp, const eemo_dns_packet* pkt)
{
	/* Only look at valid queries */
	if (!pkt->qr_flag && !pkt->is_partial && (pkt->questions != NULL) && (pkt->questions->qname != NULL))
	{
		if (strlen(pkt->questions->qname) >= strlen(sld_to_monitor))
		{
			int ofs = strlen(pkt->questions->qname);
			ofs -= strlen(sld_to_monitor);

			if (strcmp(&pkt->questions->qname[ofs], sld_to_monitor) == 0)
			{
				current_interval_count++;
			}

			if ((ip_info.ts.tv_sec > last_dump_time) && (ip_info.ts.tv_sec % dump_interval == 0))
			{
				FILE* out = fopen(stats_file, "a");

				fprintf(out, "%u,%llu\n", (unsigned int) ip_info.ts.tv_sec, current_interval_count);

				last_dump_time = ip_info.ts.tv_sec;

				current_interval_count = 0L;

				fclose(out);
			}
		}
	}

	return ERV_SKIPPED;
}

/* Plugin initialisation */
eemo_rv eemo_sldpop_init(eemo_export_fn_table_ptr eemo_fn, const char* conf_base_path)
{
	/* Initialise logging for the plugin */
	eemo_init_plugin_log(eemo_fn->log);

	INFO_MSG("Initialising sldpop plugin");

	/* Retrieve configuration */
	if (((eemo_fn->conf_get_int)(conf_base_path, "dump_interval", &dump_interval, 300) != ERV_OK) || (dump_interval <= 0))
	{
		ERROR_MSG("Failed to retrieve the dump interval from the configuration");

		return ERV_CONFIG_ERROR;
	}

	if (((eemo_fn->conf_get_string)(conf_base_path, "stats_file", &stats_file, NULL) != ERV_OK) || (stats_file == NULL))
	{
		ERROR_MSG("Failed to retrieve output file name from the configuration");

		return ERV_CONFIG_ERROR;
	}

	if (((eemo_fn->conf_get_string)(conf_base_path, "sld_to_monitor", &sld_to_monitor, NULL) != ERV_OK) || (sld_to_monitor == NULL))
	{
		ERROR_MSG("Failed to retrieve SLD to monitor from the configuration");

		return ERV_CONFIG_ERROR;
	}

	INFO_MSG("Dumping counts every %d seconds", dump_interval);
	INFO_MSG("Writing statistics to %s", stats_file);
	INFO_MSG("Counting queries for %s", sld_to_monitor);

	/* Register DNS handler */
	if ((eemo_fn->reg_dns_handler)(&eemo_sldpop_dns_handler, PARSE_QUERY | PARSE_CANONICALIZE_NAME, &dns_handler_handle) != ERV_OK)
	{
		ERROR_MSG("Failed to register sldpop DNS handler");

		(eemo_fn->unreg_dns_handler)(dns_handler_handle);

		return ERV_GENERAL_ERROR;
	}

	INFO_MSG("sldpop plugin initialisation complete");

	return ERV_OK;
}

/* Plugin uninitialisation */
eemo_rv eemo_sldpop_uninit(eemo_export_fn_table_ptr eemo_fn)
{
	INFO_MSG("Uninitialising sldpop plugin");

	/* Unregister DNS handler */
	if ((eemo_fn->unreg_dns_handler)(dns_handler_handle) != ERV_OK)
	{
		ERROR_MSG("Failed to unregister sldpop DNS handler");
	}

	/* Clean up */
	free(sld_to_monitor);
	free(stats_file);

	INFO_MSG("Finished uninitialising sldpop plugin");

	return ERV_OK;
}

/* Retrieve plugin description */
const char* eemo_sldpop_getdescription(void)
{
	return plugin_description;
}

/* Retrieve plugin status */
eemo_rv eemo_sldpop_status(void)
{
	return ERV_OK;
}

/* Plugin function table */
static eemo_plugin_fn_table sldpop_fn_table =
{
	EEMO_PLUGIN_FN_VERSION,
	&eemo_sldpop_init,
	&eemo_sldpop_uninit,
	&eemo_sldpop_getdescription,
	&eemo_sldpop_status
};

/* Entry point for retrieving plugin function table */
eemo_rv eemo_plugin_get_fn_table(eemo_plugin_fn_table_ptrptr fn_table)
{
	if (fn_table == NULL)
	{
		return ERV_PARAM_INVALID;
	}

	*fn_table = &sldpop_fn_table;

	return ERV_OK;
}

