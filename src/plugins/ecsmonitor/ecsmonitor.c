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
 * EDNS0 client subnet monitoring plugin
 */

#include "config.h"
#include <stdlib.h>
#include <stdio.h>
#include "eemo.h"
#include "eemo_api.h"
#include "eemo_plugin_log.h"
#include "dns_handler.h"
#include "dns_parser.h"

const static char* plugin_description = "EEMO EDNS0 client subnet monitoring plugin " PACKAGE_VERSION;

/* DNS handler handles */
static unsigned long	dns_handler_handle	= 0;

/* Output file */
static FILE*		edns0_mon_file		= NULL;

/* DNS handler */
eemo_rv eemo_ecsmonitor_dns_handler(eemo_ip_packet_info ip_info, int is_tcp, const eemo_dns_packet* pkt)
{
	/* Skip responses immediately */
	if (pkt->qr_flag) return ERV_SKIPPED;

	/* Check if this query has EDNS0 client subnet information */
	if (pkt->has_edns0 && pkt->has_edns0_client_subnet && (pkt->questions != NULL))
	{
		fprintf(edns0_mon_file, "%u;%u;%s;%s;%u;%s;%s;%s;%s\n",
			(unsigned int) ip_info.ts.tv_sec,
			pkt->questions->qtype,
			ip_info.ip_src,
			pkt->edns0_client_subnet_ip,
			pkt->edns0_client_subnet_src_scope,
			ip_info.src_as_short,
			ip_info.src_geo_ip,
			pkt->edns0_client_subnet_as_short,
			pkt->edns0_client_subnet_geo_ip);

		return ERV_HANDLED;
	}
	else
	{
		return ERV_SKIPPED;
	}
}

/* Plugin initialisation */
eemo_rv eemo_ecsmonitor_init(eemo_export_fn_table_ptr eemo_fn, const char* conf_base_path)
{
	char*	out_file	= NULL;

	/* Initialise logging for the plugin */
	eemo_init_plugin_log(eemo_fn->log);

	INFO_MSG("Initialising ecsmonitor plugin");

	if (((eemo_fn->conf_get_string)(conf_base_path, "out_file", &out_file, NULL) != ERV_OK) || (out_file == NULL))
	{
		ERROR_MSG("Could not get output file for EDNS0 client subnet monitoring plugin from the configuration");

		return ERV_CONFIG_ERROR;
	}

	/* Open output file */
	if ((edns0_mon_file = fopen(out_file, "a")) == NULL)
	{
		ERROR_MSG("Failed to open or append %s for writing", out_file);

		free(out_file);

		return ERV_NO_ACCESS;
	}

	free(out_file);

	/* Write CSV header if the file is empty */
	if (ftell(edns0_mon_file) == 0)
	{
		fprintf(edns0_mon_file, "timestamp;qtype;q_src;ecs_ip;ecs_scope;q_as;q_geoip;ecs_ip_as;ecs_ip_geoip\n");
	}

	/* Register DNS handler */
	if ((eemo_fn->reg_dns_handler)(&eemo_ecsmonitor_dns_handler, PARSE_QUERY, &dns_handler_handle) != ERV_OK)
	{
		ERROR_MSG("Failed to register ecsmonitor DNS handler");

		(eemo_fn->unreg_dns_handler)(dns_handler_handle);

		return ERV_GENERAL_ERROR;
	}

	INFO_MSG("Demo plugin initialisation complete");

	return ERV_OK;
}

/* Plugin uninitialisation */
eemo_rv eemo_ecsmonitor_uninit(eemo_export_fn_table_ptr eemo_fn)
{
	INFO_MSG("Uninitialising ecsmonitor plugin");

	/* Unregister DNS handler */
	if ((eemo_fn->unreg_dns_handler)(dns_handler_handle) != ERV_OK)
	{
		ERROR_MSG("Failed to unregister ecsmonitor DNS handler");
	}

	fclose(edns0_mon_file);

	INFO_MSG("Finished uninitialising ecsmonitor plugin");

	return ERV_OK;
}

/* Retrieve plugin description */
const char* eemo_ecsmonitor_getdescription(void)
{
	return plugin_description;
}

/* Retrieve plugin status */
eemo_rv eemo_ecsmonitor_status(void)
{
	return ERV_OK;
}

/* Plugin function table */
static eemo_plugin_fn_table ecsmonitor_fn_table =
{
	EEMO_PLUGIN_FN_VERSION,
	&eemo_ecsmonitor_init,
	&eemo_ecsmonitor_uninit,
	&eemo_ecsmonitor_getdescription,
	&eemo_ecsmonitor_status
};

/* Entry point for retrieving plugin function table */
eemo_rv eemo_plugin_get_fn_table(eemo_plugin_fn_table_ptrptr fn_table)
{
	if (fn_table == NULL)
	{
		return ERV_PARAM_INVALID;
	}

	*fn_table = &ecsmonitor_fn_table;

	return ERV_OK;
}

