/*
 * Copyright (c) 2010-2017 SURFnet bv
 * Copyright (c) 2017 Roland van Rijswijk-Deij
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
 * High-precision timestamp logging of query source IPs
 */

#include "config.h"
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <assert.h>
#include <sys/wait.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include "utlist.h"
#include "uthash.h"
#include "eemo.h"
#include "eemo_api.h"
#include "eemo_plugin_log.h"
#include "dns_handler.h"
#include "dns_parser.h"

const static char* plugin_description = "EEMO high-precision timestamp query src IP logging plug-in " PACKAGE_VERSION;

/* DNS handler handles */
static unsigned long	dns_handler_handle	= 0;

/* Output file prefix */
static FILE*		out_query_csv		= NULL;

/* DNS handler */
eemo_rv eemo_qsrcips_dns_handler(eemo_ip_packet_info ip_info, int is_tcp, const eemo_dns_packet* pkt)
{
	if (pkt->qr_flag == 0)
	{
		/* Handle queries */
		fprintf(out_query_csv, "%u.%llu,%s\n", (unsigned int) ip_info.ts.tv_sec, (unsigned long long) ip_info.ts.tv_usec, ip_info.ip_src);

		return ERV_HANDLED;
	}

	return ERV_SKIPPED;
}

/* Plugin initialisation */
eemo_rv eemo_qsrcips_init(eemo_export_fn_table_ptr eemo_fn, const char* conf_base_path)
{
	char*	out_file	= NULL;

	/* Initialise logging for the plugin */
	eemo_init_plugin_log(eemo_fn->log);

	INFO_MSG("Initialising high-precision timestamp query src logging plugin");

	if (((eemo_fn->conf_get_string)(conf_base_path, "out_file", &out_file, NULL) != ERV_OK) || (out_file == NULL))
	{
		ERROR_MSG("Could not get output file name from the configuration");

		return ERV_CONFIG_ERROR;
	}

	out_query_csv = fopen(out_file, "a");

	if (out_query_csv == NULL)
	{
		ERROR_MSG("Failed to open %s for writing", out_file);

		return ERV_CONFIG_ERROR;
	}

	/* Register DNS handler */
	if ((eemo_fn->reg_dns_handler)(&eemo_qsrcips_dns_handler, 0, &dns_handler_handle) != ERV_OK)
	{
		ERROR_MSG("Failed to register qsrcips DNS handler");

		(eemo_fn->unreg_dns_handler)(dns_handler_handle);

		return ERV_GENERAL_ERROR;
	}

	INFO_MSG("Plugin initialisation complete");

	return ERV_OK;
}

/* Plugin uninitialisation */
eemo_rv eemo_qsrcips_uninit(eemo_export_fn_table_ptr eemo_fn)
{
	INFO_MSG("Uninitialising qsrcips plugin");

	/* Unregister DNS handler */
	if ((eemo_fn->unreg_dns_handler)(dns_handler_handle) != ERV_OK)
	{
		ERROR_MSG("Failed to unregister qsrcips DNS handler");
	}

	if (out_query_csv != NULL)
	{
		fclose(out_query_csv);
		out_query_csv = NULL;
	}

	INFO_MSG("Finished uninitialising qsrcips plugin");

	return ERV_OK;
}

/* Retrieve plugin description */
const char* eemo_qsrcips_getdescription(void)
{
	return plugin_description;
}

/* Retrieve plugin status */
eemo_rv eemo_qsrcips_status(void)
{
	return ERV_OK;
}

/* Plugin function table */
static eemo_plugin_fn_table qsrcips_fn_table =
{
	EEMO_PLUGIN_FN_VERSION,
	&eemo_qsrcips_init,
	&eemo_qsrcips_uninit,
	&eemo_qsrcips_getdescription,
	&eemo_qsrcips_status
};

/* Entry point for retrieving plugin function table */
eemo_rv eemo_plugin_get_fn_table(eemo_plugin_fn_table_ptrptr fn_table)
{
	if (fn_table == NULL)
	{
		return ERV_PARAM_INVALID;
	}

	*fn_table = &qsrcips_fn_table;

	return ERV_OK;
}

