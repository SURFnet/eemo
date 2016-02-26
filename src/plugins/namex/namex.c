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
 * Answer name extraction plugin
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
#include "eemo.h"
#include "eemo_api.h"
#include "eemo_plugin_log.h"
#include "dns_handler.h"
#include "dns_parser.h"

const static char* plugin_description = "EEMO DNS answer name extraction plugin " PACKAGE_VERSION;

/* DNS handler handles */
static unsigned long	dns_handler_handle	= 0;

/* Output file */
static FILE*		namex_file		= NULL;

/* DNS handler */
eemo_rv eemo_namex_dns_handler(eemo_ip_packet_info ip_info, int is_tcp, const eemo_dns_packet* pkt)
{
	eemo_dns_rr*	rr_it	= NULL;

	/* Skip queries immediately */
	if (!pkt->qr_flag) return ERV_SKIPPED;

	/* Skip non-authoritative answers */
	if (!pkt->aa_flag) return ERV_SKIPPED;

	/* Only look at responses that actually contain answers */
	if (pkt->ans_count == 0) return ERV_SKIPPED;

	/* Iterate over the answers and extract the DNSKEY records */
	LL_FOREACH(pkt->answers, rr_it)
	{
		/* Output the answer name */
		fprintf(namex_file, "%s\n", rr_it->name);
	}

	return ERV_HANDLED;
}

/* Plugin initialisation */
eemo_rv eemo_namex_init(eemo_export_fn_table_ptr eemo_fn, const char* conf_base_path)
{
	char*	namex_file_name		= NULL;

	/* Initialise logging for the plugin */
	eemo_init_plugin_log(eemo_fn->log);

	INFO_MSG("Initialising answer name extraction plugin");

	if (((eemo_fn->conf_get_string)(conf_base_path, "out_file", &namex_file_name, NULL) != ERV_OK) || (namex_file_name == NULL))
	{
		ERROR_MSG("Could not get output file name from the configuration");

		return ERV_CONFIG_ERROR;
	}

	namex_file = fopen(namex_file_name, "w");

	if (namex_file == NULL)
	{
		ERROR_MSG("Failed to open %s for writing", namex_file_name);

		free(namex_file_name);

		return ERV_GENERAL_ERROR;
	}

	free(namex_file_name);

	/* Register DNS handler */
	if ((eemo_fn->reg_dns_handler)(&eemo_namex_dns_handler, PARSE_QUERY|PARSE_RESPONSE, &dns_handler_handle) != ERV_OK)
	{
		ERROR_MSG("Failed to register namex DNS handler");

		(eemo_fn->unreg_dns_handler)(dns_handler_handle);

		return ERV_GENERAL_ERROR;
	}

	INFO_MSG("Answer name extraction plugin initialisation complete");

	return ERV_OK;
}

/* Plugin uninitialisation */
eemo_rv eemo_namex_uninit(eemo_export_fn_table_ptr eemo_fn)
{
	INFO_MSG("Uninitialising namex plugin");

	/* Unregister DNS handler */
	if ((eemo_fn->unreg_dns_handler)(dns_handler_handle) != ERV_OK)
	{
		ERROR_MSG("Failed to unregister namex DNS handler");
	}

	if (namex_file != NULL)
	{
		fclose(namex_file);
	}

	INFO_MSG("Finished uninitialising namex plugin");

	return ERV_OK;
}

/* Retrieve plugin description */
const char* eemo_namex_getdescription(void)
{
	return plugin_description;
}

/* Retrieve plugin status */
eemo_rv eemo_namex_status(void)
{
	return ERV_OK;
}

/* Plugin function table */
static eemo_plugin_fn_table namex_fn_table =
{
	EEMO_PLUGIN_FN_VERSION,
	&eemo_namex_init,
	&eemo_namex_uninit,
	&eemo_namex_getdescription,
	&eemo_namex_status
};

/* Entry point for retrieving plugin function table */
eemo_rv eemo_plugin_get_fn_table(eemo_plugin_fn_table_ptrptr fn_table)
{
	if (fn_table == NULL)
	{
		return ERV_PARAM_INVALID;
	}

	*fn_table = &namex_fn_table;

	return ERV_OK;
}

