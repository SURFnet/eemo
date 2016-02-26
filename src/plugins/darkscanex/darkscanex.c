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
 * Plugin to extract scanning DNS queries
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
#include "eemo.h"
#include "eemo_api.h"
#include "eemo_plugin_log.h"
#include "dns_handler.h"
#include "dns_parser.h"

const static char* plugin_description = "EEMO DNS scanning extraction plugin " PACKAGE_VERSION;

/* DNS handler handles */
static unsigned long		dns_handler_handle	= 0;

/* Output files */
static FILE*			query_out_file		= NULL;
static FILE*			response_out_file	= NULL;

static unsigned long long	q_count			= 0;
static unsigned long long	mq_count		= 0;
static unsigned long long	r_count			= 0;
static unsigned long long	mr_count		= 0;

/* Output some statistics */
static void eemo_darkscanex_int_stats(void)
{
	static time_t	mark	= 0;

	if ((time(NULL) - mark) >= 60)
	{
		mark = time(NULL);

		INFO_MSG("Counted %llu queries, %llu malformed queries, %llu responses and %llu malformed responses", q_count, mq_count, r_count, mr_count);
	}
}

/* DNS handler */
eemo_rv eemo_darkscanex_dns_handler(eemo_ip_packet_info ip_info, int is_tcp, const eemo_dns_packet* pkt)
{
	if (pkt->qr_flag)
	{
		if (pkt->questions != NULL)
		{
			r_count++;

			fprintf(query_out_file, "%u;%s;%5u;%5u;%d;%u\n",
				(unsigned int) ip_info.ts.tv_sec,
				pkt->questions->qname,
				pkt->questions->qclass,
				pkt->questions->qtype,
				pkt->has_edns0,
				pkt->has_edns0 ? pkt->edns0_max_size : 0);
		}
		else
		{
			mr_count++;
		}
	}
	else
	{
		if (pkt->questions != NULL)
		{
			q_count++;

			fprintf(query_out_file, "%u;%s;%5u;%5u;%d;%u\n",
				(unsigned int) ip_info.ts.tv_sec,
				pkt->questions->qname,
				pkt->questions->qclass,
				pkt->questions->qtype,
				pkt->has_edns0,
				pkt->has_edns0 ? pkt->edns0_max_size : 0);
		}
		else
		{
			mq_count++;
		}
	}

	eemo_darkscanex_int_stats();

	return ERV_HANDLED;
}

/* Plugin initialisation */
eemo_rv eemo_darkscanex_init(eemo_export_fn_table_ptr eemo_fn, const char* conf_base_path)
{
	char*	query_out_file_name	= NULL;
	char*	response_out_file_name	= NULL;

	/* Initialise logging for the plugin */
	eemo_init_plugin_log(eemo_fn->log);

	INFO_MSG("Initialising darkscanex plugin");

	if (((eemo_fn->conf_get_string)(conf_base_path, "query_out_file", &query_out_file_name, NULL) != ERV_OK) || (query_out_file_name == NULL))
	{
		ERROR_MSG("Could not get query output file from the configuration");

		return ERV_CONFIG_ERROR;
	}

	query_out_file = fopen(query_out_file_name, "a");

	if (query_out_file == NULL)
	{
		ERROR_MSG("Failed to append query output file %s", query_out_file_name);

		free(query_out_file_name);

		fclose(query_out_file);

		return ERV_GENERAL_ERROR;
	}

	free(query_out_file_name);

	if (((eemo_fn->conf_get_string)(conf_base_path, "response_out_file", &response_out_file_name, NULL) != ERV_OK) || (response_out_file_name == NULL))
	{
		ERROR_MSG("Could not get response output file from the configuration");

		return ERV_CONFIG_ERROR;
	}

	response_out_file = fopen(response_out_file_name, "a");

	if (response_out_file == NULL)
	{
		ERROR_MSG("Failed to append response output file %s", response_out_file_name);

		free(response_out_file_name);

		fclose(query_out_file);

		return ERV_GENERAL_ERROR;
	}

	free(response_out_file_name);

	/* Register DNS handler */
	if ((eemo_fn->reg_dns_handler)(&eemo_darkscanex_dns_handler, PARSE_QUERY, &dns_handler_handle) != ERV_OK)
	{
		ERROR_MSG("Failed to register darkscanex DNS handler");

		(eemo_fn->unreg_dns_handler)(dns_handler_handle);

		return ERV_GENERAL_ERROR;
	}

	INFO_MSG("darkscanex plugin initialisation complete");

	return ERV_OK;
}

/* Plugin uninitialisation */
eemo_rv eemo_darkscanex_uninit(eemo_export_fn_table_ptr eemo_fn)
{
	INFO_MSG("Uninitialising darkscanex plugin");

	/* Unregister DNS handler */
	if ((eemo_fn->unreg_dns_handler)(dns_handler_handle) != ERV_OK)
	{
		ERROR_MSG("Failed to unregister darkscanex DNS handler");
	}

	if (query_out_file != NULL)
	{
		fclose(query_out_file);
	}

	if (response_out_file != NULL)
	{
		fclose(response_out_file);
	}

	INFO_MSG("Finished uninitialising darkscanex plugin");

	return ERV_OK;
}

/* Retrieve plugin description */
const char* eemo_darkscanex_getdescription(void)
{
	return plugin_description;
}

/* Retrieve plugin status */
eemo_rv eemo_darkscanex_status(void)
{
	return ERV_OK;
}

/* Plugin function table */
static eemo_plugin_fn_table darkscanex_fn_table =
{
	EEMO_PLUGIN_FN_VERSION,
	&eemo_darkscanex_init,
	&eemo_darkscanex_uninit,
	&eemo_darkscanex_getdescription,
	&eemo_darkscanex_status
};

/* Entry point for retrieving plugin function table */
eemo_rv eemo_plugin_get_fn_table(eemo_plugin_fn_table_ptrptr fn_table)
{
	if (fn_table == NULL)
	{
		return ERV_PARAM_INVALID;
	}

	*fn_table = &darkscanex_fn_table;

	return ERV_OK;
}

