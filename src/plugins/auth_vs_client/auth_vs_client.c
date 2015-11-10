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
#include <wait.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include "utlist.h"
#include "eemo.h"
#include "eemo_api.h"
#include "eemo_plugin_log.h"
#include "dns_handler.h"
#include "dns_parser.h"

const static char* plugin_description = "EEMO DNS query monitoring plugin " PACKAGE_VERSION;

/* DNS handler handles */
static unsigned long	dns_handler_handle	= 0;

/* Monitored name */
static char*		monitor_name		= NULL;

/* Resolver IPs */
static char**		resolver_ips		= NULL;
static int		resolver_ips_count	= 0;

/* Output files */
static FILE*		auth_queries_fd		= NULL;
static FILE*		client_queries_fd	= NULL;

/* DNS handler */
eemo_rv eemo_auth_vs_client_dns_handler(eemo_ip_packet_info ip_info, int is_tcp, const eemo_dns_packet* pkt)
{
	eemo_dns_query*	q_it	= NULL;

	/* Skip responses immediately */
	if (pkt->qr_flag) return ERV_SKIPPED;

	/* Make sure there are questions in the query */
	if (pkt->questions == NULL) return ERV_SKIPPED;

	/* Iterate over the answers and extract the DNSKEY records */
	LL_FOREACH(pkt->questions, q_it)
	{
		if ((q_it->qname == NULL) || (strlen(q_it->qname) < strlen(monitor_name))) continue;

		if (strcmp(&q_it->qname[strlen(q_it->qname)-strlen(monitor_name)], monitor_name) == 0)
		{
			/* Match! */
			FILE*	out	= client_queries_fd;
			int	i	= 0;

			for (i = 0; i < resolver_ips_count; i++)
			{
				if (strcmp(ip_info.ip_src, resolver_ips[i]) == 0)
				{
					out = auth_queries_fd;
					break;
				}
			}

			fprintf(out, "%u;%s;%s;%s\n", (unsigned int) ip_info.ts.tv_sec, ip_info.ip_src, ip_info.ip_dst, q_it->qname);
			fflush(out);
		}
	}

	return ERV_HANDLED;
}

/* Plugin initialisation */
eemo_rv eemo_auth_vs_client_init(eemo_export_fn_table_ptr eemo_fn, const char* conf_base_path)
{
	char*	auth_queries_file	= NULL;
	char*	client_queries_file	= NULL;

	/* Initialise logging for the plugin */
	eemo_init_plugin_log(eemo_fn->log);

	INFO_MSG("Initialising query monitoring plugin");

	if (((eemo_fn->conf_get_string)(conf_base_path, "auth_file", &auth_queries_file, NULL) != ERV_OK) || (auth_queries_file == NULL))
	{
		ERROR_MSG("Could not get output file name for queries to the authoritative name servers from the configuration");

		return ERV_CONFIG_ERROR;
	}

	auth_queries_fd = fopen(auth_queries_file, "a");

	if (auth_queries_fd == NULL)
	{
		ERROR_MSG("Failed to open %s for writing", auth_queries_file);

		free(auth_queries_file);

		return ERV_GENERAL_ERROR;
	}

	free(auth_queries_file);

	if (((eemo_fn->conf_get_string)(conf_base_path, "client_file", &client_queries_file, NULL) != ERV_OK) || (client_queries_file == NULL))
	{
		ERROR_MSG("Could not get output file name for queries from clients from the configuration");

		return ERV_CONFIG_ERROR;
	}

	client_queries_fd = fopen(client_queries_file, "a");

	if (client_queries_fd == NULL)
	{
		ERROR_MSG("Failed to open %s for writing", client_queries_file);

		free(client_queries_file);

		return ERV_GENERAL_ERROR;
	}

	free(client_queries_file);

	/* Retrieve the name to monitor */
	if (((eemo_fn->conf_get_string)(conf_base_path, "monitor_name", &monitor_name, NULL) != ERV_OK) || (monitor_name == NULL))
	{
		ERROR_MSG("Failed to retrieve the name to monitor queries for from the configuration");

		return ERV_CONFIG_ERROR;
	}

	/* Retrieve IP addresses for the resolver */
	if ((eemo_fn->conf_get_string_array(conf_base_path, "resolver_ips", &resolver_ips, &resolver_ips_count) != ERV_OK) || (resolver_ips_count <= 0))
	{
		ERROR_MSG("Could not retrieve resolver IPs from the configuration");

		return ERV_CONFIG_ERROR;
	}

	/* Register DNS handler */
	if ((eemo_fn->reg_dns_handler)(&eemo_auth_vs_client_dns_handler, PARSE_QUERY|PARSE_RESPONSE|PARSE_CANONICALIZE_NAME, &dns_handler_handle) != ERV_OK)
	{
		ERROR_MSG("Failed to register auth_vs_client DNS handler");

		(eemo_fn->unreg_dns_handler)(dns_handler_handle);

		return ERV_GENERAL_ERROR;
	}

	INFO_MSG("Query monitoring plugin initialisation complete");

	return ERV_OK;
}

/* Plugin uninitialisation */
eemo_rv eemo_auth_vs_client_uninit(eemo_export_fn_table_ptr eemo_fn)
{
	INFO_MSG("Uninitialising auth_vs_client plugin");

	/* Unregister DNS handler */
	if ((eemo_fn->unreg_dns_handler)(dns_handler_handle) != ERV_OK)
	{
		ERROR_MSG("Failed to unregister auth_vs_client DNS handler");
	}

	if (auth_queries_fd != NULL)
	{
		fclose(auth_queries_fd);
	}

	if (client_queries_fd != NULL)
	{
		fclose(client_queries_fd);
	}

	if (resolver_ips_count > 0)
	{
		(eemo_fn->conf_free_string_array)(resolver_ips, resolver_ips_count);	
	}

	free(monitor_name);

	INFO_MSG("Finished uninitialising auth_vs_client plugin");

	return ERV_OK;
}

/* Retrieve plugin description */
const char* eemo_auth_vs_client_getdescription(void)
{
	return plugin_description;
}

/* Retrieve plugin status */
eemo_rv eemo_auth_vs_client_status(void)
{
	return ERV_OK;
}

/* Plugin function table */
static eemo_plugin_fn_table auth_vs_client_fn_table =
{
	EEMO_PLUGIN_FN_VERSION,
	&eemo_auth_vs_client_init,
	&eemo_auth_vs_client_uninit,
	&eemo_auth_vs_client_getdescription,
	&eemo_auth_vs_client_status
};

/* Entry point for retrieving plugin function table */
eemo_rv eemo_plugin_get_fn_table(eemo_plugin_fn_table_ptrptr fn_table)
{
	if (fn_table == NULL)
	{
		return ERV_PARAM_INVALID;
	}

	*fn_table = &auth_vs_client_fn_table;

	return ERV_OK;
}

