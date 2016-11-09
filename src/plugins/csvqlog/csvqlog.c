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
 * Compact CSV DNS query logging plugin
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

const static char* plugin_description = "EEMO DNS compact CSV query logging plugin " PACKAGE_VERSION;

/* DNS handler handles */
static unsigned long	dns_handler_handle	= 0;

/* Output file */
static FILE*		csvqlog_file		= NULL;

/* DNS handler */
eemo_rv eemo_csvqlog_dns_handler(eemo_ip_packet_info ip_info, int is_tcp, const eemo_dns_packet* pkt)
{
	/* Skip responses immediately */
	if (pkt->qr_flag) return ERV_SKIPPED;

	/* Log query details */
	/*fprintf(csvqlog, "timestamp,src_ip,qname,qclass,qtype,has_edns0,edns0_bufsize,edns0_do,is_tcp\n");*/

	/* Log query timestamp with microsecond precision */
	fprintf(csvqlog_file, "%u.%6d,", (unsigned int) ip_info.ts.tv_sec, (int) ip_info.ts.tv_usec);

	/* Log source IP from which the query originated */
	fprintf(csvqlog_file, "%s,", ip_info.ip_src);

	/* Log the query name, class and type */
	if (pkt->questions != NULL)
	{
		fprintf(csvqlog_file, "%s,%d,%d,", pkt->questions->qname, pkt->questions->qclass, pkt->questions->qtype);
	}
	else
	{
		fprintf(csvqlog_file, "(null),-1,-1,");
	}

	/* Log EDNS0 information */
	if (pkt->has_edns0)
	{
		fprintf(csvqlog_file, "%d,%d,%d,", pkt->has_edns0, pkt->edns0_max_size, pkt->edns0_do);
	}
	else
	{
		fprintf(csvqlog_file, "0,0,0,");
	}

	/* Log TCP information */
	fprintf(csvqlog_file, "%d\n", is_tcp);

	return ERV_HANDLED;
}

/* Plugin initialisation */
eemo_rv eemo_csvqlog_init(eemo_export_fn_table_ptr eemo_fn, const char* conf_base_path)
{
	char*	csvqlog_file_name		= NULL;

	/* Initialise logging for the plugin */
	eemo_init_plugin_log(eemo_fn->log);

	INFO_MSG("Initialising compact CSV DNS query logging plugin");

	if (((eemo_fn->conf_get_string)(conf_base_path, "out_file", &csvqlog_file_name, NULL) != ERV_OK) || (csvqlog_file_name == NULL))
	{
		ERROR_MSG("Could not get output file name from the configuration");

		return ERV_CONFIG_ERROR;
	}

	csvqlog_file = fopen(csvqlog_file_name, "w");

	if (csvqlog_file == NULL)
	{
		ERROR_MSG("Failed to open %s for writing", csvqlog_file_name);

		free(csvqlog_file_name);

		return ERV_GENERAL_ERROR;
	}

	free(csvqlog_file_name);

	/* Register DNS handler */
	if ((eemo_fn->reg_dns_handler)(&eemo_csvqlog_dns_handler, PARSE_QUERY|PARSE_CANONICALIZE_NAME, &dns_handler_handle) != ERV_OK)
	{
		ERROR_MSG("Failed to register csvqlog DNS handler");

		(eemo_fn->unreg_dns_handler)(dns_handler_handle);

		return ERV_GENERAL_ERROR;
	}

	/* Write CSV header */
	fprintf(csvqlog_file, "timestamp,src_ip,qname,qclass,qtype,has_edns0,edns0_bufsize,edns0_do,is_tcp\n");

	INFO_MSG("Compact CSV DNS query logging plugin initialisation complete");

	return ERV_OK;
}

/* Plugin uninitialisation */
eemo_rv eemo_csvqlog_uninit(eemo_export_fn_table_ptr eemo_fn)
{
	INFO_MSG("Uninitialising csvqlog plugin");

	/* Unregister DNS handler */
	if ((eemo_fn->unreg_dns_handler)(dns_handler_handle) != ERV_OK)
	{
		ERROR_MSG("Failed to unregister csvqlog DNS handler");
	}

	if (csvqlog_file != NULL)
	{
		fclose(csvqlog_file);
	}

	INFO_MSG("Finished uninitialising csvqlog plugin");

	return ERV_OK;
}

/* Retrieve plugin description */
const char* eemo_csvqlog_getdescription(void)
{
	return plugin_description;
}

/* Retrieve plugin status */
eemo_rv eemo_csvqlog_status(void)
{
	return ERV_OK;
}

/* Plugin function table */
static eemo_plugin_fn_table csvqlog_fn_table =
{
	EEMO_PLUGIN_FN_VERSION,
	&eemo_csvqlog_init,
	&eemo_csvqlog_uninit,
	&eemo_csvqlog_getdescription,
	&eemo_csvqlog_status
};

/* Entry point for retrieving plugin function table */
eemo_rv eemo_plugin_get_fn_table(eemo_plugin_fn_table_ptrptr fn_table)
{
	if (fn_table == NULL)
	{
		return ERV_PARAM_INVALID;
	}

	*fn_table = &csvqlog_fn_table;

	return ERV_OK;
}

