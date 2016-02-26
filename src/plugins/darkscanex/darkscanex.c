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
#include "uthash.h"

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

typedef struct dscan_ht_ent
{
	char		name[512];
	unsigned int	qt_count[256];
	unsigned int	qt_other_count;
	unsigned int	w_edns0[2];
	unsigned int	edns0_max_size;
	time_t		first_seen;
	time_t		last_seen;
	UT_hash_handle	hh;
}
dscan_ht_ent;

static dscan_ht_ent*	query_ht	= NULL;
static dscan_ht_ent*	response_ht	= NULL;

/* Output some statistics */
static void eemo_darkscanex_int_stats(void)
{
	static time_t	mark	= 0;

	if ((time(NULL) - mark) >= 60)
	{
		mark = time(NULL);

		INFO_MSG("Counted %llu queries, %llu malformed queries, %llu responses and %llu malformed responses", q_count, mq_count, r_count, mr_count);

		INFO_MSG("Query hash table has %d entries, response hash table has %d entries", HASH_COUNT(query_ht), HASH_COUNT(response_ht));
	}
}

/* DNS handler */
eemo_rv eemo_darkscanex_dns_handler(eemo_ip_packet_info ip_info, int is_tcp, const eemo_dns_packet* pkt)
{
	if (pkt->qr_flag)
	{
		if (pkt->questions != NULL)
		{
			dscan_ht_ent*	response_ent	= NULL;

			r_count++;

			HASH_FIND_STR(response_ht, pkt->questions->qname, response_ent);

			if (response_ent == NULL)
			{
				response_ent = (dscan_ht_ent*) malloc(sizeof(dscan_ht_ent));

				memset(response_ent, 0, sizeof(dscan_ht_ent));

				strcpy(response_ent->name, pkt->questions->qname);

				response_ent->first_seen = (time_t) ip_info.ts.tv_sec;

				HASH_ADD_STR(response_ht, name, response_ent);
			}

			if (pkt->questions->qtype > 255)
			{
				response_ent->qt_other_count++;
			}
			else
			{
				response_ent->qt_count[pkt->questions->qtype]++;
			}

			if (pkt->has_edns0)
			{
				response_ent->w_edns0[1]++;

				if (pkt->edns0_max_size > response_ent->edns0_max_size)
				{
					response_ent->edns0_max_size = pkt->edns0_max_size;
				}
			}
			else
			{
				response_ent->w_edns0[0]++;
			}

			response_ent->last_seen = (time_t) ip_info.ts.tv_sec;
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
			dscan_ht_ent*	query_ent	= NULL;

			q_count++;

			HASH_FIND_STR(query_ht, pkt->questions->qname, query_ent);

			if (query_ent == NULL)
			{
				query_ent = (dscan_ht_ent*) malloc(sizeof(dscan_ht_ent));

				memset(query_ent, 0, sizeof(dscan_ht_ent));

				strcpy(query_ent->name, pkt->questions->qname);

				query_ent->first_seen = (time_t) ip_info.ts.tv_sec;

				HASH_ADD_STR(query_ht, name, query_ent);
			}

			if (pkt->questions->qtype > 255)
			{
				query_ent->qt_other_count++;
			}
			else
			{
				query_ent->qt_count[pkt->questions->qtype]++;
			}

			if (pkt->has_edns0)
			{
				query_ent->w_edns0[1]++;

				if (pkt->edns0_max_size > query_ent->edns0_max_size)
				{
					query_ent->edns0_max_size = pkt->edns0_max_size;
				}
			}
			else
			{
				query_ent->w_edns0[0]++;
			}

			query_ent->last_seen = (time_t) ip_info.ts.tv_sec;
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
	if ((eemo_fn->reg_dns_handler)(&eemo_darkscanex_dns_handler, PARSE_QUERY | PARSE_RESPONSE, &dns_handler_handle) != ERV_OK)
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
	dscan_ht_ent*	ht_it	= NULL;
	dscan_ht_ent*	ht_tmp	= NULL;

	INFO_MSG("Uninitialising darkscanex plugin");

	/* Unregister DNS handler */
	if ((eemo_fn->unreg_dns_handler)(dns_handler_handle) != ERV_OK)
	{
		ERROR_MSG("Failed to unregister darkscanex DNS handler");
	}

	if (query_out_file != NULL)
	{
		/* Write out query hash table */
		INFO_MSG("Outputting query hash table");

		HASH_ITER(hh, query_ht, ht_it, ht_tmp)
		{
			int	i	= 0;

			for (i = 0; i < 255; i++)
			{
				if (ht_it->qt_count[i] > 0)
				{
					fprintf(query_out_file, "%s;%u;%u;%d;%u;-1;-1;-1\n", ht_it->name, (unsigned int) ht_it->first_seen, (unsigned int) ht_it->last_seen, i, ht_it->qt_count[i]);
				}

				if (ht_it->qt_other_count > 0)
				{
					fprintf(query_out_file, "%s;%u;%u;65537;%u;-1;-1;-1\n", ht_it->name, (unsigned int) ht_it->first_seen, (unsigned int) ht_it->last_seen, ht_it->qt_other_count);
				}
			}

			if (ht_it->w_edns0[0] > 0)
			{
				fprintf(query_out_file, "%s;%u;%u;-1;-1;%u;-1;-1\n", ht_it->name, (unsigned int) ht_it->first_seen, (unsigned int) ht_it->last_seen, ht_it->w_edns0[0]);
			}
			
			if (ht_it->w_edns0[1] > 0)
			{
				fprintf(query_out_file, "%s;%u;%u;-1;-1;-1;%u;%u\n", ht_it->name, (unsigned int) ht_it->first_seen, (unsigned int) ht_it->last_seen, ht_it->w_edns0[1], ht_it->edns0_max_size);
			}
		}

		fclose(query_out_file);
	}

	if (response_out_file != NULL)
	{
		INFO_MSG("Outputting response hash table");

		HASH_ITER(hh, response_ht, ht_it, ht_tmp)
		{
			int	i	= 0;

			for (i = 0; i < 255; i++)
			{
				if (ht_it->qt_count[i] > 0)
				{
					fprintf(response_out_file, "%s;%u;%u;%d;%u;-1;-1;-1\n", ht_it->name, (unsigned int) ht_it->first_seen, (unsigned int) ht_it->last_seen, i, ht_it->qt_count[i]);
				}

				if (ht_it->qt_other_count > 0)
				{
					fprintf(response_out_file, "%s;%u;%u;65537;%u;-1;-1;-1\n", ht_it->name, (unsigned int) ht_it->first_seen, (unsigned int) ht_it->last_seen, ht_it->qt_other_count);
				}
			}

			if (ht_it->w_edns0[0] > 0)
			{
				fprintf(response_out_file, "%s;%u;%u;-1;-1;%u;-1;-1\n", ht_it->name, (unsigned int) ht_it->first_seen, (unsigned int) ht_it->last_seen, ht_it->w_edns0[0]);
			}
			
			if (ht_it->w_edns0[1] > 0)
			{
				fprintf(response_out_file, "%s;%u;%u;-1;-1;-1;%u;%u\n", ht_it->name, (unsigned int) ht_it->first_seen, (unsigned int) ht_it->last_seen, ht_it->w_edns0[1], ht_it->edns0_max_size);
			}
		}

		fclose(response_out_file);
	}

	/* Clean up hash tables */
	HASH_ITER(hh, query_ht, ht_it, ht_tmp)
	{
		HASH_DEL(query_ht, ht_it);
		free(ht_it);
	}

	HASH_ITER(hh, response_ht, ht_it, ht_tmp)
	{
		HASH_DEL(response_ht, ht_it);
		free(ht_it);
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

