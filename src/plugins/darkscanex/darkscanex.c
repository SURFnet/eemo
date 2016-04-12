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
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include "eemo.h"
#include "eemo_api.h"
#include "eemo_plugin_log.h"
#include "dns_handler.h"
#include "dns_parser.h"
#include "uthash.h"

#define UNIQ_IP_STORAGE	256

const static char* plugin_description = "EEMO DNS scanning extraction plugin " PACKAGE_VERSION;

/* DNS handler handles */
static unsigned long		dns_handler_handle	= 0;

/* Output files */
static FILE*			query_out_file		= NULL;

static int			q_threshold		= 1;
static unsigned long long	q_multi_count		= 0;
static unsigned long long	q_count			= 0;
static unsigned long long	q_saturated_count	= 0;

static time_t			last_prune		= (time_t) 0;

static int			prune_interval		= 600;

static eemo_export_fn_table_ptr eemo_fn_tab		= NULL;

typedef struct dscan_ht_ent
{
	char		qname_qc_qt_edns[512];
	uint32_t	ip[UNIQ_IP_STORAGE];
	int		ip_count;
	hll_stor*	hll_ipcount;
	int		is_saturated;
	int		reached_threshold;
	time_t		first_seen;
	time_t		last_seen;
	int		seen_count;
	UT_hash_handle	hh;
}
dscan_ht_ent;

static dscan_ht_ent*	query_ht	= NULL;

static void eemo_darkscanex_int_qtostring(const eemo_dns_packet* pkt, char* str, const size_t str_len)
{
	snprintf(str, str_len, "%s_%05d_%05d_%d",
		pkt->questions->qname,
		pkt->questions->qclass,
		pkt->questions->qtype,
		pkt->has_edns0);
}

/* Output some statistics */
static void eemo_darkscanex_int_stats(void)
{
	static time_t	mark	= 0;

	if ((time(NULL) - mark) >= 60)
	{
		mark = time(NULL);

		INFO_MSG("Counted %llu queries", q_count);
		INFO_MSG("Counted %llu queries to more than %d IPs", q_multi_count, q_threshold);
		INFO_MSG("Counted %llu queries to %d IPs or more", q_saturated_count, UNIQ_IP_STORAGE);
		INFO_MSG("Query hash table has %d entries", HASH_COUNT(query_ht));
	}

	/* Periodically prune hash table */
	if ((time(NULL) - last_prune) >= prune_interval)
	{
		dscan_ht_ent*	ht_it	= NULL;
		dscan_ht_ent*	ht_tmp	= NULL;

		last_prune = time(NULL);

		INFO_MSG("Performing hash table prune");

		INFO_MSG("Hash table has %d entries before prune", HASH_COUNT(query_ht));

		HASH_ITER(hh, query_ht, ht_it, ht_tmp)
		{
			if (ht_it->is_saturated || ht_it->reached_threshold) continue;

			if (ht_it->ip_count == 1)
			{
				/* Single destination IP, has been there for at least a minute, prune it */
				if ((last_prune - ht_it->first_seen) >= 60)
				{
					HASH_DEL(query_ht, ht_it);
					free(ht_it);
				}
			}
			else if (ht_it->ip_count <= q_threshold)
			{
				/* Less than the threshold, has been there for at one prune interval */
				if ((last_prune - ht_it->first_seen) >= prune_interval)
				{
					HASH_DEL(query_ht, ht_it);
					free(ht_it);
				}
			}
		}

		INFO_MSG("Hash table has %d entries after prune", HASH_COUNT(query_ht));
	}
}

/* DNS handler */
eemo_rv eemo_darkscanex_dns_handler(eemo_ip_packet_info ip_info, int is_tcp, const eemo_dns_packet* pkt)
{
	if (pkt->qr_flag)
	{
		/* Don't do anything with responses */
		return ERV_SKIPPED;
	}
	else
	{
		/* Only look at query which have a destination within our darknet */
		const char*	cidr_match	= NULL;

		/* FIXME: we assume darknets are IPv4 only for the moment */
		if (((ip_info.ip_type == IP_TYPE_V4) && (eemo_fn_tab->cm_match_v4(ip_info.dst_addr.v4, &cidr_match) != ERV_OK)) ||
		    (ip_info.ip_type == IP_TYPE_V6))
		{
			/* Not matching the darknet as destination, skip it */
			return ERV_SKIPPED;
		}

		if ((pkt->questions != NULL) && (pkt->questions->qname != NULL))
		{
			char		qname_qc_qt_edns[512]	= { 0 };
			dscan_ht_ent*	query_ent		= NULL;
			int		i			= 0;

			eemo_darkscanex_int_qtostring(pkt, qname_qc_qt_edns, 512);

			q_count++;

			HASH_FIND_STR(query_ht, qname_qc_qt_edns, query_ent);

			if (query_ent == NULL)
			{
				query_ent = (dscan_ht_ent*) malloc(sizeof(dscan_ht_ent));

				memset(query_ent, 0, sizeof(dscan_ht_ent));

				eemo_darkscanex_int_qtostring(pkt, query_ent->qname_qc_qt_edns, 512);

				query_ent->first_seen = (time_t) ip_info.ts.tv_sec;

				HASH_ADD_STR(query_ht, qname_qc_qt_edns, query_ent);
			}

			query_ent->last_seen = (time_t) ip_info.ts.tv_sec;
			query_ent->seen_count++;

			if (!query_ent->is_saturated)
			{
				int	seen_before	= 0;

				/* Find a free slot to save the destination IP */
				for (i = 0; i < UNIQ_IP_STORAGE; i++)
				{
					if (query_ent->ip[i] == ip_info.dst_addr.v4)
					{
						seen_before = 1;
						break;
					}
				}

				if (!seen_before)
				{
					for (i = 0; i < UNIQ_IP_STORAGE; i++)
					{
						if (query_ent->ip[i] == 0)
						{
							query_ent->ip[i] = ip_info.dst_addr.v4;
							break;
						}
					}

					i++;
	
					query_ent->ip_count = i;
	
					if (i == (q_threshold + 1))
					{
						q_multi_count++;
						query_ent->reached_threshold = 1;
					}
	
					if (i == UNIQ_IP_STORAGE)
					{
						query_ent->is_saturated = 1;
						q_saturated_count++;
	
						INFO_MSG("Storage for query %s saturated, starting probabilistic counting", qname_qc_qt_edns);

						query_ent->hll_ipcount = (hll_stor*) malloc(sizeof(hll_stor));

						assert(query_ent->hll_ipcount != NULL);

						eemo_fn_tab->hll_init(*(query_ent->hll_ipcount));
	
						for (i = 0; i < UNIQ_IP_STORAGE; i++)
						{
							eemo_fn_tab->hll_add(*(query_ent->hll_ipcount), &query_ent->ip[i], sizeof(uint32_t));
						}
					}
				}
			}
			else
			{
				eemo_fn_tab->hll_add(*(query_ent->hll_ipcount), &ip_info.dst_addr.v4, sizeof(uint32_t));
			}
		}
	}

	eemo_darkscanex_int_stats();

	return ERV_HANDLED;
}

/* Plugin initialisation */
eemo_rv eemo_darkscanex_init(eemo_export_fn_table_ptr eemo_fn, const char* conf_base_path)
{
	char*	query_out_file_name	= NULL;
	char**	darknet_cidr_blocks	= NULL;
	int	darknet_cidr_block_ct	= 0;
	int	i			= 0;
	
	/* Keep function table */
	eemo_fn_tab = eemo_fn;

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

	if (((eemo_fn->conf_get_int)(conf_base_path, "query_threshold", &q_threshold, 1) != ERV_OK) || (q_threshold < 0))
	{
		ERROR_MSG("Failed to get query threshold from the configuration");

		return ERV_CONFIG_ERROR;
	}

	INFO_MSG("Assuming queries to %d or more IP addresses are scans", q_threshold);

	if (((eemo_fn->conf_get_int)(conf_base_path, "prune_interval", &prune_interval, 1800) != ERV_OK) || (prune_interval < 0))
	{
		ERROR_MSG("Failed to retrieve the hash table prune interval from the configuration");

		return ERV_CONFIG_ERROR;
	}

	INFO_MSG("Pruning query hash table every %d seconds", prune_interval);

	if (((eemo_fn->conf_get_string_array)(conf_base_path, "darknet_cidr_blocks", &darknet_cidr_blocks, &darknet_cidr_block_ct) != ERV_OK) || (darknet_cidr_block_ct == 0) || (darknet_cidr_blocks == NULL))
	{
		ERROR_MSG("Failed to retrieve list of darknet CIDR blocks from the configuration");

		return ERV_CONFIG_ERROR;
	}

	for (i = 0; i < darknet_cidr_block_ct; i++)
	{
		if ((eemo_fn->cm_add_block)(darknet_cidr_blocks[i], darknet_cidr_blocks[i]) != ERV_OK)
		{
			ERROR_MSG("Failed to add darknet CIDR block %s", darknet_cidr_blocks[i]);

			return ERV_CONFIG_ERROR;
		}

		INFO_MSG("Added darknet CIDR block %s", darknet_cidr_blocks[i]);
	}

	(eemo_fn->conf_free_string_array)(darknet_cidr_blocks, darknet_cidr_block_ct);

	/* Register DNS handler */
	if ((eemo_fn->reg_dns_handler)(&eemo_darkscanex_dns_handler, PARSE_QUERY, &dns_handler_handle) != ERV_OK)
	{
		ERROR_MSG("Failed to register darkscanex DNS handler");

		(eemo_fn->unreg_dns_handler)(dns_handler_handle);

		return ERV_GENERAL_ERROR;
	}

	INFO_MSG("darkscanex plugin initialisation complete");

	last_prune = time(NULL);

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
			if (ht_it->ip_count > q_threshold)
			{
				uint64_t	prob_count	= 0;

				if (ht_it->is_saturated)
				{
					prob_count = eemo_fn_tab->hll_count(*(ht_it->hll_ipcount));
				}

				fprintf(query_out_file, "%s;%d;%d;%llu;%d;%u;%u\n", ht_it->qname_qc_qt_edns, ht_it->ip_count, ht_it->is_saturated, (unsigned long long) prob_count, ht_it->seen_count, (unsigned int) ht_it->first_seen, (unsigned int) ht_it->last_seen);
			}
		}

		fclose(query_out_file);
	}

	/* Clean up hash tables */
	HASH_ITER(hh, query_ht, ht_it, ht_tmp)
	{
		HASH_DEL(query_ht, ht_it);
		free(ht_it->hll_ipcount);
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

