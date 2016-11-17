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
 * Query/response size distribution 
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

const static char* plugin_description = "EEMO DNS query/response size distribution mapping " PACKAGE_VERSION;

/* DNS handler handles */
static unsigned long	dns_handler_handle	= 0;

/* Output file name */
static char*		qrsizedist_name_prefix	= NULL;

/* Addresses of resolver to monitor */
static struct in_addr	v4_mon;
static int		v4_mon_set		= 0;
static struct in6_addr	v6_mon;
static int		v6_mon_set		= 0;

/* Matrix size */
static int		max_qsize		= 1500;
static int		max_rsize		= 4096;

/* Intervals */
static int		write_interval		= 3600;
static int		prune_timeout		= 30;

/* Query tracking hash table */
typedef struct
{
	char		key[2048];
	struct timeval	ts;
	int		qsize;
	UT_hash_handle	hh;
}
q_ht_ent;

static q_ht_ent*	q_ht	= NULL;

/* Statistics */
static int		dup_ht_keys		= 0;
static int		missing_queries		= 0;
static int		oversize_queries	= 0;
static int		oversize_responses	= 0;
static int		processed		= 0;

/* State */
static int*		qrdist_matrix		= NULL;
static time_t		next_write		= 0;

/* Add a query to the query hash table */
static void eemo_qrsizedist_int_add_query(const char* srcip, const char* qname, const uint16_t qclass, const uint16_t qtype, const uint16_t srcport, const uint16_t qid, const int qsize, const struct timeval* ts)
{
	char		qkey[2048]	= { 0 };
	q_ht_ent*	new_ent		= NULL;

	snprintf(qkey, 2048, "%s-%s-%04x-%04x-%04x-%04x", srcip, qname, qclass, qtype, srcport, qid);

	/* Ensure the query is not already in the hash table */
	HASH_FIND_STR(q_ht, qkey, new_ent);

	if (new_ent != NULL)
	{
		WARNING_MSG("Query from %s:%u for %u %u %s with ID %u is already in the state table, removing existing entry", srcip, srcport, qclass, qtype, qname, qid);

		HASH_DEL(q_ht, new_ent);

		free(new_ent);

		new_ent = NULL;
	}
	
	/* Add the query to the hash table */
	new_ent = (q_ht_ent*) malloc(sizeof(q_ht_ent));

	memset(new_ent, 0, sizeof(q_ht_ent));

	memcpy(new_ent->key, qkey, 2048);
	memcpy(&new_ent->ts, ts, sizeof(struct timeval));
	new_ent->qsize = qsize;

	HASH_ADD_STR(q_ht, key, new_ent);
}

/* Find the size of a query in the query hash table */
static int eemo_qrsizedist_int_find_qsize(const char* srcip, const char* qname, const uint16_t qclass, const uint16_t qtype, const uint16_t srcport, const uint16_t qid)
{
	int		found_qsize	= -1;
	q_ht_ent*	found_ent	= NULL;
	char		findkey[2048]	= { 0 };

	snprintf(findkey, 2048, "%s-%s-%04x-%04x-%04x-%04x", srcip, qname, qclass, qtype, srcport, qid);

	/* Try to find the query */
	HASH_FIND_STR(q_ht, findkey, found_ent);

	if (found_ent == NULL)
	{
		WARNING_MSG("Could not find query from %s:%u for %u %u %s with ID %u", srcip, srcport, qclass, qtype, qname, qid); 
	}
	else
	{
		found_qsize = found_ent->qsize;

		HASH_DEL(q_ht, found_ent);

		free(found_ent);
	}

	return found_qsize;
}

/* Prune the query hash table */
static void eemo_qrsizedist_int_prune_qht(void)
{
	q_ht_ent*	ht_it		= NULL;
	q_ht_ent*	ht_tmp		= NULL;
	time_t		now		= time(NULL);
	int		prune_count	= 0;

	HASH_ITER(hh, q_ht, ht_it, ht_tmp)
	{
		if ((now - ht_it->ts.tv_sec) >= prune_timeout)
		{
			HASH_DEL(q_ht, ht_it);
			free(ht_it);
			prune_count++;
		}
	}

	INFO_MSG("Pruned %d queries from the state table", prune_count);
}

/* Write to file if applicable */
static void eemo_qrsizedist_int_write(const struct timeval* ts, const int force)
{
	time_t	now	= time(NULL);

	if (force || (now >= next_write))
	{
		char	out_name[512]	= { 0 };
		FILE*	out_fd		= NULL;

		snprintf(out_name, 512, "%s-%u.qrmatrix", qrsizedist_name_prefix, (unsigned int) next_write);

		out_fd = fopen(out_name, "w");

		if (out_fd != NULL)
		{
			if (fwrite(qrdist_matrix, 1, max_qsize * max_rsize * sizeof(int), out_fd) != (max_qsize * max_rsize * sizeof(int)))
			{
				WARNING_MSG("Failed to write %d bytes to %s", max_qsize * max_rsize * sizeof(int), out_name);
			}
			else
			{
				INFO_MSG("Wrote %d bytes to %s", max_qsize * max_rsize * sizeof(int), out_name);
			}

			fclose(out_fd);
		}
		else
		{
			ERROR_MSG("Failed to open %s for writing, data lost!");
		}

		/* Clear state */
		memset(qrdist_matrix, 0, max_qsize * max_rsize * sizeof(int));

		INFO_MSG("%d duplicate queries encountered in this interval", dup_ht_keys);
		INFO_MSG("%d missing queries encountered in this interval", missing_queries);
		INFO_MSG("%d oversize queries encountered in this interval", oversize_queries);
		INFO_MSG("%d oversize responses encountered in this interval", oversize_responses);
		INFO_MSG("%d queries/responses matched and processed", processed);

		processed = dup_ht_keys = missing_queries = oversize_queries = oversize_responses = 0;

		/* Prune the state table */
		eemo_qrsizedist_int_prune_qht();

		next_write += write_interval;
	}
}

/* DNS handler */
eemo_rv eemo_qrsizedist_dns_handler(eemo_ip_packet_info ip_info, int is_tcp, const eemo_dns_packet* pkt)
{
	/* Skip TCP traffic */
	if (is_tcp) return ERV_SKIPPED;

	if (pkt->qr_flag == 0)
	{
		int	dstmatch	= 0;

		/* Check if the query was sent to the resolver we are monitoring */
		if ((ip_info.ip_type == IP_TYPE_V4) && v4_mon_set)
		{
			if (memcmp(&ip_info.dst_addr.v4, &v4_mon, sizeof(struct in_addr)) == 0)
			{
				dstmatch = 1;
			}
		}
		else if ((ip_info.ip_type == IP_TYPE_V6) && v6_mon_set)
		{
			if (memcmp(&ip_info.dst_addr.v6, &v6_mon, sizeof(struct in6_addr)) == 0)
			{
				dstmatch = 1;
			}
		}

		if (!dstmatch) return ERV_SKIPPED;

		/* This is a query */
		if (pkt->questions != NULL)
		{
			/* Add the query to the state table */
			eemo_qrsizedist_int_add_query(ip_info.ip_src, pkt->questions->qname, pkt->questions->qclass, pkt->questions->qtype, pkt->srcport, pkt->query_id, pkt->udp_len, &ip_info.ts);
		}
	}
	else
	{
		int	srcmatch	= 0;

		/* Check if the query was sent to the resolver we are monitoring */
		if ((ip_info.ip_type == IP_TYPE_V4) && v4_mon_set)
		{
			if (memcmp(&ip_info.src_addr.v4, &v4_mon, sizeof(struct in_addr)) == 0)
			{
				srcmatch = 1;
			}
		}
		else if ((ip_info.ip_type == IP_TYPE_V6) && v6_mon_set)
		{
			if (memcmp(&ip_info.src_addr.v6, &v6_mon, sizeof(struct in6_addr)) == 0)
			{
				srcmatch = 1;
			}
		}

		if (!srcmatch) return ERV_SKIPPED;

		/* This is a response */
		if (pkt->questions != NULL)
		{
			/* Find the query size */
			int qsize = eemo_qrsizedist_int_find_qsize(ip_info.ip_dst, pkt->questions->qname, pkt->questions->qclass, pkt->questions->qtype, pkt->dstport, pkt->query_id);

			if (qsize != -1)
			{
				/* Update the matrix */
				int rsize = pkt->udp_len;

				if (rsize > max_rsize)
				{
					oversize_responses++;
				}

				if (qsize > max_qsize)
				{
					oversize_queries++;
				}

				if ((rsize > max_rsize) || (qsize > max_qsize))
				{
					return ERV_SKIPPED;
				}

				rsize -= 1;
				qsize -= 1;

				qrdist_matrix[(rsize * max_qsize) + qsize]++;
				processed++;
			}
		}
	}

	eemo_qrsizedist_int_write(&ip_info.ts, 0);

	return ERV_HANDLED;
}

/* Plugin initialisation */
eemo_rv eemo_qrsizedist_init(eemo_export_fn_table_ptr eemo_fn, const char* conf_base_path)
{
	time_t	now		= 0;
	char*	v4_mon_str	= NULL;
	char*	v6_mon_str	= NULL;

	/* Initialise logging for the plugin */
	eemo_init_plugin_log(eemo_fn->log);

	INFO_MSG("Initialising query/response size distribution plugin");

	if (((eemo_fn->conf_get_string)(conf_base_path, "out_file", &qrsizedist_name_prefix, NULL) != ERV_OK) || (qrsizedist_name_prefix == NULL))
	{
		ERROR_MSG("Could not get output file name prefix from the configuration");

		return ERV_CONFIG_ERROR;
	}

	INFO_MSG("Prefixing output files with '%s'", qrsizedist_name_prefix);

	if ((eemo_fn->conf_get_int)(conf_base_path, "max_qsize", &max_qsize, max_qsize) != ERV_OK)
	{
		ERROR_MSG("Failed to get maximum query size from the configuration");

		return ERV_CONFIG_ERROR;
	}

	INFO_MSG("Maximum query size %d bytes", max_qsize);

	if ((eemo_fn->conf_get_int)(conf_base_path, "max_rsize", &max_rsize, max_rsize) != ERV_OK)
	{
		ERROR_MSG("Failed to get maximum response size from the configuration");

		return ERV_CONFIG_ERROR;
	}

	INFO_MSG("Maximum response size %d bytes", max_rsize);

	if ((eemo_fn->conf_get_int)(conf_base_path, "write_interval", &write_interval, write_interval) != ERV_OK)
	{
		ERROR_MSG("Failed to get the write interval from the configuration");

		return ERV_CONFIG_ERROR;
	}

	INFO_MSG("Write interval %ds", write_interval);

	if ((eemo_fn->conf_get_string)(conf_base_path, "v4_resolver", &v4_mon_str, NULL) != ERV_OK)
	{
		ERROR_MSG("Failed to retrieve the IPv4 address of the resolver to monitor from the configuration");

		return ERV_CONFIG_ERROR;
	}

	if (v4_mon_str != NULL)
	{
		if (inet_pton(AF_INET, v4_mon_str, &v4_mon) != 1)
		{
			ERROR_MSG("Failed to parse '%s' as an IPv4 address", v4_mon_str);

			return ERV_CONFIG_ERROR;
		}

		INFO_MSG("Monitoring resolver IPv4 address %s", v4_mon_str);

		free(v4_mon_str);

		v4_mon_set = 1;
	}

	if ((eemo_fn->conf_get_string)(conf_base_path, "v6_resolver", &v6_mon_str, NULL) != ERV_OK)
	{
		ERROR_MSG("Failed to retrieve the IPv6 address of the resolver to monitor from the configuration");

		return ERV_CONFIG_ERROR;
	}

	if (v6_mon_str != NULL)
	{
		if (inet_pton(AF_INET6, v6_mon_str, &v6_mon) != 1)
		{
			ERROR_MSG("Failed to parse '%s' as an IPv6 address", v6_mon_str);

			return ERV_CONFIG_ERROR;
		}

		INFO_MSG("Monitoring resolver IPv6 address %s", v6_mon_str);

		free(v6_mon_str);

		v6_mon_set = 1;
	}

	if (!v4_mon_set && !v6_mon_set)
	{
		ERROR_MSG("No resolver to monitor configured via IPv4 nor IPv6");

		return ERV_CONFIG_ERROR;
	}

	/* Allocate memory */
	qrdist_matrix = (int*) malloc(max_qsize * max_rsize * sizeof(int));

	INFO_MSG("Allocated %dx%d matrix of %d bytes", max_qsize, max_rsize, max_qsize * max_rsize * sizeof(int));

	/* Register DNS handler */
	if ((eemo_fn->reg_dns_handler)(&eemo_qrsizedist_dns_handler, PARSE_QUERY|PARSE_RESPONSE|PARSE_CANONICALIZE_NAME, &dns_handler_handle) != ERV_OK)
	{
		ERROR_MSG("Failed to register qrsizedist DNS handler");

		(eemo_fn->unreg_dns_handler)(dns_handler_handle);

		return ERV_GENERAL_ERROR;
	}

	/* Determine the next write time */
	now = time(NULL);
	next_write = ((now / write_interval) * write_interval) + write_interval;

	INFO_MSG("Next state dump will be at %u, it is now %u", (unsigned int) next_write, (unsigned int) now);

	INFO_MSG("Query/response size distribution plugin initialisation complete");

	return ERV_OK;
}

/* Plugin uninitialisation */
eemo_rv eemo_qrsizedist_uninit(eemo_export_fn_table_ptr eemo_fn)
{
	q_ht_ent*	ht_it	= NULL;
	q_ht_ent*	ht_tmp	= NULL;

	INFO_MSG("Uninitialising qrsizedist plugin");

	/* Unregister DNS handler */
	if ((eemo_fn->unreg_dns_handler)(dns_handler_handle) != ERV_OK)
	{
		ERROR_MSG("Failed to unregister qrsizedist DNS handler");
	}

	/* Dump the last table */
	eemo_qrsizedist_int_write(NULL, 1);

	free(qrsizedist_name_prefix);
	free(qrdist_matrix);

	qrdist_matrix = NULL;
	qrsizedist_name_prefix = NULL;

	/* Clean up */
	HASH_ITER(hh, q_ht, ht_it, ht_tmp)
	{
		HASH_DEL(q_ht, ht_it);
		free(ht_it);
	}

	q_ht = NULL;

	INFO_MSG("Finished uninitialising qrsizedist plugin");

	return ERV_OK;
}

/* Retrieve plugin description */
const char* eemo_qrsizedist_getdescription(void)
{
	return plugin_description;
}

/* Retrieve plugin status */
eemo_rv eemo_qrsizedist_status(void)
{
	return ERV_OK;
}

/* Plugin function table */
static eemo_plugin_fn_table qrsizedist_fn_table =
{
	EEMO_PLUGIN_FN_VERSION,
	&eemo_qrsizedist_init,
	&eemo_qrsizedist_uninit,
	&eemo_qrsizedist_getdescription,
	&eemo_qrsizedist_status
};

/* Entry point for retrieving plugin function table */
eemo_rv eemo_plugin_get_fn_table(eemo_plugin_fn_table_ptrptr fn_table)
{
	if (fn_table == NULL)
	{
		return ERV_PARAM_INVALID;
	}

	*fn_table = &qrsizedist_fn_table;

	return ERV_OK;
}

