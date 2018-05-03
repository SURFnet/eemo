/*
 * Copyright (c) 2010-2018 SURFnet bv
 * Copyright (c) 2018 Gijs Rijnders
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
 * DNS query name population size measurements and grouping
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
#include "hyperloglogpp.h"

const static char* plugin_description = "EEMO query name population size measurement and grouping plugin " PACKAGE_VERSION;

/* Handles */
static unsigned long		dns_handler_handle	= 0;
static eemo_export_fn_table_ptr	eemo_fn_exp		= NULL;

/* Configuration */
// Currently we support 8 destinations for matching.
static struct in_addr		v4_dst[8];				/* IPv4 query destination */
static int			v4_dst_count		= 0;
static int			v4_dst_set		= 0;
static struct in6_addr		v6_dst[8];				/* IPv6 query destination */
static int			v6_dst_count		= 0;
static int			v6_dst_set		= 0;

static char*			statistics_dir		= NULL;

#define STATISTICS_INTERVAL_HOUR	3600
#define STATISTICS_INTERVAL_DAY		86400

/* Overall counters */
static hll_stor			global_prob_count_hour;
static hll_stor			global_prob_count_day;

/* Hash table types */
typedef struct v4_ht_ent
{
	struct in_addr		addr;
	hll_stor		prob_count;
	unsigned short		prefix_len;
	UT_hash_handle		hh;
}
v4_ht_ent;

typedef struct v6_ht_ent
{
	struct in6_addr		addr;
	hll_stor		prob_count;
	unsigned short		prefix_len;
	UT_hash_handle		hh;
}
v6_ht_ent;

/* State */
static v4_ht_ent*		v4_ht_hour	= NULL;
static v6_ht_ent*		v6_ht_hour	= NULL;
static v4_ht_ent*		v4_ht_day	= NULL;
static v6_ht_ent*		v6_ht_day	= NULL;

/* Update address-based hash tables */
static void update_v4_addr_ht(v4_ht_ent** ht, struct in_addr* addr, const char* const name, const unsigned short prefixlen)
{
	/* Try to find the entry */
	v4_ht_ent*	entry	= NULL;

	HASH_FIND(hh, *ht, addr, sizeof(struct in_addr), entry);

	if (entry == NULL)
	{
		/* This is a new entry */
		entry = (v4_ht_ent*) malloc(sizeof(v4_ht_ent));

		assert(entry != NULL);

		memset(entry, 0, sizeof(v4_ht_ent));

		memcpy(&entry->addr, addr, sizeof(struct in_addr));

		HASH_ADD(hh, (*ht), addr, sizeof(struct in_addr), entry);

		eemo_fn_exp->hll_init(entry->prob_count);
	}

	// Update the HyperLogLog counter with the specified domain name.
	eemo_fn_exp->hll_add(entry->prob_count, name, strlen(name));

	// Update the prefix length of this entry.
	entry->prefix_len = prefixlen;
}

static void update_v6_addr_ht(v6_ht_ent** ht, struct in6_addr* addr, const char* const name, const unsigned short prefixlen)
{
	/* Try to find the entry */
	v6_ht_ent*	entry	= NULL;

	HASH_FIND(hh, *ht, addr, sizeof(struct in6_addr), entry);

	if (entry == NULL)
	{
		/* This is a new entry */
		entry = (v6_ht_ent*) malloc(sizeof(v6_ht_ent));

		assert(entry != NULL);

		memset(entry, 0, sizeof(v6_ht_ent));

		memcpy(&entry->addr, addr, sizeof(struct in6_addr));

		HASH_ADD(hh, (*ht), addr, sizeof(struct in6_addr), entry);

		eemo_fn_exp->hll_init(entry->prob_count);
	}

	// Update the HyperLogLog counter with the specified domain name.
	eemo_fn_exp->hll_add(entry->prob_count, name, strlen(name));

	// Update the prefix length of this entry.
	entry->prefix_len = prefixlen;
}

// File type definitions.
typedef int filetype_t;

#define FILETYPE_IPV4	0x4
#define FILETYPE_IPV6	0x6

// Dump type definitions (hourly, daily).
typedef int dumptype_t;

#define DUMPTYPE_HOURLY 1
#define DUMPTYPE_DAILY	2

// Provides a filename that is specialized for the time interval.
void timeframe_filename(char* const outFileName, const time_t timestamp, const filetype_t filetype, const dumptype_t dumptype)
{
	// Can we write the filename to the output buffer?
	if (outFileName)
	{
		// Round the timestamp down to the hour.
		const int dumpstats_interval = dumptype == DUMPTYPE_HOURLY ? STATISTICS_INTERVAL_HOUR : STATISTICS_INTERVAL_DAY;
		const time_t rounded = timestamp - (timestamp % dumpstats_interval);

		// Prepare a filename suffix.
		const char* const suffix = dumptype == DUMPTYPE_HOURLY ? "hour" : "day";

		// Different behavior for different filetypes.
		switch (filetype)
		{
			case FILETYPE_IPV4:
				sprintf(outFileName, "%s/ipv4prefixes.%s.%li", statistics_dir, suffix, rounded);
				break;
			case FILETYPE_IPV6:
				sprintf(outFileName, "%s/ipv6prefixes.%s.%li", statistics_dir, suffix, rounded);
				break;
			default:
				ERROR_MSG("Invalid filetype specified!");
				break;
		}
	}
}

// Writes the contents of the IPv4 hash table to a CSV file.
void write_csv_ht_v4(const char* const filename, v4_ht_ent* p_hashtable, const unsigned long long globcount)
{
	FILE* out = NULL;
	v4_ht_ent* v4_it = NULL;
	v4_ht_ent* v4_tmp = NULL;

	// Is the filename valid?
	if (filename && p_hashtable)
	{
		// Try to open the output file.
		out = fopen(filename, "w");
		if (out)
		{
			// Write global unique domain count first (some summary).
			fprintf(out, "Global count: %llu\n\n", globcount);

			// Write CSV header to file.
			fprintf(out, "prefix,uniqcount\n");

			// Iterate through the IPv4 prefixes.
			HASH_ITER(hh, p_hashtable, v4_it, v4_tmp)
			{
				// Convert the IPv4 address to a its string representation.
				char ip_str[INET_ADDRSTRLEN]	= { 0 };
				if (inet_ntop(AF_INET, &v4_it->addr, ip_str, INET_ADDRSTRLEN) != NULL)
				{
					fprintf(out, "%s/%i,%llu\n", ip_str, v4_it->prefix_len, (unsigned long long) eemo_fn_exp->hll_count(v4_it->prob_count));
				}

				HASH_DEL(p_hashtable, v4_it);
				free(v4_it);
			}

			// Close the output file.
			fclose(out);
		}
		else
		{
			ERROR_MSG("Invalid parameters %p and %p!", filename, p_hashtable);
		}
	}
}

// Writes the contents of the IPv6 hash table to a CSV file.
void write_csv_ht_v6(const char* const filename, v6_ht_ent* p_hashtable, const unsigned long long globcount)
{
	FILE* out = NULL;
	v6_ht_ent* v6_it = NULL;
	v6_ht_ent* v6_tmp = NULL;

	// Are the input parameters valid?
	if (filename && p_hashtable)
	{
		// Try to open the output file.
		out = fopen(filename, "w");
		if (out)
		{
			// Write global unique domain count first (some summary).
			fprintf(out, "Global count: %llu\n\n", globcount);

			// Write CSV header to file.
			fprintf(out, "prefix,uniqcount\n");

			// Iterate through the IPv4 prefixes.
			HASH_ITER(hh, p_hashtable, v6_it, v6_tmp)
			{
				// Convert the IPv4 address to a its string representation.
				char ip_str[INET6_ADDRSTRLEN]	= { 0 };
				if (inet_ntop(AF_INET6, &v6_it->addr, ip_str, INET6_ADDRSTRLEN) != NULL)
				{
					fprintf(out, "%s/%i,%llu\n", ip_str, v6_it->prefix_len, (unsigned long long) eemo_fn_exp->hll_count(v6_it->prob_count));
				}

				HASH_DEL(p_hashtable, v6_it);
				free(v6_it);
			}

			// Close the output file.
			fclose(out);
		}
		else
		{
			ERROR_MSG("Invalid parameters %p and %p!", filename, p_hashtable);
		}
	}
}

typedef struct dump_thread_params
{
	// The unique domain name hash table grouped per IPv4 prefix.
	v4_ht_ent*		dump_v4_ht;

	// The unique domain name hash table grouped per IPv6 prefix.
	v6_ht_ent*		dump_v6_ht;

	// The unique domain name count over all IPv4 and IPv6 prefixes.
	unsigned long long 	globcount;

	// The timestamp for the current timeframe.
	time_t			timestamp;

	// Is this a dump for hourly or daily statistics?
	dumptype_t		dumptype;
}
dump_thread_params;

// Dumps the statistics to their designated files. The statistics will be dumped each hour and each day.
static void* eemo_dnsuniq_int_dumpstats_thread(void* params)
{
	dump_thread_params* cu_params = (dump_thread_params*) params;

	// Check whether the statistics directory exists.
	if (statistics_dir)
	{
		char fn[512];

		// Open the correct output file, we do not want to overwrite anything by accident.
		// Try to open IPv4 output file for this timeframe, and write the data to it.
		timeframe_filename(fn, cu_params->timestamp, FILETYPE_IPV4, cu_params->dumptype);
		write_csv_ht_v4(fn, cu_params->dump_v4_ht, cu_params->globcount);

		// Try to open IPv6 output file for this timeframe, and write the data to it.
		timeframe_filename(fn, cu_params->timestamp, FILETYPE_IPV6, cu_params->dumptype);
		write_csv_ht_v6(fn, cu_params->dump_v6_ht, cu_params->globcount);
	}
	else
	{
		ERROR_MSG("Could not open statistics files because the output directory is invalid!");
	}

	// Reset global HyperLogLog counter.
	if (cu_params->dumptype == DUMPTYPE_HOURLY)
	{
		eemo_fn_exp->hll_init(global_prob_count_hour);
	}
	else
	{
		eemo_fn_exp->hll_init(global_prob_count_day);
	}

	// Free the thread parameters and return.
	free(cu_params);
	INFO_MSG("Statistics round for timestamp %i complete!", cu_params->timestamp);

	return NULL;
}

static void eemo_dnsuniq_int_dumpstats_hour(const int is_exiting)
{
	static time_t		mark_hour	= 0;
	dump_thread_params*	cu_hour		= NULL;
	pthread_t		cu_thr_hour;

	// Has the time interval passed?
	if (!is_exiting)
	{
		if (mark_hour == 0)
		{
			mark_hour = time(NULL);
			return;
		}

		if (time(NULL) - mark_hour < STATISTICS_INTERVAL_HOUR)
		{
			return;
		}

		mark_hour = time(NULL);
	}

	/* Dump statistics */
	cu_hour = (dump_thread_params*) malloc(sizeof(dump_thread_params));

	assert(cu_hour != NULL);

	cu_hour->dump_v4_ht	= v4_ht_hour;
	v4_ht_hour		= NULL;
	cu_hour->dump_v6_ht	= v6_ht_hour;
	v6_ht_hour		= NULL;
	cu_hour->timestamp	= mark_hour;
	cu_hour->globcount	= (unsigned long long) eemo_fn_exp->hll_count(global_prob_count_hour);
	cu_hour->dumptype	= DUMPTYPE_HOURLY;

	// Create a separate threat that dumps the statistics to a file.
	if (pthread_create(&cu_thr_hour, NULL, eemo_dnsuniq_int_dumpstats_thread, cu_hour) != 0)
	{
		ERROR_MSG("Failed to spawn hourly statistics writing thread!");
	}
	else
	{
		if (is_exiting)
		{
			pthread_join(cu_thr_hour, NULL);
		}
		else
		{
			pthread_detach(cu_thr_hour);
		}
	}
}

static void eemo_dnsuniq_int_dumpstats_day(const int is_exiting)
{
	static time_t		mark_day	= 0;
	dump_thread_params*	cu_day		= NULL;
	pthread_t		cu_thr_day;

	// Now look if the same information should also be dumped per day!
	if (!is_exiting)
	{
		if (mark_day == 0)
		{
			mark_day = time(NULL);
			return;
		}

		if (time(NULL) - mark_day < STATISTICS_INTERVAL_DAY)
		{
			return;
		}
	}

	/* Dump statistics */
	cu_day = (dump_thread_params*) malloc(sizeof(dump_thread_params));

	assert(cu_day != NULL);

	cu_day->dump_v4_ht	= v4_ht_day;
	v4_ht_day		= NULL;
	cu_day->dump_v6_ht	= v6_ht_day;
	v6_ht_day		= NULL;
	cu_day->timestamp	= mark_day;
	cu_day->globcount	= (unsigned long long) eemo_fn_exp->hll_count(global_prob_count_day);
	cu_day->dumptype	= DUMPTYPE_DAILY;

	// Create a separate threat that dumps the statistics to a file.
	if (pthread_create(&cu_thr_day, NULL, eemo_dnsuniq_int_dumpstats_thread, cu_day) != 0)
	{
		ERROR_MSG("Failed to spawn daily statistics writing thread!");
	}
	else
	{
		if (is_exiting)
		{
			pthread_join(cu_thr_day, NULL);
		}
		else
		{
			pthread_detach(cu_thr_day);
		}
	}
}

// Prefix length constant definitions.
#define PREFIX_SLASH24 24
#define PREFIX_SLASH20 20
#define PREFIX_SLASH16 16
#define PREFIX_SLASH64 64

/* Query handler */
eemo_rv eemo_dnsuniq_dns_handler(eemo_ip_packet_info ip_info, int is_tcp, const eemo_dns_packet* pkt)
{
	eemo_rv rv = ERV_SKIPPED;

	/* Only look at valid queries */
	if (!pkt->qr_flag && !pkt->is_partial && (pkt->questions != NULL) && (pkt->questions->qname != NULL))
	{
		int	dst_match	= 0;

		/* Check if the query is directed toward the resolver we're monitoring */
		if ((ip_info.ip_type == IP_TYPE_V4) && v4_dst_set)
		{
			// Check if any configured IPv4 address matches.
			for (int i = 0; i < v4_dst_count; ++i)
			{
				if (memcmp(&ip_info.dst_addr.v4, &v4_dst[i], sizeof(struct in_addr)) == 0)
				{
					dst_match = 1;
					break;
				}
			}
		}
		else if ((ip_info.ip_type == IP_TYPE_V6) && v6_dst_set)
		{
			// Check if any configured IPv4 address matches.
			for (int i = 0; i < v6_dst_count; ++i)
			{
				if (memcmp(&ip_info.dst_addr.v6, &v6_dst[i], sizeof(struct in6_addr)) == 0)
				{
					dst_match = 1;
					break;
				}
			}
		}

		if (dst_match)
		{
			// Take the domain name out of DNS packet, and put it in the hash tables.
			if (ip_info.ip_type == IP_TYPE_V4)
			{
				uint32_t	ip4_prefix	= 0;
				memcpy(&ip4_prefix, &ip_info.src_addr.v4, sizeof(uint32_t));

				// Save the /24 prefix of the IPv4 address.
				ip4_prefix = htonl(ntohl(ip4_prefix) & 0xffffff00);
				update_v4_addr_ht(&v4_ht_hour, (struct in_addr*) &ip4_prefix, pkt->questions->qname, PREFIX_SLASH24);
				update_v4_addr_ht(&v4_ht_day, (struct in_addr*) &ip4_prefix, pkt->questions->qname, PREFIX_SLASH24);

				// Save the /20 prefix of the IPv4 address.
				ip4_prefix = htonl(ntohl(ip4_prefix) & 0xfffff000);
				update_v4_addr_ht(&v4_ht_hour, (struct in_addr*) &ip4_prefix, pkt->questions->qname, PREFIX_SLASH20);
				update_v4_addr_ht(&v4_ht_day, (struct in_addr*) &ip4_prefix, pkt->questions->qname, PREFIX_SLASH20);

				// Save the /16 prefix of the IPv4 address.
				ip4_prefix = htonl(ntohl(ip4_prefix) & 0xffff0000);
				update_v4_addr_ht(&v4_ht_hour, (struct in_addr*) &ip4_prefix, pkt->questions->qname, PREFIX_SLASH16);
				update_v4_addr_ht(&v4_ht_day, (struct in_addr*) &ip4_prefix, pkt->questions->qname, PREFIX_SLASH16);
			}
			else if (ip_info.ip_type == IP_TYPE_V6)
			{
				uint16_t	ip6_prefix_creat[8]	= { 0 };
				struct in6_addr	ip6_prefix;

				memcpy(ip6_prefix_creat, &ip_info.src_addr.v6, sizeof(struct in6_addr));
				memset(&ip6_prefix_creat[4], 0, 4 * sizeof(uint16_t));
				memcpy(&ip6_prefix, ip6_prefix_creat, 8 * sizeof(uint16_t));
				update_v6_addr_ht(&v6_ht_hour, (struct in6_addr*) &ip6_prefix, pkt->questions->qname, PREFIX_SLASH64);
				update_v6_addr_ht(&v6_ht_day, (struct in6_addr*) &ip6_prefix, pkt->questions->qname, PREFIX_SLASH64);
			}

			// Add the domain name to the global HyperLogLog counter.
			eemo_fn_exp->hll_add(global_prob_count_hour, pkt->questions->qname, strlen(pkt->questions->qname));
			eemo_fn_exp->hll_add(global_prob_count_day, pkt->questions->qname, strlen(pkt->questions->qname));

			rv = ERV_HANDLED;
		}

		// Dump the statistics to a file if the time interval has passed.
		eemo_dnsuniq_int_dumpstats_hour(0);
		eemo_dnsuniq_int_dumpstats_day(0);
	}

	return rv;
}

/* Plugin initialisation */
eemo_rv eemo_dnsuniq_init(eemo_export_fn_table_ptr eemo_fn, const char* conf_base_path)
{
	char**	v4_dst_str	= NULL;
	char**	v6_dst_str	= NULL;

	eemo_fn_exp = eemo_fn;

	/* Initialise logging for the plugin */
	eemo_init_plugin_log(eemo_fn->log);

	INFO_MSG("Initialising dnsuniq plugin");

	/* Retrieve configuration */
	if ((eemo_fn->conf_get_string_array)(conf_base_path, "v4_dst", &v4_dst_str, &v4_dst_count) != ERV_OK)
	{
		ERROR_MSG("Failed to retrieve IPv4 resolver destination addresses from the configuration");

		return ERV_CONFIG_ERROR;
	}

	if (v4_dst_str != NULL)
	{
		// Convert all IPv4 strings to addresses.
		for (int i = 0; i < v4_dst_count; ++i)
		{
			if (inet_pton(AF_INET, v4_dst_str[i], &v4_dst[i]) != 1)
			{
				ERROR_MSG("Configured value %s is not a valid IPv4 address", v4_dst_str[i]);

				return ERV_CONFIG_ERROR;
			}

			v4_dst_set = 1;
		}
	}
	else
	{
		WARNING_MSG("No IPv4 resolver destination address specified, will not tally queries over IPv4!");
	}

	// Free the IPv4 destination string array.
	eemo_fn->conf_free_string_array(v4_dst_str, v4_dst_count);

	if ((eemo_fn->conf_get_string_array)(conf_base_path, "v6_dst", &v6_dst_str, &v6_dst_count) != ERV_OK)
	{
		ERROR_MSG("Failed to retrieve IPv6 resolver destination addresses from the configuration");

		return ERV_CONFIG_ERROR;
	}

	if (v6_dst_str != NULL)
	{
		// Convert all IPv4 strings to addresses.
		for (int i = 0; i < v6_dst_count; ++i)
		{
			if (inet_pton(AF_INET6, v6_dst_str[i], &v6_dst[i]) != 1)
			{
				ERROR_MSG("Configured value %s is not a valid IPv6 address", v6_dst_str[i]);

				return ERV_CONFIG_ERROR;
			}

			v6_dst_set = 1;
		}
	}
	else
	{
		WARNING_MSG("No IPv6 resolver destination address specified, will not tally queries over IPv6!");
	}

	// Free the IPv6 destination string array.
	eemo_fn->conf_free_string_array(v6_dst_str, v6_dst_count);

	if ((eemo_fn->conf_get_string)(conf_base_path, "statistics_dir", &statistics_dir, NULL) != ERV_OK)
	{
		ERROR_MSG("Failed to retrieve directory name to store statistic files in!");

		return ERV_CONFIG_ERROR;
	}

	if (statistics_dir == NULL)
	{
		WARNING_MSG("No directory specified to store count statistics in");
	}

	/* Register DNS handler */
	if ((eemo_fn->reg_dns_handler)(&eemo_dnsuniq_dns_handler, PARSE_QUERY | PARSE_CANONICALIZE_NAME, &dns_handler_handle) != ERV_OK)
	{
		ERROR_MSG("Failed to register dnsuniq DNS handler");

		(eemo_fn->unreg_dns_handler)(dns_handler_handle);

		return ERV_GENERAL_ERROR;
	}

	// Initialize HyperLogLog for global count.
	eemo_fn_exp->hll_init(global_prob_count_hour);
	eemo_fn_exp->hll_init(global_prob_count_day);

	INFO_MSG("dnsuniq plugin initialisation complete");

	return ERV_OK;
}

/* Plugin uninitialisation */
eemo_rv eemo_dnsuniq_uninit(eemo_export_fn_table_ptr eemo_fn)
{
	// Dump the current statistics before quitting.
	eemo_dnsuniq_int_dumpstats_hour(1);
	eemo_dnsuniq_int_dumpstats_day(1);

	INFO_MSG("Uninitialising dnsuniq plugin");

	/* Unregister DNS handler */
	if ((eemo_fn->unreg_dns_handler)(dns_handler_handle) != ERV_OK)
	{
		ERROR_MSG("Failed to unregister dnsuniq DNS handler");
	}

	/* Clean up */
	free(statistics_dir);

	INFO_MSG("Finished uninitialising dnsuniq plugin");

	return ERV_OK;
}

/* Retrieve plugin description */
const char* eemo_dnsuniq_getdescription(void)
{
	return plugin_description;
}

/* Retrieve plugin status */
eemo_rv eemo_dnsuniq_status(void)
{
	return ERV_OK;
}

/* Plugin function table */
static eemo_plugin_fn_table dnsuniq_fn_table =
{
	EEMO_PLUGIN_FN_VERSION,
	&eemo_dnsuniq_init,
	&eemo_dnsuniq_uninit,
	&eemo_dnsuniq_getdescription,
	&eemo_dnsuniq_status
};

/* Entry point for retrieving plugin function table */
eemo_rv eemo_plugin_get_fn_table(eemo_plugin_fn_table_ptrptr fn_table)
{
	if (fn_table == NULL)
	{
		return ERV_PARAM_INVALID;
	}

	*fn_table = &dnsuniq_fn_table;

	return ERV_OK;
}
