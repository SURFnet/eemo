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
 * DNS query client and name population size measurements
 */

#include "config.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <time.h>
#include <pthread.h>
#include "eemo.h"
#include "eemo_api.h"
#include "eemo_plugin_log.h"
#include "dns_handler.h"
#include "dns_parser.h"
#include "uthash.h"

const static char* plugin_description = "EEMO query population measurement plugin " PACKAGE_VERSION;

/* Handles */
static unsigned long		dns_handler_handle	= 0;

/* Configuration */
static int			top_individual_ip4	= 100;	/* Keep a top <x> of individual IPv4 addresses */
static int			top_individual_ip6	= 100;	/* Keep a top <x> of individual IPv6 addresses */
static int			top_pfx24_ip4		= 25;	/* Keep a top <x> of IPv4 /24 prefixes with clients */
static int			top_pfx64_ip6		= 25;	/* Keep a top <x> of IPv6 /64 prefixes with clients */
static int			top_qnames		= 100;	/* Keep a top <x> of query names */
static int			top_slds		= 25;	/* Keep a top <x> of second-level domains */

static struct in_addr		v4_dst;				/* IPv4 query destination */
static int			v4_dst_set		= 0;
static struct in6_addr		v6_dst;				/* IPv6 query destination */
static int			v6_dst_set		= 0;

static char*			top_v4_file		= NULL;
static char*			top_v4_pfx_file		= NULL;
static char*			top_v6_file		= NULL;
static char*			top_v6_pfx_file		= NULL;
static char*			top_qname_file		= NULL;
static char*			top_sld_file		= NULL;

static int			dumpstats_interval	= 60;	/* Dump and reset statistics every <x> seconds */

/* Overall counters */
static unsigned long long	v4_q_ctr		= 0;
static unsigned long long	v6_q_ctr		= 0;

/* Hash table types */
typedef struct v4_ht_ent
{
	struct in_addr		addr;
	unsigned long long	count;
	UT_hash_handle		hh;
}
v4_ht_ent;

typedef struct v6_ht_ent
{
	struct in6_addr		addr;
	unsigned long long	count;
	UT_hash_handle		hh;
}
v6_ht_ent;

typedef struct qname_ht_ent
{
	char			name[512];
	unsigned long long	count;
	UT_hash_handle		hh;
}
qname_ht_ent;

/* State */
static v4_ht_ent*		v4_ht		= NULL;
static v4_ht_ent*		v4_pfx_ht	= NULL;
static v6_ht_ent*		v6_ht		= NULL;
static v6_ht_ent*		v6_pfx_ht	= NULL;
static qname_ht_ent*		qname_ht	= NULL;
static qname_ht_ent*		sld_ht		= NULL;

/* Update address-based hash tables */
static void update_v4_addr_ht(v4_ht_ent** ht, struct in_addr* addr)
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
	} 
	
	entry->count++;
}

static void update_v6_addr_ht(v6_ht_ent** ht, struct in6_addr* addr)
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
	} 
	
	entry->count++;
}

/* Macro to update name-based hash tables */
static void update_qname_ht(qname_ht_ent** ht, const char* name)
{
	/* Try to find the entry */ 
	qname_ht_ent*	entry	= NULL; 
	
	HASH_FIND_STR(*ht, name, entry); 
	
	if (entry == NULL) 
	{ 
		/* This is a new entry */ \
		entry = (qname_ht_ent*) malloc(sizeof(qname_ht_ent));
		
		assert(entry != NULL); 
		
		memset(entry, 0, sizeof(qname_ht_ent));
		
		assert(strlen(name) < 512);
		
		strcpy(entry->name, name);
		
		HASH_ADD_STR((*ht), name, entry);
	}
	
	entry->count++;
}

/* Extract the TLD and SLD from a domain name string */
static int eemo_querypop_int_extract_tld_sld(const char* string, const char** tld, const char** sld)
{
	assert(string != NULL);
	assert(tld != NULL);
	assert(sld != NULL);

	const char*	dotloc	= strrchr(string, '.');

	if (strlen(string) < 1)
	{
		return -1;
	}

	dotloc--;

	while (dotloc >= string)
	{
		if (*dotloc == '.') break;
		dotloc--;
	}

	if (dotloc < string)
	{
		return -1;
	}

	*tld = (dotloc + 1);

	dotloc--;

	while (dotloc >= string)
	{
		if (*dotloc == '.') break;
		dotloc--;
	}

	*sld = (dotloc + 1);

	if ((*tld == NULL) || (*sld == NULL))
	{
		return -1;
	}

	return 0;
}

static int sort_count_v4(v4_ht_ent* a, v4_ht_ent* b)
{
	return (b->count - a->count);
}

static int sort_count_v6(v6_ht_ent* a, v6_ht_ent* b)
{
	return (b->count - a->count);
}

static int sort_count_qname(qname_ht_ent* a, qname_ht_ent* b)
{
	return (b->count - a->count);
}

typedef struct dump_thread_params
{
	v4_ht_ent*		dump_v4_ht;
	v4_ht_ent*		dump_v4_pfx_ht;
	v6_ht_ent*		dump_v6_ht;
	v6_ht_ent*		dump_v6_pfx_ht;
	qname_ht_ent*		dump_qname_ht;
	qname_ht_ent*		dump_sld_ht;
	unsigned long long	v4_q;
	unsigned long long	v6_q;
}
dump_thread_params;

static void* eemo_querypop_int_dumpstats_thread(void* params)
{
	dump_thread_params*	cu_params	= (dump_thread_params*) params;
	v4_ht_ent*		v4_it		= NULL;
	v4_ht_ent*		v4_tmp		= NULL;
	v6_ht_ent*		v6_it		= NULL;
	v6_ht_ent*		v6_tmp		= NULL;
	qname_ht_ent*		q_it		= NULL;
	qname_ht_ent*		q_tmp		= NULL;
	FILE*			out		= NULL;
	int			i		= 0;

	if (top_v4_file != NULL)
	{
		out = fopen(top_v4_file, "w");

		if (out == NULL) ERROR_MSG("Failed to open %s for writing", top_v4_file);
	}
	else
	{
		out = NULL;
	}

	i = 0;

	HASH_SORT(cu_params->dump_v4_ht, sort_count_v4);

	HASH_ITER(hh, cu_params->dump_v4_ht, v4_it, v4_tmp)
	{
		if ((i++ < top_individual_ip4) && (out != NULL))
		{
			char	ip_str[INET_ADDRSTRLEN]	= { 0 };

			if (inet_ntop(AF_INET, &v4_it->addr, ip_str, INET_ADDRSTRLEN) != NULL)
			{
				fprintf(out, "%3d - %15s %llu (%.2f%%)\n", i, ip_str, v4_it->count, (double) (v4_it->count * 100.0f) / (double) cu_params->v4_q);
			}
		}

		HASH_DEL(cu_params->dump_v4_ht, v4_it);
		free(v4_it);
	}

	if (out != NULL) fclose(out);

	if (top_v4_pfx_file != NULL)
	{
		out = fopen(top_v4_pfx_file, "w");

		if (out == NULL) ERROR_MSG("Failed to open %s for writing", top_v4_pfx_file);
	}
	else
	{
		out = NULL;
	}

	i = 0;

	HASH_SORT(cu_params->dump_v4_pfx_ht, sort_count_v4);

	HASH_ITER(hh, cu_params->dump_v4_pfx_ht, v4_it, v4_tmp)
	{
		if ((i++ < top_pfx24_ip4) && (out != NULL))
		{
			char	ip_str[INET_ADDRSTRLEN]	= { 0 };

			if (inet_ntop(AF_INET, &v4_it->addr, ip_str, INET_ADDRSTRLEN) != NULL)
			{
				fprintf(out, "%3d - %13s/24 %llu (%.2f%%)\n", i, ip_str, v4_it->count, (double) (v4_it->count * 100.0f) / (double) cu_params->v4_q);
			}
		}

		HASH_DEL(cu_params->dump_v4_pfx_ht, v4_it);
		free(v4_it);
	}

	if (out != NULL) fclose(out);

	if (top_v6_file != NULL)
	{
		out = fopen(top_v6_file, "w");

		if (out == NULL) ERROR_MSG("Failed to open %s for writing", top_v6_file);
	}
	else
	{
		out = NULL;
	}

	i = 0;

	HASH_SORT(cu_params->dump_v6_ht, sort_count_v6);

	HASH_ITER(hh, cu_params->dump_v6_ht, v6_it, v6_tmp)
	{
		if ((i++ < top_individual_ip4) && (out != NULL))
		{
			char	ip_str[INET6_ADDRSTRLEN]	= { 0 };

			if (inet_ntop(AF_INET6, &v6_it->addr, ip_str, INET6_ADDRSTRLEN) != NULL)
			{
				fprintf(out, "%3d - %39s %llu (%.2f%%)\n", i, ip_str, v6_it->count, (double) (v6_it->count * 100.0f) / (double) cu_params->v6_q);
			}
		}

		HASH_DEL(cu_params->dump_v6_ht, v6_it);
		free(v6_it);
	}

	if (out != NULL) fclose(out);

	if (top_v6_pfx_file != NULL)
	{
		out = fopen(top_v6_pfx_file, "w");

		if (out == NULL) ERROR_MSG("Failed to open %s for writing", top_v6_pfx_file);
	}
	else
	{
		out = NULL;
	}

	i = 0;

	HASH_SORT(cu_params->dump_v6_pfx_ht, sort_count_v6);

	HASH_ITER(hh, cu_params->dump_v6_pfx_ht, v6_it, v6_tmp)
	{
		if ((i++ < top_pfx64_ip6) && (out != NULL))
		{
			char	ip_str[INET6_ADDRSTRLEN]	= { 0 };

			if (inet_ntop(AF_INET6, &v6_it->addr, ip_str, INET6_ADDRSTRLEN) != NULL)
			{
				fprintf(out, "%3d - %21s/64 %llu (%.2f%%)\n", i, ip_str, v6_it->count, (double) (v6_it->count * 100.0f) / (double) cu_params->v6_q);
			}
		}

		HASH_DEL(cu_params->dump_v6_pfx_ht, v6_it);
		free(v6_it);
	}

	if (out != NULL) fclose(out);

	if (top_qname_file != NULL)
	{
		out = fopen(top_qname_file, "w");

		if (out == NULL) ERROR_MSG("Failed to open %s for writing", top_qname_file);
	}
	else
	{
		out = NULL;
	}

	i = 0;

	HASH_SORT(cu_params->dump_qname_ht, sort_count_qname);

	HASH_ITER(hh, cu_params->dump_qname_ht, q_it, q_tmp)
	{
		if ((i++ < top_qnames) && (out != NULL))
		{
			fprintf(out, "%3d - %63s %llu (%.2f%%)\n", i, q_it->name, q_it->count, (double) (q_it->count * 100.0f) / (double) (cu_params->v4_q + cu_params->v6_q));
		}

		HASH_DEL(cu_params->dump_qname_ht, q_it);
		free(q_it);
	}

	if (out != NULL) fclose(out);

	if (top_sld_file != NULL)
	{
		out = fopen(top_sld_file, "w");

		if (out == NULL) ERROR_MSG("Failed to open %s for writing", top_sld_file);
	}
	else
	{
		out = NULL;
	}

	i = 0;

	HASH_SORT(cu_params->dump_sld_ht, sort_count_qname);

	HASH_ITER(hh, cu_params->dump_sld_ht, q_it, q_tmp)
	{
		if ((i++ < top_slds) && (out != NULL))
		{
			fprintf(out, "%3d - %63s %llu (%.2f%%)\n", i, q_it->name, q_it->count, (double) (q_it->count * 100.0f) / (double) (cu_params->v4_q + cu_params->v6_q));
		}

		HASH_DEL(cu_params->dump_sld_ht, q_it);
		free(q_it);
	}

	if (out != NULL) fclose(out);

	free(cu_params);

	INFO_MSG("Statistics cleanup complete");

	return NULL;
}

static void eemo_querypop_int_dumpstats(const int is_exiting)
{
	static time_t		mark	= 0;
	dump_thread_params*	cu	= NULL;
	pthread_t		cu_thr;

	if (!is_exiting)
	{
		if (mark == 0)
		{
			mark = time(NULL);
			return;
		}

		if (time(NULL) - mark < dumpstats_interval)
		{
			return;
		}

		mark = time(NULL);
	}

	/* Dump statistics */
	cu = (dump_thread_params*) malloc(sizeof(dump_thread_params));

	assert(cu != NULL);

	cu->dump_v4_ht		= v4_ht;
	v4_ht			= NULL;
	cu->dump_v4_pfx_ht	= v4_pfx_ht;
	v4_pfx_ht		= NULL;
	cu->dump_v6_ht		= v6_ht;
	v6_ht			= NULL;
	cu->dump_v6_pfx_ht	= v6_pfx_ht;
	v6_pfx_ht		= NULL;
	cu->dump_qname_ht	= qname_ht;
	qname_ht		= NULL;
	cu->dump_sld_ht	= sld_ht;
	sld_ht			= NULL;
	cu->v4_q		= v4_q_ctr;
	cu->v6_q		= v6_q_ctr;
	
	v4_q_ctr = 0;
	v6_q_ctr = 0;
	
	if (pthread_create(&cu_thr, NULL, eemo_querypop_int_dumpstats_thread, cu) != 0)
	{
		ERROR_MSG("Failed to spawn cleanup thread");
	}
	else
	{
		if (is_exiting)
		{
			pthread_join(cu_thr, NULL);
		}
		else
		{
			pthread_detach(cu_thr);
		}
	}
}

/* Query handler */
eemo_rv eemo_querypop_dns_handler(eemo_ip_packet_info ip_info, int is_tcp, const eemo_dns_packet* pkt)
{
	/* Only look at valid queries */
	if (!pkt->qr_flag && (pkt->questions != NULL) && (pkt->questions->qname != NULL))
	{
		int	dst_match	= 0;

		/* Check if the query is directed toward the resolver we're monitoring */
		if ((ip_info.ip_type == IP_TYPE_V4) && v4_dst_set)
		{
			if (memcmp(&ip_info.dst_addr.v4, &v4_dst, sizeof(struct in_addr)) == 0)
			{
				dst_match = 1;
			}
		}
		else if ((ip_info.ip_type == IP_TYPE_V6) && v6_dst_set)
		{
			if (memcmp(&ip_info.dst_addr.v6, &v6_dst, sizeof(struct in6_addr)) == 0)
			{
				dst_match = 1;
			}
		}

		if (dst_match)
		{
			const char*	tld	= NULL;
			const char*	sld	= NULL;

			if (ip_info.ip_type == IP_TYPE_V4)
			{
				uint32_t	ip4_prefix	= 0;

				memcpy(&ip4_prefix, &ip_info.src_addr.v4, sizeof(uint32_t));

				ip4_prefix = htonl(ntohl(ip4_prefix) & 0xffffff00);

				update_v4_addr_ht(&v4_ht, (struct in_addr*) &ip_info.src_addr.v4);
				update_v4_addr_ht(&v4_pfx_ht, (struct in_addr*) &ip4_prefix);

				v4_q_ctr++;
			}
			else if (ip_info.ip_type == IP_TYPE_V6)
			{
				uint16_t	ip6_prefix_creat[8]	= { 0 };
				struct in6_addr	ip6_prefix;
				
				memcpy(ip6_prefix_creat, &ip_info.src_addr.v6, sizeof(struct in6_addr));

				memset(&ip6_prefix_creat[4], 0, 4 * sizeof(uint16_t));
				
				memcpy(&ip6_prefix, ip6_prefix_creat, 8 * sizeof(uint16_t));

				update_v6_addr_ht(&v6_ht, (struct in6_addr*) &ip_info.src_addr.v6);
				update_v6_addr_ht(&v6_pfx_ht, (struct in6_addr*) &ip6_prefix);

				v6_q_ctr++;
			}

			update_qname_ht(&qname_ht, pkt->questions->qname);

			if (eemo_querypop_int_extract_tld_sld(pkt->questions->qname, &tld, &sld) == 0)
			{
				update_qname_ht(&sld_ht, sld);
			}
			else
			{
				update_qname_ht(&sld_ht, pkt->questions->qname);
			}
		}

		eemo_querypop_int_dumpstats(0);
	}

	return ERV_SKIPPED;
}

/* Plugin initialisation */
eemo_rv eemo_querypop_init(eemo_export_fn_table_ptr eemo_fn, const char* conf_base_path)
{
	char*	v4_dst_str	= NULL;
	char*	v6_dst_str	= NULL;

	/* Initialise logging for the plugin */
	eemo_init_plugin_log(eemo_fn->log);

	INFO_MSG("Initialising querypop plugin");

	/* Retrieve configuration */
	if (((eemo_fn->conf_get_int)(conf_base_path, "top_individual_ip4", &top_individual_ip4, top_individual_ip4) != ERV_OK) ||
	    (top_individual_ip4 <= 0))
	{
		ERROR_MSG("Failed to retrieve a valid configuration value for the length of the top <x> IPv4 client address list");

		return ERV_CONFIG_ERROR;
	}

	INFO_MSG("Will maintain a list of the top %d IPv4 client addresses", top_individual_ip4);

	if (((eemo_fn->conf_get_int)(conf_base_path, "top_individual_ip6", &top_individual_ip6, top_individual_ip6) != ERV_OK) ||
	    (top_individual_ip6 <= 0))
	{
		ERROR_MSG("Failed to retrieve a valid configuration value for the length of the top <x> IPv6 client address list");

		return ERV_CONFIG_ERROR;
	}

	INFO_MSG("Will maintain a list of the top %d IPv6 client addresses", top_individual_ip4);

	if (((eemo_fn->conf_get_int)(conf_base_path, "top_pfx24_ip4", &top_pfx24_ip4, top_pfx24_ip4) != ERV_OK) ||
	    (top_pfx24_ip4 <= 0))
	{
		ERROR_MSG("Failed to retrieve a valid configuration value for the length of the top <x> IPv4 client address /24 prefix list");

		return ERV_CONFIG_ERROR;
	}

	INFO_MSG("Will maintain a list of the top %d IPv4 client address /24 prefixes", top_pfx24_ip4);

	if (((eemo_fn->conf_get_int)(conf_base_path, "top_pfx64_ip6", &top_pfx64_ip6, top_pfx64_ip6) != ERV_OK) ||
	    (top_pfx64_ip6 <= 0))
	{
		ERROR_MSG("Failed to retrieve a valid configuration value for the length of the top <x> IPv6 client address /64 prefix list");

		return ERV_CONFIG_ERROR;
	}

	INFO_MSG("Will maintain a list of the top %d IPv6 client address /64 prefixes", top_pfx64_ip6);

	if (((eemo_fn->conf_get_int)(conf_base_path, "top_qnames", &top_qnames, top_qnames) != ERV_OK) ||
	    (top_qnames <= 0))
	{
		ERROR_MSG("Failed to retrieve a valid configuration value for the length of the top <x> query names list");

		return ERV_CONFIG_ERROR;
	}

	INFO_MSG("Will maintain a list of the top %d query names", top_qnames);

	if (((eemo_fn->conf_get_int)(conf_base_path, "top_slds", &top_slds, top_slds) != ERV_OK) ||
	    (top_slds <= 0))
	{
		ERROR_MSG("Failed to retrieve a valid configuration value for the length of the top <x> query SLDs list");

		return ERV_CONFIG_ERROR;
	}

	INFO_MSG("Will maintain a list of the top %d query SLDs", top_slds);

	if ((eemo_fn->conf_get_string)(conf_base_path, "v4_dst", &v4_dst_str, NULL) != ERV_OK)
	{
		ERROR_MSG("Failed to retrieve IPv4 resolver destination address from the configuration");

		return ERV_CONFIG_ERROR;
	}

	if (v4_dst_str != NULL)
	{
		/* Convert string to IPv4 address */
		if (inet_pton(AF_INET, v4_dst_str, &v4_dst) != 1)
		{
			ERROR_MSG("Configured value %s is not a valid IPv4 address", v4_dst_str);

			return ERV_CONFIG_ERROR;
		}

		free(v4_dst_str);
		v4_dst_set = 1;
	}
	else
	{
		WARNING_MSG("No IPv4 resolver destination address specified, will not tally queries over IPv4!");
	}

	if ((eemo_fn->conf_get_string)(conf_base_path, "v6_dst", &v6_dst_str, NULL) != ERV_OK)
	{
		ERROR_MSG("Failed to retrieve IPv6 resolver destination address from the configuration");

		return ERV_CONFIG_ERROR;
	}

	if (v6_dst_str != NULL)
	{
		/* Convert string to IPv6 address */
		if (inet_pton(AF_INET6, v6_dst_str, &v6_dst) != 1)
		{
			ERROR_MSG("Configured value %s is not a valid IPv6 address", v6_dst_str);

			return ERV_CONFIG_ERROR;
		}

		free(v6_dst_str);
		v6_dst_set = 1;
	}
	else
	{
		WARNING_MSG("No IPv6 resolver destination address specified, will not tally queries over IPv6!");
	}

	if ((eemo_fn->conf_get_string)(conf_base_path, "top_v4_file", &top_v4_file, NULL) != ERV_OK)
	{
		ERROR_MSG("Failed to retrieve filename to store top IPv4 client addresses in");

		return ERV_CONFIG_ERROR;
	}

	if (top_v4_file == NULL)
	{
		WARNING_MSG("No file specified to store top IPv4 client addresses in");
	}

	if ((eemo_fn->conf_get_string)(conf_base_path, "top_v4_pfx_file", &top_v4_pfx_file, NULL) != ERV_OK)
	{
		ERROR_MSG("Failed to retrieve filename to store top IPv4 client address prefixes in");

		return ERV_CONFIG_ERROR;
	}

	if (top_v4_pfx_file == NULL)
	{
		WARNING_MSG("No file specified to store top IPv4 client address prefixes in");
	}

	if ((eemo_fn->conf_get_string)(conf_base_path, "top_v6_file", &top_v6_file, NULL) != ERV_OK)
	{
		ERROR_MSG("Failed to retrieve filename to store top IPv6 client addresses in");

		return ERV_CONFIG_ERROR;
	}

	if (top_v6_file == NULL)
	{
		WARNING_MSG("No file specified to store top IPv6 client addresses in");
	}

	if ((eemo_fn->conf_get_string)(conf_base_path, "top_v6_pfx_file", &top_v6_pfx_file, NULL) != ERV_OK)
	{
		ERROR_MSG("Failed to retrieve filename to store top IPv6 client address prefixes in");

		return ERV_CONFIG_ERROR;
	}

	if (top_v6_pfx_file == NULL)
	{
		WARNING_MSG("No file specified to store top IPv6 client address prefixes in");
	}

	if ((eemo_fn->conf_get_string)(conf_base_path, "top_qname_file", &top_qname_file, NULL) != ERV_OK)
	{
		ERROR_MSG("Failed to retrieve filename to store top query names in");

		return ERV_CONFIG_ERROR;
	}

	if (top_qname_file == NULL)
	{
		WARNING_MSG("No file specified to store top query names in");
	}

	if ((eemo_fn->conf_get_string)(conf_base_path, "top_sld_file", &top_sld_file, NULL) != ERV_OK)
	{
		ERROR_MSG("Failed to retrieve filename to store top query SLDs in");

		return ERV_CONFIG_ERROR;
	}

	if (top_sld_file == NULL)
	{
		WARNING_MSG("No file specified to store top query SLDs in");
	}

	if (((eemo_fn->conf_get_int)(conf_base_path, "dumpstats_interval", &dumpstats_interval, dumpstats_interval) != ERV_OK) ||
	   (dumpstats_interval <= 0))
	{
		ERROR_MSG("Invalid statistics interval in configuration");

		return ERV_CONFIG_ERROR;
	}

	/* Register DNS handler */
	if ((eemo_fn->reg_dns_handler)(&eemo_querypop_dns_handler, PARSE_QUERY | PARSE_CANONICALIZE_NAME, &dns_handler_handle) != ERV_OK)
	{
		ERROR_MSG("Failed to register querypop DNS handler");

		(eemo_fn->unreg_dns_handler)(dns_handler_handle);

		return ERV_GENERAL_ERROR;
	}

	INFO_MSG("querypop plugin initialisation complete");

	return ERV_OK;
}

/* Plugin uninitialisation */
eemo_rv eemo_querypop_uninit(eemo_export_fn_table_ptr eemo_fn)
{
	eemo_querypop_int_dumpstats(1);

	INFO_MSG("Uninitialising querypop plugin");

	/* Unregister DNS handler */
	if ((eemo_fn->unreg_dns_handler)(dns_handler_handle) != ERV_OK)
	{
		ERROR_MSG("Failed to unregister querypop DNS handler");
	}

	/* Clean up */
	free(top_v4_file);
	free(top_v4_pfx_file);
	free(top_v6_file);
	free(top_v6_pfx_file);
	free(top_qname_file);
	free(top_sld_file);

	INFO_MSG("Finished uninitialising querypop plugin");

	return ERV_OK;
}

/* Retrieve plugin description */
const char* eemo_querypop_getdescription(void)
{
	return plugin_description;
}

/* Retrieve plugin status */
eemo_rv eemo_querypop_status(void)
{
	return ERV_OK;
}

/* Plugin function table */
static eemo_plugin_fn_table querypop_fn_table =
{
	EEMO_PLUGIN_FN_VERSION,
	&eemo_querypop_init,
	&eemo_querypop_uninit,
	&eemo_querypop_getdescription,
	&eemo_querypop_status
};

/* Entry point for retrieving plugin function table */
eemo_rv eemo_plugin_get_fn_table(eemo_plugin_fn_table_ptrptr fn_table)
{
	if (fn_table == NULL)
	{
		return ERV_PARAM_INVALID;
	}

	*fn_table = &querypop_fn_table;

	return ERV_OK;
}

