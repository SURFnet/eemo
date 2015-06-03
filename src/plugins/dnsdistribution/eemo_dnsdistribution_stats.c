/* $Id$ */

/*
 * Copyright (c) 2010-2011 SURFnet bv
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
 * DNS distribution statistics plugin
 */

#include "config.h"
#include "eemo.h"
#include "eemo_log.h"
#include "eemo_dnsdistribution_stats.h"
#include "uthash.h"
#include "utlist.h"
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

#define IP_ANY	"*"


/* Hashtable that hold strings as keys and integers as values (e.g. domain names and their popularity) */
struct hashentry_si
{
	char *name;
	int value;
	UT_hash_handle hh;         /* makes this structure hashable */
};

/* Hashtable that holds integers as keys and values (e.g. TTLs and their occurrences) */
struct hashentry_ii
{
	int key;
	int value;
	UT_hash_handle hh;
};

/* Linked list that contains <string, integer> hashtables*/
struct ll_hashtable
{
	struct hashentry_si *table;
	char *tag;
	struct ll_hashtable *next;
};

/* Cache hit ratio */
static struct cache_hit_ratio
{
	unsigned int QUERIES;
	unsigned int RESPONSES;
} chr;

/* Configuration */
static char*	stat_file_qname_popularity		= NULL;
static char*	stat_file_ttl				= NULL;
static char**	ips_resolver				= NULL;
static int	ips_count				= NULL;
static struct 	hashentry_si *qname_table	 	= NULL;
static struct	ll_hashtable 	*ttl_table_ALL		= NULL;
static struct	ll_hashtable 	*ttl_table_A		= NULL;
static struct	ll_hashtable 	*ttl_table_AAAA		= NULL;
static struct	ll_hashtable 	*ttl_table_PTR		= NULL;
static struct	ll_hashtable 	*ttl_table_NS		= NULL;
static struct	ll_hashtable 	*ttl_table_SOA		= NULL;
static struct	ll_hashtable 	*ttl_table_CNAME	= NULL;
static struct	ll_hashtable 	*ttl_table_DNSKEY	= NULL;
static struct	ll_hashtable 	*ttl_table_TXT		= NULL;
static struct	ll_hashtable 	*ttl_table_MX		= NULL;
struct 	ll_hashtable *ttl_tables 			= NULL;

/* Statistics file */
FILE*	stat_fp_qname_popularity			= NULL;

/* Sorts two hash_si items, based on their (integer) value */
int sort_on_value_descending(struct hashentry_si* a, struct hashentry_si* b)
{
	return b->value - a->value;
}

/* Sorts two hash_ii items, based on the their (integer) key */
int sort_on_key_ascending(struct hashentry_ii* a, struct hashentry_ii* b)
{
	return a->key - b->key;
}

/* Write statistics to file */
void write_stats(void)
{
	/* Printing QNAME popularity statistics */
	int ln 				= 1;
	stat_fp_qname_popularity 	= fopen(stat_file_qname_popularity, "w");
	struct ll_hashtable *ttl_table 	= NULL;

	if (stat_fp_qname_popularity != NULL)
	{		
		struct hashentry_si *s		= NULL;
		struct hashentry_si *tmp 	= NULL;

		INFO_MSG("Q: A total of %d unique query names were requested", HASH_COUNT(qname_table));		

		/* Sort the qname hashtable */
		HASH_SORT( qname_table, sort_on_value_descending);

		/* Write the statistics to the file */
		fprintf(stat_fp_qname_popularity, "# 'Query name popularity'\t'Query name'\n");

		HASH_ITER(hh, qname_table, s, tmp)
		{
			fprintf(stat_fp_qname_popularity, "%u\t%u\t%s\n", ln, s->value, s->name);
			ln++;
		}

		fflush(stat_fp_qname_popularity);
		fclose(stat_fp_qname_popularity);
	}
	
	/* Printing TTL occurrences statistics */
	LL_FOREACH(ttl_tables, ttl_table)
	{
		char filepath[1024] = {0};
		snprintf(filepath, 1024, "%s.%s", stat_file_ttl, ttl_table->tag);
		FILE* stat_fp_ttl 		= fopen(filepath, "w");
		int total  			= HASH_COUNT(ttl_table->table);
		struct hashentry_ii *t		= NULL; 	/* Temporary structs for iteration */
		struct hashentry_ii *tm		= NULL; 	/* Temporary structs for iteration */
		int cntr 			= 0;

		/* Loop over the TTL hashtable to generate the cumulative table */	
		struct hashentry_ii *ttl_table_cdf = NULL;
		struct hashentry_si *s, *tmp;	/* Temporary structs for iteration */

		HASH_ITER(hh, ttl_table->table, s, tmp)
		{
			/* Check if the current TTL is already an entry in ttl_table_cdf*/
			struct hashentry_ii *e = NULL;
			HASH_FIND_INT(ttl_table_cdf, &(s->value), e);
			if (e != NULL )
                        {
                        	/* TTL was added before: increment its value */
                                e->value++;
                        }
                        else
                        {
                        	/* TTL was not added before: add to ttl_table_cdf */
                                struct hashentry_ii *d = NULL;
                               	d = ( struct hashentry_ii* ) malloc ( sizeof ( struct hashentry_ii ) );
                                d->key = s->value;
                                d->value = 1;
				HASH_ADD_INT( ttl_table_cdf, key, d);	
			}
		}	
		INFO_MSG("R: A total of %-6d unique RR sets (%-4d unique TTLs) were returned and stored in '%s'", total, HASH_COUNT(ttl_table_cdf), filepath)

		HASH_SORT( ttl_table_cdf, sort_on_key_ascending); 
			
		/* Calculate the CDF values as percentages and print them to the file */
		fprintf(stat_fp_ttl, "# 'TTL'\t'Occurrences'\t'CDF value'\n");
		fprintf(stat_fp_ttl, "0\t0\t0\n");  /* First entry is 0,0 */
		HASH_ITER(hh, ttl_table_cdf, t, tm)
		{
			cntr += t->value;
			double perc = (double) cntr / (double) total;
			fprintf(stat_fp_ttl, "%u\t%u\t%0.10f\n", t->key, t->value, perc);
			HASH_DEL(ttl_table_cdf, t);
			free(t);
		}
		
		fflush(stat_fp_ttl);
		fclose(stat_fp_ttl);
	}

	/* Cache hit ratio */
	INFO_MSG("Cache hit ratio: %0.2f%%", 100 - (((double) chr.RESPONSES/ (double) chr.QUERIES)*100));
}

/* Signal handler for alarms & user signals */
void signal_handler(int signum)
{
	if (signum == SIGUSR1)
	{
		DEBUG_MSG("Received user signal to dump statistics");
	}
	else if (signum == SIGALRM)
	{
		DEBUG_MSG("Received automated alarm to dump statistics");
	}
}

/* Initialise the DNS query counter module */
void eemo_dnsdistribution_stats_init(char* stats_file_qname_popularity, char* stats_file_ttl, char** resolver_ips, int ip_count)
{
	stat_file_qname_popularity 	= stats_file_qname_popularity;
	stat_file_ttl 			= stats_file_ttl;
	ips_resolver 			= resolver_ips;
	ips_count 			= ip_count;
	int i 				= 0;

	INFO_MSG("Writing statistics to the files called %s and %s.x", stat_file_qname_popularity, stat_file_ttl);

	for (i = 0; i < ips_count; i++)
	{
		INFO_MSG("The requests are filtered for the resolver with %s as IP address", ips_resolver[i]);
	}

	/* Register signal handler */
	signal(SIGUSR1, signal_handler);
	signal(SIGALRM, signal_handler);

	/* Initialize the TTL tables */
	ttl_table_ALL		= ( struct ll_hashtable* ) malloc ( sizeof ( struct ll_hashtable) );
	ttl_table_A  		= ( struct ll_hashtable* ) malloc ( sizeof ( struct ll_hashtable) );
	ttl_table_AAAA  	= ( struct ll_hashtable* ) malloc ( sizeof ( struct ll_hashtable) );
	ttl_table_PTR  		= ( struct ll_hashtable* ) malloc ( sizeof ( struct ll_hashtable) );
	ttl_table_NS  		= ( struct ll_hashtable* ) malloc ( sizeof ( struct ll_hashtable) );
	ttl_table_SOA		= ( struct ll_hashtable* ) malloc ( sizeof ( struct ll_hashtable) );
	ttl_table_CNAME		= ( struct ll_hashtable* ) malloc ( sizeof ( struct ll_hashtable) );
	ttl_table_DNSKEY	= ( struct ll_hashtable* ) malloc ( sizeof ( struct ll_hashtable) );
	ttl_table_TXT		= ( struct ll_hashtable* ) malloc ( sizeof ( struct ll_hashtable) );
	ttl_table_MX		= ( struct ll_hashtable* ) malloc ( sizeof ( struct ll_hashtable) );
	ttl_table_ALL->tag	= "ALL";
	ttl_table_A->tag	= "A";
	ttl_table_AAAA->tag	= "AAAA";
	ttl_table_PTR->tag	= "PTR";
	ttl_table_NS->tag	= "NS";
	ttl_table_SOA->tag	= "SOA";
	ttl_table_CNAME->tag	= "CNAME";
	ttl_table_DNSKEY->tag	= "DNSKEY";
	ttl_table_TXT->tag	= "TXT";
	ttl_table_MX->tag	= "MX";
	LL_APPEND(ttl_tables, ttl_table_ALL);
	LL_APPEND(ttl_tables, ttl_table_A);
	LL_APPEND(ttl_tables, ttl_table_AAAA);
	LL_APPEND(ttl_tables, ttl_table_PTR);
	LL_APPEND(ttl_tables, ttl_table_NS);
	LL_APPEND(ttl_tables, ttl_table_SOA);
	LL_APPEND(ttl_tables, ttl_table_CNAME);
	LL_APPEND(ttl_tables, ttl_table_DNSKEY);
	LL_APPEND(ttl_tables, ttl_table_TXT);
	LL_APPEND(ttl_tables, ttl_table_MX);
	struct ll_hashtable *s; /* Temporary struct for iteration*/ 
	LL_FOREACH(ttl_tables, s)
	{	
		s->table 	=  NULL;
	}

	/* Initialize cache hit ratio statistics */
	chr.QUERIES 	= 0;
	chr.RESPONSES 	= 0;
}

/* Uninitialise the DNS query counter module */
void eemo_dnsdistribution_stats_uninit(eemo_conf_free_string_array_fn free_strings)
{
	struct hashentry_si *s 		= NULL; /* Temporary struct for iteration */
	struct hashentry_si *tmp 	= NULL; /* Temporary struct for iteration */
	struct ll_hashtable *ttl_table  = NULL;

	/* Unregister signal handlers */
	alarm(0);
	signal(SIGUSR1, SIG_DFL);
	signal(SIGALRM, SIG_DFL);
	
	/* Write statistics */
	write_stats();

	/* Free memory of TTL hashtables */
	LL_FOREACH(ttl_tables, ttl_table)
	{
		struct hashentry_si *s, *tmp;
		HASH_ITER(hh, ttl_table->table, s, tmp)
		{
			HASH_DEL(ttl_table->table, s);
			free(s->name);
			free(s);
		}
		LL_DELETE(ttl_tables, ttl_table);
	}		

	/* Free memory of qname hashtable */
	HASH_ITER(hh, qname_table, s, tmp)
	{
		HASH_DEL(qname_table, s);
		free(s->name);
		free(s);
	}
	
	/* Free memory of the files */
	free(stat_file_qname_popularity);
	free(stat_file_ttl);
}

/* Handle DNS query packets and log the statistics */
eemo_rv eemo_dnsdistribution_stats_handleqr(eemo_ip_packet_info ip_info, int is_tcp, const eemo_dns_packet* dns_packet)
{
	eemo_dns_query* query_it = NULL;
	eemo_dns_rr* rr_it 	 = NULL;

	if (dns_packet->qr_flag)
	{
		int i = 0;
		/* This is a response */

		/* Count only valid responses */
		if (!dns_packet->is_valid)
		{
			return ERV_SKIPPED;
		}
		/* Log TTL value of responses */
		/* Only consider messsages towards the selected resolver */
		for (i = 0; i < ips_count; i++)
		{
			if (!strcmp(ip_info.ip_dst, ips_resolver[i]) || !strcmp(ip_info.ip_dst, IP_ANY))
			{
				/* Only 'authoritative answers' are considered in the cache hit ratio*/
				if (dns_packet->aa_flag == 1)
				{
					chr.RESPONSES++; /* Cache hit ratio statistics */
				}
				
				LL_FOREACH(dns_packet->answers, rr_it)
				{
					struct hashentry_si *s  = NULL;
					/* Select the right hashtable */
			
					switch( rr_it->type )
					{
					case DNS_QTYPE_A:
						HASH_FIND_STR ( ttl_table_A->table, rr_it->name , s );
						break;
					case DNS_QTYPE_AAAA:
						HASH_FIND_STR ( ttl_table_AAAA->table, rr_it->name , s );
						break;
					case DNS_QTYPE_PTR:
						HASH_FIND_STR ( ttl_table_PTR->table, rr_it->name , s );
						break;					
					case DNS_QTYPE_NS:
						HASH_FIND_STR ( ttl_table_NS->table, rr_it->name , s );
						break;					
					case DNS_QTYPE_SOA:
						HASH_FIND_STR ( ttl_table_SOA->table, rr_it->name , s );
						break;					
					case DNS_QTYPE_CNAME:
						HASH_FIND_STR ( ttl_table_CNAME->table, rr_it->name , s );
						break;					
					case DNS_QTYPE_DNSKEY:
						HASH_FIND_STR ( ttl_table_DNSKEY->table, rr_it->name , s );
						break;
					case DNS_QTYPE_TXT:
						HASH_FIND_STR ( ttl_table_TXT->table, rr_it->name , s );
						break;
					case DNS_QTYPE_MX:
						HASH_FIND_STR ( ttl_table_MX->table, rr_it->name , s );
						break;
					default:
						break;
					}
					
					if (s == NULL)
					{
						/* Name was never received before: add to ttl_table, ignore otherwise */
						struct hashentry_si *d = NULL;
						d = ( struct hashentry_si* ) malloc ( sizeof ( struct hashentry_si ) );
						d->name = malloc( strlen( rr_it->name )+1 );
						strcpy(d->name, rr_it->name);
						d->value = rr_it->ttl;

						switch( rr_it->type )
						{
						case DNS_QTYPE_A:
							HASH_ADD_KEYPTR ( hh, ttl_table_A->table, d->name, strlen ( d->name ), d );
							break;
						case DNS_QTYPE_AAAA:
							HASH_ADD_KEYPTR ( hh, ttl_table_AAAA->table, d->name, strlen ( d->name ), d );
							break;
						case DNS_QTYPE_PTR:
							HASH_ADD_KEYPTR ( hh, ttl_table_PTR->table, d->name, strlen ( d->name ), d );
							break;
						case DNS_QTYPE_NS:
							HASH_ADD_KEYPTR ( hh, ttl_table_NS->table, d->name, strlen ( d->name ), d );
							break;
						case DNS_QTYPE_SOA:
							HASH_ADD_KEYPTR ( hh, ttl_table_SOA->table, d->name, strlen ( d->name ), d );
							break;
						case DNS_QTYPE_CNAME:
							HASH_ADD_KEYPTR ( hh, ttl_table_CNAME->table, d->name, strlen ( d->name ), d );
							break;
						case DNS_QTYPE_DNSKEY:
							HASH_ADD_KEYPTR ( hh, ttl_table_DNSKEY->table, d->name, strlen ( d->name ), d );
							break;
						case DNS_QTYPE_TXT:
							HASH_ADD_KEYPTR ( hh, ttl_table_TXT->table, d->name, strlen ( d->name ), d );
							break;
						case DNS_QTYPE_MX:
							HASH_ADD_KEYPTR ( hh, ttl_table_MX->table, d->name, strlen ( d->name ), d );
							break;
						default:
							/* We do not want to collect stats for response types for which no hashtable exist, so the entry is removed */
							free(d->name);
							free(d);
							break;
						}
					}

					/* Also add to the hashtabel that stores ALL responses */
					HASH_FIND_STR ( ttl_table_ALL->table, rr_it->name , s );
					if (s == NULL)
					{
						/* Name was never received before: add to ttl_table */
						struct hashentry_si *d = NULL;
						d = ( struct hashentry_si* ) malloc ( sizeof ( struct hashentry_si ) );
						d->name = malloc( strlen( rr_it->name )+1 );
						strcpy(d->name, rr_it->name);
						d->value = rr_it->ttl;

						HASH_ADD_KEYPTR ( hh, ttl_table_ALL->table, d->name, strlen ( d->name ), d );
					}
				}
				break;
			}
		}
	}
	else
	{
		/* This is a query */		
		int i = 0;
		
		if (!dns_packet->is_valid)
		{
			return ERV_SKIPPED;
		}
		for (i = 0; i < ips_count; i++)
		{
			if (!strcmp(ip_info.ip_dst, ips_resolver[i]) || !strcmp(ip_info.ip_dst, IP_ANY))
			{
				chr.QUERIES++; /* Cache hit ratio statistics */
				LL_FOREACH(dns_packet->questions, query_it)
				{
					/* Log value of domain names */
					struct hashentry_si *s = NULL;
					HASH_FIND_STR ( qname_table, query_it->qname, s );
					if ( s != NULL ) 
					{
						/* Domain name was requested before: increment its value */
						s->value++;
					}
					else
					{
						 /* Domain name was never requested before: add to qname_table */
						struct hashentry_si *d = NULL;
						d = ( struct hashentry_si* ) malloc ( sizeof ( struct hashentry_si ) );
						d->name = malloc( strlen( query_it->qname )+1 );
						strcpy(d->name, query_it->qname);
						d->value = 1;
						HASH_ADD_KEYPTR ( hh, qname_table, d->name, strlen ( d->name ), d );		
					}
				}
			break;
			}
		}
	}

	return ERV_HANDLED;
}
