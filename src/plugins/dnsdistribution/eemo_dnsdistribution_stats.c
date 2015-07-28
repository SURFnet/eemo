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
#include <time.h>

#define IP_ANY	"*"

/* */
typedef enum {
	QUESTION,
	ANSWER,
	AUTHORITY,
	ADDITIONAL
} dns_section; 

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
static struct chr_table
{
	unsigned int QUERIES;
	unsigned int RESPONSES;
} chr;

/* RCODE */
static struct rcodes_table
{
	unsigned int NOERROR;
	unsigned int FORMERR;
	unsigned int SERVFAIL;
	unsigned int NXDOMAIN;
	unsigned int NOTIMPL;
	unsigned int REFUSED;
} rcodes;

/* Statistics file */
FILE*	stat_fp_qnamepop_cl	= NULL;
FILE*	stat_fp_qnamepop_q_ns	= NULL;
FILE*	stat_fp_qnamepop_r_ns	= NULL;
FILE*	stat_fp_general		= NULL;
FILE*	stat_fp_sigs_per_resp	= NULL;
FILE*	stat_fp_rcodes		= NULL;

/* Configuration */
static char*	stat_file_general			= NULL;
static char*	stat_file_qname_popularity		= NULL;
static char*	stat_file_ttl				= NULL;
static char*	stat_file_sigs_per_resp			= NULL;
static char*	stat_file_rcodes			= NULL;
static char**	ips_resolver				= NULL;
static int	ips_count				= 0;
static int 	stat_emit_interval			= 0;
static int 	stat_qname_interval_ctr			= 0;
static int 	curr_stat_qname_interval_ctr		= 0;
static int	nr_quer					= 0;
static int	nr_quer_out				= 0;
static int	nr_resp					= 0;
static int	nr_frag					= 0;
static int	nr_trun					= 0;
static int	nr_trun_with_sigs			= 0;
static int 	nr_sigs					= 0;
static int	nr_resp_with_sigs			= 0;
static struct	timespec time_before;
static struct 	hashentry_si *qname_table	 	= NULL;
static struct 	hashentry_si *qname_table_q_ns 		= NULL;
static struct 	hashentry_si *qname_table_r_ns 		= NULL;
static struct	ll_hashtable 	*ttl_table_ALL		= NULL;
static struct	ll_hashtable 	*ttl_table_A		= NULL;
static struct	ll_hashtable 	*ttl_table_AAAA		= NULL;
static struct	ll_hashtable 	*ttl_table_PTR		= NULL;
static struct	ll_hashtable 	*ttl_table_NS		= NULL;
static struct	ll_hashtable 	*ttl_table_NS_auth	= NULL;
static struct	ll_hashtable 	*ttl_table_SOA		= NULL;
static struct	ll_hashtable 	*ttl_table_SOA_auth	= NULL;
static struct	ll_hashtable 	*ttl_table_DS		= NULL;
static struct	ll_hashtable 	*ttl_table_DS_auth	= NULL;
static struct	ll_hashtable 	*ttl_table_CNAME	= NULL;
static struct	ll_hashtable 	*ttl_table_DNSKEY	= NULL;
static struct	ll_hashtable 	*ttl_table_RRSIG	= NULL;
static struct	ll_hashtable 	*ttl_table_RRSIG_auth	= NULL;
static struct	ll_hashtable 	*ttl_table_TXT		= NULL;
static struct	ll_hashtable 	*ttl_table_MX		= NULL;
static struct	ll_hashtable 	*ttl_table_NSEC		= NULL;
static struct	ll_hashtable 	*ttl_table_NSEC_auth	= NULL;
static struct	ll_hashtable 	*ttl_table_NSEC3	= NULL;
static struct	ll_hashtable 	*ttl_table_NSEC3_auth	= NULL;
static struct	ll_hashtable 	*ttl_table_SRV		= NULL;
static struct	ll_hashtable 	*ttl_table_TSIG		= NULL;
static struct	ll_hashtable 	*ttl_table_DLV		= NULL;
static struct 	ll_hashtable 	*ttl_tables 		= NULL;
static struct	hashentry_ii *sigs_per_resp_table	= NULL;

void init_var(void)
{	
	INFO_MSG("Initializing variables..");
	struct ll_hashtable *s		= NULL; /* Temporary struct for iteration */

	/* Initialize the TTL tables */
	ttl_table_ALL 			= ( struct ll_hashtable* ) malloc ( sizeof ( struct ll_hashtable) );
	ttl_table_A  			= ( struct ll_hashtable* ) malloc ( sizeof ( struct ll_hashtable) );
	ttl_table_AAAA  		= ( struct ll_hashtable* ) malloc ( sizeof ( struct ll_hashtable) );
	ttl_table_PTR  			= ( struct ll_hashtable* ) malloc ( sizeof ( struct ll_hashtable) );
	ttl_table_NS  			= ( struct ll_hashtable* ) malloc ( sizeof ( struct ll_hashtable) );
	ttl_table_NS_auth		= ( struct ll_hashtable* ) malloc ( sizeof ( struct ll_hashtable) );
	ttl_table_SOA			= ( struct ll_hashtable* ) malloc ( sizeof ( struct ll_hashtable) );
	ttl_table_SOA_auth		= ( struct ll_hashtable* ) malloc ( sizeof ( struct ll_hashtable) );
	ttl_table_DS			= ( struct ll_hashtable* ) malloc ( sizeof ( struct ll_hashtable) );
	ttl_table_DS_auth		= ( struct ll_hashtable* ) malloc ( sizeof ( struct ll_hashtable) );
	ttl_table_CNAME			= ( struct ll_hashtable* ) malloc ( sizeof ( struct ll_hashtable) );
	ttl_table_DNSKEY		= ( struct ll_hashtable* ) malloc ( sizeof ( struct ll_hashtable) );
	ttl_table_RRSIG			= ( struct ll_hashtable* ) malloc ( sizeof ( struct ll_hashtable) );
	ttl_table_RRSIG_auth		= ( struct ll_hashtable* ) malloc ( sizeof ( struct ll_hashtable) );
	ttl_table_TXT			= ( struct ll_hashtable* ) malloc ( sizeof ( struct ll_hashtable) );
	ttl_table_MX			= ( struct ll_hashtable* ) malloc ( sizeof ( struct ll_hashtable) );
	ttl_table_NSEC			= ( struct ll_hashtable* ) malloc ( sizeof ( struct ll_hashtable) );
	ttl_table_NSEC_auth		= ( struct ll_hashtable* ) malloc ( sizeof ( struct ll_hashtable) );
	ttl_table_NSEC3			= ( struct ll_hashtable* ) malloc ( sizeof ( struct ll_hashtable) );
	ttl_table_NSEC3_auth		= ( struct ll_hashtable* ) malloc ( sizeof ( struct ll_hashtable) );
	ttl_table_SRV			= ( struct ll_hashtable* ) malloc ( sizeof ( struct ll_hashtable) );
	ttl_table_TSIG			= ( struct ll_hashtable* ) malloc ( sizeof ( struct ll_hashtable) );
	ttl_table_DLV			= ( struct ll_hashtable* ) malloc ( sizeof ( struct ll_hashtable) );
	ttl_table_ALL->tag		= "ALL";
	ttl_table_A->tag		= "A";
	ttl_table_AAAA->tag		= "AAAA";
	ttl_table_PTR->tag		= "PTR";
	ttl_table_NS->tag		= "NS";
	ttl_table_NS_auth->tag		= "NS_AUTH";
	ttl_table_SOA->tag		= "SOA";
	ttl_table_SOA_auth->tag		= "SOA_AUTH";
	ttl_table_DS->tag		= "DS";
	ttl_table_DS_auth->tag		= "DS_AUTH";
	ttl_table_CNAME->tag		= "CNAME";
	ttl_table_DNSKEY->tag		= "DNSKEY";
	ttl_table_RRSIG->tag		= "RRSIG";
	ttl_table_RRSIG_auth->tag	= "RRSIG_AUTH";
	ttl_table_TXT->tag		= "TXT";
	ttl_table_MX->tag		= "MX";
	ttl_table_NSEC->tag		= "NSEC";
	ttl_table_NSEC_auth->tag	= "NSEC_AUTH";
	ttl_table_NSEC3->tag		= "NSEC3";
	ttl_table_NSEC3_auth->tag	= "NSEC3_AUTH";
	ttl_table_SRV->tag		= "SRV";
	ttl_table_TSIG->tag		= "TSIG";
	ttl_table_DLV->tag		= "DLV";
	LL_APPEND(ttl_tables, ttl_table_ALL);
	LL_APPEND(ttl_tables, ttl_table_A);
	LL_APPEND(ttl_tables, ttl_table_AAAA);
	LL_APPEND(ttl_tables, ttl_table_PTR);
	LL_APPEND(ttl_tables, ttl_table_NS);
	LL_APPEND(ttl_tables, ttl_table_NS_auth);
	LL_APPEND(ttl_tables, ttl_table_SOA);
	LL_APPEND(ttl_tables, ttl_table_SOA_auth);
	LL_APPEND(ttl_tables, ttl_table_DS);
	LL_APPEND(ttl_tables, ttl_table_DS_auth);
	LL_APPEND(ttl_tables, ttl_table_CNAME);
	LL_APPEND(ttl_tables, ttl_table_DNSKEY);
	LL_APPEND(ttl_tables, ttl_table_RRSIG);
	LL_APPEND(ttl_tables, ttl_table_RRSIG_auth);
	LL_APPEND(ttl_tables, ttl_table_TXT);
	LL_APPEND(ttl_tables, ttl_table_MX);
	LL_APPEND(ttl_tables, ttl_table_NSEC);
	LL_APPEND(ttl_tables, ttl_table_NSEC_auth);
	LL_APPEND(ttl_tables, ttl_table_NSEC3);
	LL_APPEND(ttl_tables, ttl_table_NSEC3_auth);
	LL_APPEND(ttl_tables, ttl_table_SRV);
	LL_APPEND(ttl_tables, ttl_table_TSIG);
	LL_APPEND(ttl_tables, ttl_table_DLV);
	
	LL_FOREACH(ttl_tables, s)
	{	
		s->table 	=  NULL;
	}

	/* Initialize cache hit ratio statistics */
	chr.QUERIES 		= 0;
	chr.RESPONSES 		= 0;

	/* Initialize RCODES statistics */
	rcodes.NOERROR		= 0;
	rcodes.FORMERR		= 0;
	rcodes.SERVFAIL		= 0;
	rcodes.NXDOMAIN		= 0;
	rcodes.NOTIMPL		= 0;
	rcodes.REFUSED		= 0;

	/* Initialize the variables for counting signatures */
	nr_quer			= 0;
	nr_quer_out		= 0;
	nr_sigs 		= 0;
	nr_frag			= 0;
	nr_trun			= 0;
	nr_trun_with_sigs	= 0;
	nr_resp			= 0;
	nr_resp_with_sigs	= 0;
}

/* Free memory of all variables used in a stat reset (i.e. the filepath values are not freed) */
void free_var(void)
{
	INFO_MSG("Freeing variables");
	struct hashentry_si *s 			= NULL; /* Temporary struct for iteration */
	struct hashentry_si *tmp 		= NULL; /* Temporary struct for iteration */
	struct ll_hashtable *ttl_table  	= NULL;
	struct ll_hashtable *ttl_table_tmp	= NULL;
	struct hashentry_ii *s_ii		= NULL;
	struct hashentry_ii *tmp_ii		= NULL;
	
	/* Free memory of TTL hashtables */
	LL_FOREACH_SAFE(ttl_tables, ttl_table, ttl_table_tmp)
	{
		struct hashentry_si *s, *tmp;
		HASH_ITER(hh, ttl_table->table, s, tmp)
		{
			HASH_DEL(ttl_table->table, s);
			free(s->name);
			free(s);
		}
		LL_DELETE(ttl_tables, ttl_table);
		free(ttl_table);
	}
	
	/* Free memory of nr_sigs_per_resp hashtable */
	HASH_ITER(hh, sigs_per_resp_table, s_ii, tmp_ii)
	{		
		HASH_DEL(sigs_per_resp_table, s_ii);
		free(s_ii);
	}

	/* Free memory of qname hashtable */
	if (curr_stat_qname_interval_ctr >= stat_qname_interval_ctr) 
	{
		HASH_ITER(hh, qname_table, s, tmp)
		{
			HASH_DEL(qname_table, s);
			free(s->name);
			free(s);
		}

		HASH_ITER(hh, qname_table_q_ns, s, tmp)
		{
			HASH_DEL(qname_table_q_ns, s);
			free(s->name);
			free(s);
		}

		HASH_ITER(hh, qname_table_r_ns, s, tmp)
		{
			HASH_DEL(qname_table_r_ns, s);
			free(s->name);
			free(s);
		}
	}
}

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
	INFO_MSG("Writing stats..");
	int ln 				= 1;
	stat_fp_general	 		= fopen(stat_file_general, "a");
	stat_fp_qnamepop_cl 		= fopen(stat_file_qname_popularity, "a");
	stat_fp_sigs_per_resp		= fopen(stat_file_sigs_per_resp, "a");
	stat_fp_rcodes	 		= fopen(stat_file_rcodes, "a");

	/* QNAME table towards NSs */
	char filepath_q_ns[1024] 	= {0};
	snprintf(filepath_q_ns, 1024, "%s_Q_NS", stat_file_qname_popularity);
	stat_fp_qnamepop_q_ns	 	= fopen(filepath_q_ns, "a");

	/* QNAME table from NSs */
	char filepath_r_ns[1024] 	= {0};
	snprintf(filepath_r_ns, 1024, "%s_R_NS", stat_file_qname_popularity);
	stat_fp_qnamepop_r_ns 		= fopen(filepath_r_ns, "a");

	struct ll_hashtable *ttl_table 	= NULL;

	/* Variables used in timing */
	struct timespec time_after;
	long int passed_time_s 		= 0;
	long int passed_time_ns 	= 0;
	float passed_time_total 	= 0;

	clock_gettime(CLOCK_REALTIME, &time_after);

	/* Printing general statistics*/
	passed_time_s = time_after.tv_sec - time_before.tv_sec;
	passed_time_ns = time_after.tv_nsec - time_before.tv_nsec;
	passed_time_total = (float) passed_time_s + (float) passed_time_ns/1000000000;

	if (stat_fp_general != NULL)
	{
		INFO_MSG("- General..");
		/* time, queries, responses, queries to ns, frag, trun, trun_sigs, sigs, resp_sigs, chr*/
		fprintf(stat_fp_general, "%.3f\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%0.2f\n", passed_time_total, nr_quer, nr_resp, chr.RESPONSES, nr_quer_out, nr_frag, nr_trun, nr_trun_with_sigs, nr_sigs, nr_resp_with_sigs, 100 - (((double) chr.RESPONSES/ (double) chr.QUERIES)*100));
		fclose(stat_fp_general);	
	}

	/* Printing QNAME popularity statistics */
	if (stat_fp_qnamepop_cl != NULL && curr_stat_qname_interval_ctr >= stat_qname_interval_ctr)
	{		
		INFO_MSG("- QNAME popularity from clients..");
		struct hashentry_si *s		= NULL;
		struct hashentry_si *tmp 	= NULL;

		/* Sort the qname hashtable */
		HASH_SORT( qname_table, sort_on_value_descending);

		HASH_ITER(hh, qname_table, s, tmp)
		{
			fprintf(stat_fp_qnamepop_cl, "%u\t%u\t%s\n", ln, s->value, s->name);
			ln++;
		}
		fprintf(stat_fp_qnamepop_cl, "\n\n");
		
		fclose(stat_fp_qnamepop_cl);
	}

	ln = 1;
	if (stat_fp_qnamepop_q_ns != NULL && curr_stat_qname_interval_ctr >= stat_qname_interval_ctr)
	{		
		INFO_MSG("- QNAME popularity towards NSs..");
		struct hashentry_si *s		= NULL;
		struct hashentry_si *tmp 	= NULL;

		/* Sort the qname hashtable */
		HASH_SORT( qname_table_q_ns, sort_on_value_descending);

		HASH_ITER(hh, qname_table_q_ns, s, tmp)
		{
			fprintf(stat_fp_qnamepop_q_ns, "%u\t%u\t%s\n", ln, s->value, s->name);
			ln++;
		}
		fprintf(stat_fp_qnamepop_q_ns, "\n\n");
		
		fclose(stat_fp_qnamepop_q_ns);
	}
	
	ln = 1;	
	if (stat_fp_qnamepop_r_ns != NULL && curr_stat_qname_interval_ctr >= stat_qname_interval_ctr)
	{		
		INFO_MSG("- QNAME popularity from NSs..");
		struct hashentry_si *s		= NULL;
		struct hashentry_si *tmp 	= NULL;

		/* Sort the qname hashtable */
		HASH_SORT( qname_table_r_ns, sort_on_value_descending);

		HASH_ITER(hh, qname_table_r_ns, s, tmp)
		{
			fprintf(stat_fp_qnamepop_r_ns, "%u\t%u\t%s\n", ln, s->value, s->name);
			ln++;
		}
		fprintf(stat_fp_qnamepop_r_ns, "\n\n");
		
		fclose(stat_fp_qnamepop_r_ns);
	}

	/* Printing TTL occurrences statistics */
	INFO_MSG("- TTL occurrences..");
	LL_FOREACH(ttl_tables, ttl_table)
	{
		char filepath[1024] = {0};
		snprintf(filepath, 1024, "%s.%s", stat_file_ttl, ttl_table->tag);
		FILE* stat_fp_ttl 		= fopen(filepath, "a");
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

		HASH_SORT( ttl_table_cdf, sort_on_key_ascending); 
			
		/* Calculate the CDF values as percentages and print them to the file */
		fprintf(stat_fp_ttl, "0\t0\t0\n");  /* First entry is 0,0 */
		HASH_ITER(hh, ttl_table_cdf, t, tm)
		{
			cntr += t->value;
			double perc = (double) cntr / (double) total;
			fprintf(stat_fp_ttl, "%u\t%u\t%0.10f\n", t->key, t->value, perc);
			HASH_DEL(ttl_table_cdf, t);
			free(t);
		}
		fprintf(stat_fp_ttl, "\n\n");
		
		fclose(stat_fp_ttl);
	}

	/* Printing number of signatures per query statistics */
	if (stat_fp_sigs_per_resp != NULL)
	{
		INFO_MSG("- Signatures per query..");
                HASH_SORT( sigs_per_resp_table, sort_on_key_ascending);

		struct hashentry_ii *s_ii	= NULL;
		struct hashentry_ii *tmp_ii	= NULL;
		HASH_ITER(hh, sigs_per_resp_table, s_ii, tmp_ii)
		{
			fprintf(stat_fp_sigs_per_resp, "%d\t%d\n", s_ii->key, s_ii->value);
		}
		fprintf(stat_fp_sigs_per_resp, "\n\n");		
		
		fclose(stat_fp_sigs_per_resp);
	}	
	
	/* Printing rcode statistics */
	if (stat_fp_rcodes != NULL)
	{
		INFO_MSG("- RCODE..");
		fprintf(stat_fp_rcodes, "%d\t%d\t%d\t%d\t%d\t%d\n", rcodes.NOERROR, rcodes.FORMERR, rcodes.SERVFAIL, rcodes.NXDOMAIN, rcodes.NOTIMPL, rcodes.REFUSED);	
		
		fclose(stat_fp_rcodes);
	}	
}

/* Reset statistics */
void reset_stats(void)
{
	INFO_MSG("Resetting stats..");
	free_var();	
	init_var();
}

/* Initialise the DNS query counter module */
void eemo_dnsdistribution_stats_init(char* stats_file_general, char* stats_file_qname_popularity, char* stats_file_ttl, char* stats_file_sigs_per_resp, char* stats_file_rcodes, char** resolver_ips, int ip_count, int emit_interval, int emit_qname_ctr)
{
	stat_file_general 		= stats_file_general;
	stat_file_qname_popularity 	= stats_file_qname_popularity;
	stat_file_ttl 			= stats_file_ttl;
	stat_file_sigs_per_resp		= stats_file_sigs_per_resp;
	stat_file_rcodes		= stats_file_rcodes;
	ips_resolver 			= resolver_ips;
	ips_count 			= ip_count;
	stat_emit_interval		= emit_interval;
	stat_qname_interval_ctr		= emit_qname_ctr;
	int i 				= 0;
	struct ll_hashtable *ttl_table 	= NULL;

	INFO_MSG("Writing statistics to the files %s, %s, %s and %s.x", stat_file_general, stat_file_qname_popularity, stat_file_rcodes, stat_file_ttl);

	for (i = 0; i < ips_count; i++)
	{
		INFO_MSG("The requests are filtered for the resolver with %s as IP address", ips_resolver[i]);
	}

	if (stat_emit_interval > 0)
	{
		INFO_MSG("Emitting statistics every %d seconds", stat_emit_interval);
	}
	else
	{
		INFO_MSG("Not emitting statistics per interval");	
	}
	
	INFO_MSG("Qname popularity is only transmitted once every %d emit intervals", stat_qname_interval_ctr);	

	init_var();

	/* Create output files, initialize the first line */
	stat_fp_general = fopen(stat_file_general, "w");
	if (stat_fp_general != NULL) fprintf(stat_fp_general, "time\tqueries\tresponses\tauth_resp\toutgoing queries\tfrag\ttrunc\ttrunc_w_sigs\tsignatures\tresponses_w_sigs\tchr\n");
	fclose(stat_fp_general);
	
	stat_fp_qnamepop_cl = fopen(stat_file_qname_popularity, "w");
	if (stat_fp_qnamepop_cl != NULL) fprintf(stat_fp_qnamepop_cl, "line number\tpopularity\tdomain name\n");
	fclose(stat_fp_qnamepop_cl);

	char filepath_q_ns[1024] = {0};
        snprintf(filepath_q_ns, 1024, "%s_Q_NS", stat_file_qname_popularity);
        FILE* stat_fp_qnamepop_q_ns = fopen(filepath_q_ns, "w");
	if (stat_fp_qnamepop_q_ns != NULL) fprintf(stat_fp_qnamepop_q_ns, "line number\tpopularity\tdomain name\n");
	fclose(stat_fp_qnamepop_q_ns);

	char filepath_r_ns[1024] = {0};
        snprintf(filepath_r_ns, 1024, "%s_R_NS", stat_file_qname_popularity);
        FILE* stat_fp_qnamepop_r_ns = fopen(filepath_r_ns, "w");
	if (stat_fp_qnamepop_r_ns != NULL) fprintf(stat_fp_qnamepop_r_ns, "line number\tpopularity\tdomain name\n");
	fclose(stat_fp_qnamepop_r_ns);

	stat_fp_sigs_per_resp  = fopen(stat_file_sigs_per_resp, "w");
	if (stat_fp_sigs_per_resp != NULL) fprintf(stat_fp_sigs_per_resp, "sigs per resp\toccurrence\n");
	fclose(stat_fp_sigs_per_resp);

	stat_fp_rcodes  = fopen(stat_file_rcodes, "w");
	if (stat_fp_rcodes != NULL) fprintf(stat_fp_rcodes, "NOERROR\tFORMERR\tSERVFAIL\tNXDOMAIN\tNOTIMPL\tREFUSED\n");
	fclose(stat_fp_rcodes);
	
	LL_FOREACH(ttl_tables, ttl_table)
	{
		char filepath[1024] = {0};
		snprintf(filepath, 1024, "%s.%s", stat_file_ttl, ttl_table->tag);
		FILE *stat_fp_ttl = fopen(filepath, "w");
		if (stat_fp_ttl != NULL) fprintf(stat_fp_ttl, "ttl\toccurrence\tcdf\n");
		fclose(stat_fp_ttl);
	}

	/* Initialize the timer */
	clock_gettime(CLOCK_REALTIME, &time_before);
}

/* Uninitialise the DNS query counter module */
void eemo_dnsdistribution_stats_uninit(eemo_conf_free_string_array_fn free_strings)
{
	INFO_MSG("Uninitialize DNS distribution plugin..");
	struct hashentry_si *s 		= NULL; /* Temporary struct for iteration */
	struct hashentry_si *tmp 	= NULL; /* Temporary struct for iteration */
	struct ll_hashtable *ttl_table  = NULL;
	
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
	
	HASH_ITER(hh, qname_table_q_ns, s, tmp)
	{
		HASH_DEL(qname_table_q_ns, s);
		free(s->name);
		free(s);
	}

	HASH_ITER(hh, qname_table_r_ns, s, tmp)
	{
		HASH_DEL(qname_table_r_ns, s);
		free(s->name);
		free(s);
	}

	/* Free memory of the files */
	free(stat_file_general);
	free(stat_file_qname_popularity);
	free(stat_file_ttl);
	free(stat_file_sigs_per_resp);
	free(stat_file_rcodes);
}

/* Analyses the RR set for statistic purposes,
   returns if the RR is a signature */
int analyse_rr(eemo_dns_rr* rr_it, dns_section section)
{
	int is_sig = 0;

	/* Check if the RR set is a signature */
	if(rr_it->type == DNS_QTYPE_RRSIG)
	{	
		nr_sigs++;
		is_sig++;
	}

	struct hashentry_si *s  = NULL; /* Search entry */

	/* DEBUG */
	if (section == AUTHORITY && rr_it->type != DNS_QTYPE_NS && rr_it->type != DNS_QTYPE_RRSIG && rr_it->type != DNS_QTYPE_SOA && rr_it->type != DNS_QTYPE_NSEC && rr_it->type != DNS_QTYPE_NSEC3 && rr_it->type != DNS_QTYPE_DS){
		INFO_MSG("Unexpected type: %d", rr_it->type);
	}

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
		if (section == ANSWER){
			HASH_FIND_STR ( ttl_table_NS->table, rr_it->name , s );
		}
		else if (section == AUTHORITY){
			HASH_FIND_STR ( ttl_table_NS_auth->table, rr_it->name , s );
		}
		break;					
	case DNS_QTYPE_SOA:
		if (section == ANSWER){
			HASH_FIND_STR ( ttl_table_SOA->table, rr_it->name , s );
		}
		else if (section == AUTHORITY){
			HASH_FIND_STR ( ttl_table_SOA_auth->table, rr_it->name , s );
		}
		break;					
	case DNS_QTYPE_DS:
		if (section == ANSWER){
			HASH_FIND_STR ( ttl_table_DS->table, rr_it->name , s );
		}
		else if (section == AUTHORITY){
			HASH_FIND_STR ( ttl_table_DS_auth->table, rr_it->name , s );
		}
		break;					
	case DNS_QTYPE_CNAME:
		HASH_FIND_STR ( ttl_table_CNAME->table, rr_it->name , s );
		break;					
	case DNS_QTYPE_DNSKEY:
		HASH_FIND_STR ( ttl_table_DNSKEY->table, rr_it->name , s );
		break;
	case DNS_QTYPE_RRSIG:
		if (section == ANSWER){
			HASH_FIND_STR ( ttl_table_RRSIG->table, rr_it->name , s );
		}
		else if (section == AUTHORITY){
			HASH_FIND_STR ( ttl_table_RRSIG_auth->table, rr_it->name , s );
		}
		break;
	case DNS_QTYPE_TXT:
		HASH_FIND_STR ( ttl_table_TXT->table, rr_it->name , s );
		break;
	case DNS_QTYPE_NSEC:
		if (section == ANSWER){
			HASH_FIND_STR ( ttl_table_NSEC->table, rr_it->name , s );
		}
		else if (section == AUTHORITY){
			HASH_FIND_STR ( ttl_table_NSEC_auth->table, rr_it->name , s );
		}
		break;
	case DNS_QTYPE_NSEC3:
		if (section == ANSWER){
			HASH_FIND_STR ( ttl_table_NSEC3->table, rr_it->name , s );
		}
		else if (section == AUTHORITY){
			HASH_FIND_STR ( ttl_table_NSEC3_auth->table, rr_it->name , s );
		}
		break;
	case DNS_QTYPE_SRV:
		HASH_FIND_STR ( ttl_table_SRV->table, rr_it->name , s );
		break;
	case DNS_QTYPE_TSIG:
		HASH_FIND_STR ( ttl_table_TSIG->table, rr_it->name , s );
		break;
	case DNS_QTYPE_DLV:
		HASH_FIND_STR ( ttl_table_DLV->table, rr_it->name , s );
		break;
	default:
		break;
	}
	
	/* Name was never received before: add to ttl_table, ignore otherwise */
	if (s == NULL)
	{
		struct hashentry_si *d = NULL; /* new entry */
		d = ( struct hashentry_si* ) malloc ( sizeof ( struct hashentry_si ) );
		d->name = strdup(rr_it->name);
		d->value = rr_it->ttl;

		/* Add the new entry to the correct hashtable, based on its response type */
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
			if (section == ANSWER){
				HASH_ADD_KEYPTR ( hh, ttl_table_NS->table, d->name, strlen ( d->name ), d );
			}
			else if (section == AUTHORITY){
				HASH_ADD_KEYPTR ( hh, ttl_table_NS_auth->table, d->name, strlen ( d->name ), d );
			}
			break;
		case DNS_QTYPE_SOA:
			if (section == ANSWER){
				HASH_ADD_KEYPTR ( hh, ttl_table_SOA->table, d->name, strlen ( d->name ), d );
			}
			else if (section == AUTHORITY){
				HASH_ADD_KEYPTR ( hh, ttl_table_SOA_auth->table, d->name, strlen ( d->name ), d );
			}
			break;
		case DNS_QTYPE_DS:
			if (section == ANSWER){
				HASH_ADD_KEYPTR ( hh, ttl_table_DS->table, d->name, strlen ( d->name ), d );
			}
			else if (section == AUTHORITY){
				HASH_ADD_KEYPTR ( hh, ttl_table_DS_auth->table, d->name, strlen ( d->name ), d );
			}
			break;
		case DNS_QTYPE_CNAME:
			HASH_ADD_KEYPTR ( hh, ttl_table_CNAME->table, d->name, strlen ( d->name ), d );
			break;
		case DNS_QTYPE_DNSKEY:
			HASH_ADD_KEYPTR ( hh, ttl_table_DNSKEY->table, d->name, strlen ( d->name ), d );
			break;
		case DNS_QTYPE_RRSIG:
			if (section == ANSWER){
				HASH_ADD_KEYPTR ( hh, ttl_table_RRSIG->table, d->name, strlen ( d->name ), d );
			}
			else if (section == AUTHORITY){
				HASH_ADD_KEYPTR ( hh, ttl_table_RRSIG_auth->table, d->name, strlen ( d->name ), d );
			}
			break;
		case DNS_QTYPE_TXT:
			HASH_ADD_KEYPTR ( hh, ttl_table_TXT->table, d->name, strlen ( d->name ), d );
			break;
		case DNS_QTYPE_MX:
			HASH_ADD_KEYPTR ( hh, ttl_table_MX->table, d->name, strlen ( d->name ), d );
			break;
		case DNS_QTYPE_NSEC:
			if (section == ANSWER){
				HASH_ADD_KEYPTR ( hh, ttl_table_NSEC->table, d->name, strlen ( d->name ), d );
			}
			else if (section == AUTHORITY){
				HASH_ADD_KEYPTR ( hh, ttl_table_NSEC_auth->table, d->name, strlen ( d->name ), d );
			}
			break;
		case DNS_QTYPE_NSEC3:
			if (section == ANSWER){
				HASH_ADD_KEYPTR ( hh, ttl_table_NSEC3->table, d->name, strlen ( d->name ), d );
			}
			else if (section == AUTHORITY){
				HASH_ADD_KEYPTR ( hh, ttl_table_NSEC3_auth->table, d->name, strlen ( d->name ), d );
			}
			break;
		case DNS_QTYPE_SRV:
			HASH_ADD_KEYPTR ( hh, ttl_table_SRV->table, d->name, strlen ( d->name ), d );
			break;
		case DNS_QTYPE_TSIG:
			HASH_ADD_KEYPTR ( hh, ttl_table_TSIG->table, d->name, strlen ( d->name ), d );
			break;
		case DNS_QTYPE_DLV:
			HASH_ADD_KEYPTR ( hh, ttl_table_DLV->table, d->name, strlen ( d->name ), d );
			break;
		default:
			/* We do not want to collect stats for response types for which no hashtable exist, so the entry is removed */
			free(d->name);
			free(d);
			break;
		}
	}
	
	/* Also add to the hashtable that stores ALL responses */
	s = NULL;
	HASH_FIND_STR ( ttl_table_ALL->table, rr_it->name , s );
	if (s == NULL)
	{
		/* Name was never received before: add to ttl_table */
		struct hashentry_si *d = NULL;
		d = ( struct hashentry_si* ) malloc ( sizeof ( struct hashentry_si ) );
		d->name = strdup(rr_it->name);
		d->value = rr_it->ttl;

		HASH_ADD_KEYPTR ( hh, ttl_table_ALL->table, d->name, strlen ( d->name ), d );
	}

	return is_sig;
}

/* Handle DNS query packets and log the statistics */
eemo_rv eemo_dnsdistribution_stats_handleqr(eemo_ip_packet_info ip_info, int is_tcp, const eemo_dns_packet* dns_packet)
{
	eemo_dns_query* query_it = NULL;
	eemo_dns_rr* rr_it 	 = NULL;

	/* Variables used for timing */
	struct timespec time_after;
	long int passed_time_s = 0;
	long int passed_time_ns = 0;
	float passed_time_total = 0;

	clock_gettime(CLOCK_REALTIME, &time_after);
	passed_time_s = time_after.tv_sec - time_before.tv_sec;
	passed_time_ns = time_after.tv_nsec - time_before.tv_nsec;
	passed_time_total = (float) passed_time_s + (float) passed_time_ns/1000000000;

	/* Write statistics if the sufficient amount of time has passed */
	if (passed_time_total >= stat_emit_interval)
	{
		curr_stat_qname_interval_ctr += 1;
		write_stats();
		reset_stats();
		if (curr_stat_qname_interval_ctr >= stat_qname_interval_ctr) curr_stat_qname_interval_ctr = 0;
		
		/* Reset the timer */
		clock_gettime(CLOCK_REALTIME, &time_before);
	}
		
	if (dns_packet->qr_flag)
	{
		/* This is a response */
		
		int sigs_in_resp = 0;
		int i 		 = 0;
		
		/* Count only valid responses */
		if (!dns_packet->is_valid)
		{
			return ERV_SKIPPED;
		}

		/* Log TTL value of responses 
		   Only consider messsages towards the selected resolver */
		for (i = 0; i < ips_count; i++)
		{
			if ((!strcmp(ip_info.ip_dst, ips_resolver[i]) || !strcmp(ip_info.ip_dst, IP_ANY)) && dns_packet->srcport == 53 && dns_packet->dstport != 53)
			{
				struct hashentry_ii *search_entry = NULL;
				nr_resp++;
			
				/* Count number of fragmented responses */	
				if (dns_packet->is_fragmented)
				{
					nr_frag++;
				}

				/* Only 'authoritative answers' are considered in the cache hit ratio*/
				if (dns_packet->aa_flag == 1)
				{
					chr.RESPONSES++; /* Cache hit ratio statistics */
				}
				
				/* Iterate over all QUESTION records */	
				LL_FOREACH(dns_packet->questions, query_it)
				{
					/* Log popularity of domain names */
					struct hashentry_si *s = NULL;
					HASH_FIND_STR ( qname_table_r_ns, query_it->qname, s );
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
						HASH_ADD_KEYPTR ( hh, qname_table_r_ns, d->name, strlen ( d->name ), d );	
					}
				}

				/* Iterate over all ANSWER records */
				LL_FOREACH(dns_packet->answers, rr_it)
				{
					sigs_in_resp +=	analyse_rr(rr_it, ANSWER);
				}

				/* Iterate over all AUTHORITY records */
				LL_FOREACH(dns_packet->authorities, rr_it)
				{
					sigs_in_resp +=	analyse_rr(rr_it, AUTHORITY);
				}

				/* Iterate over all ADDITIONAL records */
				LL_FOREACH(dns_packet->additionals, rr_it)
				{
				}

				/* Store the RCODE of the packet */
				switch(dns_packet->rcode)
				{
					case DNS_RCODE_NOERROR:
						rcodes.NOERROR++;
						break;
					case DNS_RCODE_FORMERR:
						rcodes.FORMERR++;
						break;
					case DNS_RCODE_SERVFAIL:
						rcodes.SERVFAIL++;
						break;
					case DNS_RCODE_NXDOMAIN:
						rcodes.NXDOMAIN++;
						break;
					case DNS_RCODE_NOTIMPL:
						rcodes.NOTIMPL++;
						break;
					case DNS_RCODE_REFUSED:
						rcodes.REFUSED++;
						break;
					default:
						break;
				}						
			
				/* Store whether the response contained signatures */	
				if (sigs_in_resp  > 0) nr_resp_with_sigs++;                                                     
				/* Store wether the response was truncated */
				if (dns_packet->tc_flag)
				{
					nr_trun++;
					if (sigs_in_resp > 0) nr_trun_with_sigs++;				
				}

				/* Store the number of signatures in the hashtable */
				HASH_FIND_INT(sigs_per_resp_table, &sigs_in_resp, search_entry);
				if (search_entry != NULL )
				{
					search_entry->value++;
				}
				else
				{
					struct hashentry_ii *new_entry = NULL;
					new_entry  = ( struct hashentry_ii* ) malloc ( sizeof ( struct hashentry_ii ) );
					new_entry->key = sigs_in_resp;
					new_entry->value = 1;
					HASH_ADD_INT( sigs_per_resp_table, key, new_entry);	
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
			/* Incoming queries */
			if ((!strcmp(ip_info.ip_dst, ips_resolver[i]) || !strcmp(ip_info.ip_dst, IP_ANY)) && dns_packet->srcport != 53 && dns_packet->dstport == 53)
			{
				nr_quer++;
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
			
			/* Outgoing queries */
			else if ((!strcmp(ip_info.ip_src, ips_resolver[i]) || !strcmp(ip_info.ip_src, IP_ANY)) && dns_packet->srcport != 53 && dns_packet->dstport == 53)
			{
				nr_quer_out++;

				LL_FOREACH(dns_packet->questions, query_it)
                                {
                                        /* Log value of domain names */
                                        struct hashentry_si *s = NULL;
                                        HASH_FIND_STR ( qname_table_q_ns, query_it->qname, s );
                                        if ( s != NULL )
                                        {
                                                /* Domain name was requested before: increment its value */
                                                s->value++;
                                        }
                                        else
                                        {
                                                 /* Domain name was never requested before: add to qname_table_q_ns */
                                                struct hashentry_si *d = NULL;
                                                d = ( struct hashentry_si* ) malloc ( sizeof ( struct hashentry_si ) );
                                                d->name = malloc( strlen( query_it->qname )+1 );
                                                strcpy(d->name, query_it->qname);
                                                d->value = 1;
                                                HASH_ADD_KEYPTR ( hh, qname_table_q_ns, d->name, strlen ( d->name ), d );
                                        }
                                }

			}			
		}
	}

	return ERV_HANDLED;
}
