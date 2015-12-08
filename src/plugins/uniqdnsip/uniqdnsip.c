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
 * DNS client population size monitoring plugin
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
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "eemo.h"
#include "eemo_api.h"
#include "eemo_plugin_log.h"
#include "dns_handler.h"
#include "dns_parser.h"
#include "uthash.h"

const static char* plugin_description = "EEMO DNS client population size monitoring plugin " PACKAGE_VERSION;

/* DNS handler handles */
static unsigned long	dns_handler_handle	= 0;

/* Output files */
static char*		dnsuniq_hour_file	= NULL;
static char*		dnsuniq_day_file	= NULL;
static char*		dnsuniq_week_file	= NULL;
static const char*	type_hourly		= "hourly";
static const char*	type_daily		= "daily";
static const char*	type_weekly		= "weekly";

/* DNS server IPs */
static char**		server_ips		= NULL;
static int		server_ips_ct		= 0;

/* Time keeping */
static struct
{
	int	day;
	int	month;
	int	year;
	time_t	next_epoch_hour_utc;
	time_t	next_epoch_day_utc;
	time_t	next_epoch_week_utc;
	time_t	prev_ts;
}
dnsuniq_today = { 0, 0, 0, 0, 0, 0, 0 };

static int	time_initialised	= 0;

typedef struct ip4_reg_ht
{
	struct in_addr	addr;
	unsigned long	seen_count;
	UT_hash_handle	hh;
}
ip4_reg_ht;

typedef struct ip6_reg_ht
{
	struct in6_addr	addr;
	unsigned long	seen_count;
	UT_hash_handle	hh;
}
ip6_reg_ht;

/* Hash tables */
static ip4_reg_ht*	v4_hour_ht	= NULL;
static ip6_reg_ht*	v6_hour_ht	= NULL;
static ip4_reg_ht*	v4_day_ht	= NULL;
static ip6_reg_ht*	v6_day_ht	= NULL;
static ip4_reg_ht*	v4_week_ht	= NULL;
static ip6_reg_ht*	v6_week_ht	= NULL;

typedef struct writer_params
{
	ip4_reg_ht*	v4_ht;
	ip6_reg_ht*	v6_ht;
	char		ts_str[256];
	const char*	type_str;
	char*		filename;
	time_t		ts;
}
writer_params;

/* Writer thread */
static void* eemo_dnsuniqip_writer(void* params)
{
	assert(params != NULL);

	writer_params*	wparams	= (writer_params*) params;

	ip4_reg_ht*		v4_ht_it	= NULL;
	ip4_reg_ht*		v4_ht_tmp	= NULL;
	ip6_reg_ht*		v6_ht_it	= NULL;
	ip6_reg_ht*		v6_ht_tmp	= NULL;
	unsigned long long	tot_ip_count	= 0;
	unsigned long long	v4_ip_count	= 0;
	unsigned long long	v6_ip_count	= 0;
	unsigned long long	tot_q_count	= 0;
	unsigned long long	v4_q_count	= 0;
	unsigned long long	v6_q_count	= 0;
	FILE*			out		= NULL;

	HASH_ITER(hh, wparams->v4_ht, v4_ht_it, v4_ht_tmp)
	{
		tot_ip_count++;
		v4_ip_count++;
		tot_q_count += v4_ht_it->seen_count;
		v4_q_count += v4_ht_it->seen_count;

		HASH_DEL(wparams->v4_ht, v4_ht_it);
		free(v4_ht_it);
	}

	HASH_ITER(hh, wparams->v6_ht, v6_ht_it, v6_ht_tmp)
	{
		tot_ip_count++;
		v6_ip_count++;
		tot_q_count += v6_ht_it->seen_count;
		v6_q_count += v6_ht_it->seen_count;

		HASH_DEL(wparams->v6_ht, v6_ht_it);
		free(v6_ht_it);
	}

	out = fopen(wparams->filename, "a");

	if (out != NULL)
	{
		fprintf(out, "%s;%u;%llu;%llu;%llu;%llu;%llu;%llu\n", wparams->ts_str, (unsigned int) wparams->ts, tot_ip_count, tot_q_count, v4_ip_count, v4_q_count, v6_ip_count, v6_q_count);

		fclose(out);

		INFO_MSG("Wrote %s statistics for %s", wparams->type_str, wparams->ts_str);
	}
	else
	{
		ERROR_MSG("Failed to write statistics to %s", wparams->filename);
	}

	free(wparams);

	return NULL;
}

/* Open file for the current day */
static void check_timers(time_t ts)
{
	struct tm	utc_time;
	char*		tzone		= NULL;

	if (!time_initialised)
	{
		/* Determine the current day and the next epoch hour, day and week */
		gmtime_r((const time_t*) &ts, &utc_time);

		dnsuniq_today.day	= utc_time.tm_mday;
		dnsuniq_today.month	= utc_time.tm_mon + 1;
		dnsuniq_today.year	= utc_time.tm_year + 1900;
		dnsuniq_today.prev_ts	= ts;

		tzone = getenv("TZ");
	
		if (tzone != NULL) tzone = strdup(tzone);

		setenv("TZ", "", 1);

		tzset();

		/* Compute the next hour epoch time */
		utc_time.tm_min = utc_time.tm_sec = 0;

		dnsuniq_today.next_epoch_hour_utc = mktime(&utc_time) + 3600;

		/* Now compute the next UTC day epoch time */
		utc_time.tm_hour = utc_time.tm_min = utc_time.tm_sec = 0;

		dnsuniq_today.next_epoch_day_utc = mktime(&utc_time) + 86400;

		/* And compute the next epoch week */
		dnsuniq_today.next_epoch_week_utc = dnsuniq_today.next_epoch_day_utc - (utc_time.tm_wday * 86400) + (7*86400);

		if (tzone != NULL)
		{
			setenv("TZ", tzone, 1);
			free(tzone);
		}
		else
		{
			unsetenv("TZ");
		}
	
		tzset();

		INFO_MSG("First timestamp is for %04d-%02d-%02d", dnsuniq_today.year, dnsuniq_today.month, dnsuniq_today.day);
		INFO_MSG("The epoch time is %u", (unsigned int) ts);
		INFO_MSG("Next epoch hour is at %u", (unsigned int) dnsuniq_today.next_epoch_hour_utc);
		INFO_MSG("Next epoch day is at %u", (unsigned int) dnsuniq_today.next_epoch_day_utc);
		INFO_MSG("Next epoch week is at %u", (unsigned int) dnsuniq_today.next_epoch_week_utc);

		time_initialised = 1;

		return;
	}

	gmtime_r((const time_t*) &dnsuniq_today.prev_ts, &utc_time);

	/* Check if we passed to the next hour */
	if (ts >= dnsuniq_today.next_epoch_hour_utc)
	{
		writer_params*	wparams	= (writer_params*) malloc(sizeof(writer_params));
		pthread_t	wthread;

		snprintf(wparams->ts_str, 256, "%04d-%02d-%02d %02d:%02d:%02d", utc_time.tm_year+1900, utc_time.tm_mon+1, utc_time.tm_mday, utc_time.tm_hour, utc_time.tm_min, utc_time.tm_sec);

		wparams->filename = dnsuniq_hour_file;
		wparams->ts = dnsuniq_today.prev_ts;
		wparams->v4_ht = v4_hour_ht;
		wparams->v6_ht = v6_hour_ht;
		wparams->type_str = type_hourly;

		v4_hour_ht = NULL;
		v6_hour_ht = NULL;

		/* Fork off a writer thread */
		if (pthread_create(&wthread, NULL, eemo_dnsuniqip_writer, wparams) != 0)
		{
			ERROR_MSG("Failed to start writer thread for hourly results");
		}
		else
		{
			pthread_detach(wthread);
		}

		dnsuniq_today.next_epoch_hour_utc += 3600;
	}

	/* Check if we passed to the next day */
	if (ts >= dnsuniq_today.next_epoch_day_utc)
	{
		writer_params*	wparams	= (writer_params*) malloc(sizeof(writer_params));
		pthread_t	wthread;

		snprintf(wparams->ts_str, 256, "%04d-%02d-%02d", utc_time.tm_year+1900, utc_time.tm_mon+1, utc_time.tm_mday);

		wparams->filename = dnsuniq_day_file;
		wparams->ts = dnsuniq_today.prev_ts;
		wparams->v4_ht = v4_day_ht;
		wparams->v6_ht = v6_day_ht;
		wparams->type_str = type_daily;

		v4_day_ht = NULL;
		v6_day_ht = NULL;

		/* Fork off a writer thread */
		if (pthread_create(&wthread, NULL, eemo_dnsuniqip_writer, wparams) != 0)
		{
			ERROR_MSG("Failed to start writer thread for daily results");
		}
		else
		{
			pthread_detach(wthread);
		}

		dnsuniq_today.next_epoch_day_utc += 86400;
	}

	/* Check if we passed to the next week */
	if (ts >= dnsuniq_today.next_epoch_week_utc)
	{
		writer_params*	wparams	= (writer_params*) malloc(sizeof(writer_params));
		pthread_t	wthread;

		snprintf(wparams->ts_str, 256, "%04d-%02d-%02d", utc_time.tm_year+1900, utc_time.tm_mon+1, utc_time.tm_mday);

		wparams->filename = dnsuniq_week_file;
		wparams->ts = dnsuniq_today.prev_ts;
		wparams->v4_ht = v4_week_ht;
		wparams->v6_ht = v6_week_ht;
		wparams->type_str = type_weekly;

		v4_week_ht = NULL;
		v6_week_ht = NULL;

		/* Fork off a writer thread */
		if (pthread_create(&wthread, NULL, eemo_dnsuniqip_writer, wparams) != 0)
		{
			ERROR_MSG("Failed to start writer thread for weekly results");
		}
		else
		{
			pthread_detach(wthread);
		}

		dnsuniq_today.next_epoch_week_utc += 7*86400;
	}

	dnsuniq_today.prev_ts = ts;
}

/* DNS handler */
eemo_rv eemo_dnsuniqip_dns_handler(eemo_ip_packet_info ip_info, int is_tcp, const eemo_dns_packet* pkt)
{
	int	i		= 0;
	int	ip_match	= 0;

	/* Check time */
	check_timers(ip_info.ts.tv_sec);

	/* Skip responses immediately */
	if (pkt->qr_flag) return ERV_SKIPPED;

	/* Check if this is a query against the DNS server we are monitoring */
	for (i = 0; i < server_ips_ct; i++)
	{
		if (strcmp(ip_info.ip_dst, server_ips[i]) == 0)
		{
			ip_match = 1;
			break;
		}
	}

	if (!ip_match) return ERV_SKIPPED;

	/* We need to count this query */
	if (ip_info.ip_type == IP_TYPE_V4)
	{
		ip4_reg_ht*	found	= NULL;

		HASH_FIND(hh, v4_hour_ht, &ip_info.src_addr, sizeof(struct in_addr), found);

		if (found == NULL)
		{
			found = (ip4_reg_ht*) malloc(sizeof(ip4_reg_ht));

			memset(found, 0, sizeof(ip4_reg_ht));
			
			memcpy(&found->addr, &ip_info.src_addr, sizeof(struct in_addr));

			HASH_ADD(hh, v4_hour_ht, addr, sizeof(struct in_addr), found);
		}

		found->seen_count++;

		found = NULL;

		HASH_FIND(hh, v4_day_ht, &ip_info.src_addr, sizeof(struct in_addr), found);

		if (found == NULL)
		{
			found = (ip4_reg_ht*) malloc(sizeof(ip4_reg_ht));

			memset(found, 0, sizeof(ip4_reg_ht));
			
			memcpy(&found->addr, &ip_info.src_addr, sizeof(struct in_addr));

			HASH_ADD(hh, v4_day_ht, addr, sizeof(struct in_addr), found);
		}

		found->seen_count++;

		found = NULL;

		HASH_FIND(hh, v4_week_ht, &ip_info.src_addr, sizeof(struct in_addr), found);

		if (found == NULL)
		{
			found = (ip4_reg_ht*) malloc(sizeof(ip4_reg_ht));

			memset(found, 0, sizeof(ip4_reg_ht));
			
			memcpy(&found->addr, &ip_info.src_addr, sizeof(struct in_addr));

			HASH_ADD(hh, v4_week_ht, addr, sizeof(struct in_addr), found);
		}

		found->seen_count++;
	}
	else if (ip_info.ip_type == IP_TYPE_V6)
	{
		ip6_reg_ht*	found	= NULL;

		HASH_FIND(hh, v6_hour_ht, &ip_info.src_addr, sizeof(struct in6_addr), found);

		if (found == NULL)
		{
			found = (ip6_reg_ht*) malloc(sizeof(ip6_reg_ht));

			memset(found, 0, sizeof(ip6_reg_ht));
			
			memcpy(&found->addr, &ip_info.src_addr, sizeof(struct in6_addr));

			HASH_ADD(hh, v6_hour_ht, addr, sizeof(struct in6_addr), found);
		}

		found->seen_count++;

		found = NULL;

		HASH_FIND(hh, v6_day_ht, &ip_info.src_addr, sizeof(struct in6_addr), found);

		if (found == NULL)
		{
			found = (ip6_reg_ht*) malloc(sizeof(ip6_reg_ht));

			memset(found, 0, sizeof(ip6_reg_ht));
			
			memcpy(&found->addr, &ip_info.src_addr, sizeof(struct in6_addr));

			HASH_ADD(hh, v6_day_ht, addr, sizeof(struct in6_addr), found);
		}

		found->seen_count++;

		found = NULL;

		HASH_FIND(hh, v6_week_ht, &ip_info.src_addr, sizeof(struct in6_addr), found);

		if (found == NULL)
		{
			found = (ip6_reg_ht*) malloc(sizeof(ip6_reg_ht));

			memset(found, 0, sizeof(ip6_reg_ht));
			
			memcpy(&found->addr, &ip_info.src_addr, sizeof(struct in6_addr));

			HASH_ADD(hh, v6_week_ht, addr, sizeof(struct in6_addr), found);
		}

		found->seen_count++;
	}

	return ERV_HANDLED;
}

/* Plugin initialisation */
eemo_rv eemo_dnsuniqip_init(eemo_export_fn_table_ptr eemo_fn, const char* conf_base_path)
{
	/* Initialise logging for the plugin */
	eemo_init_plugin_log(eemo_fn->log);

	INFO_MSG("Initialising dnsuniqip plugin");

	if (((eemo_fn->conf_get_string)(conf_base_path, "hour_file", &dnsuniq_hour_file, NULL) != ERV_OK) || (dnsuniq_hour_file == NULL))
	{
		ERROR_MSG("Could not get output file for hourly data from the configuration");

		return ERV_CONFIG_ERROR;
	}

	if (((eemo_fn->conf_get_string)(conf_base_path, "day_file", &dnsuniq_day_file, NULL) != ERV_OK) || (dnsuniq_day_file == NULL))
	{
		ERROR_MSG("Could not get output file for daily data from the configuration");

		return ERV_CONFIG_ERROR;
	}

	if (((eemo_fn->conf_get_string)(conf_base_path, "week_file", &dnsuniq_week_file, NULL) != ERV_OK) || (dnsuniq_week_file == NULL))
	{
		ERROR_MSG("Could not get output file for weekly data from the configuration");

		return ERV_CONFIG_ERROR;
	}

	if (((eemo_fn->conf_get_string_array)(conf_base_path, "server_ips", &server_ips, &server_ips_ct) != ERV_OK) || (server_ips_ct <= 0) || (server_ips == NULL))
	{
		ERROR_MSG("Could not retrieve the DNS server IPs to monitor from the configuration");

		return ERV_CONFIG_ERROR;
	}

	/* Register DNS handler */
	if ((eemo_fn->reg_dns_handler)(&eemo_dnsuniqip_dns_handler, 0, &dns_handler_handle) != ERV_OK)
	{
		ERROR_MSG("Failed to register dnsuniqip DNS handler");

		(eemo_fn->unreg_dns_handler)(dns_handler_handle);

		return ERV_GENERAL_ERROR;
	}

	INFO_MSG("Demo plugin initialisation complete");

	return ERV_OK;
}

/* Plugin uninitialisation */
eemo_rv eemo_dnsuniqip_uninit(eemo_export_fn_table_ptr eemo_fn)
{
	writer_params*	wparams	= NULL;
	struct tm	utc_time;

	gmtime_r((const time_t*) &dnsuniq_today.prev_ts, &utc_time);

	INFO_MSG("Uninitialising dnsuniqip plugin");

	/* Unregister DNS handler */
	if ((eemo_fn->unreg_dns_handler)(dns_handler_handle) != ERV_OK)
	{
		ERROR_MSG("Failed to unregister dnsuniqip DNS handler");
	}

	/* Write final set of statistics */
	wparams = (writer_params*) malloc(sizeof(writer_params));

	snprintf(wparams->ts_str, 256, "%04d-%02d-%02d %02d:%02d:%02d", utc_time.tm_year+1900, utc_time.tm_mon+1, utc_time.tm_mday, utc_time.tm_hour, utc_time.tm_min, utc_time.tm_sec);

	wparams->filename 	= dnsuniq_hour_file;
	wparams->ts		= dnsuniq_today.prev_ts;
	wparams->v4_ht		= v4_hour_ht;
	wparams->v6_ht		= v6_hour_ht;
	wparams->type_str	= type_hourly;

	eemo_dnsuniqip_writer(wparams);

	wparams = (writer_params*) malloc(sizeof(writer_params));

	snprintf(wparams->ts_str, 256, "%04d-%02d-%02d", utc_time.tm_year+1900, utc_time.tm_mon+1, utc_time.tm_mday);

	wparams->filename 	= dnsuniq_day_file;
	wparams->ts		= dnsuniq_today.prev_ts;
	wparams->v4_ht		= v4_day_ht;
	wparams->v6_ht		= v6_day_ht;
	wparams->type_str	= type_daily;

	eemo_dnsuniqip_writer(wparams);

	wparams = (writer_params*) malloc(sizeof(writer_params));

	snprintf(wparams->ts_str, 256, "%04d-%02d-%02d", utc_time.tm_year+1900, utc_time.tm_mon+1, utc_time.tm_mday);

	wparams->filename 	= dnsuniq_week_file;
	wparams->ts		= dnsuniq_today.prev_ts;
	wparams->v4_ht		= v4_week_ht;
	wparams->v6_ht		= v6_week_ht;
	wparams->type_str	= type_weekly;

	eemo_dnsuniqip_writer(wparams);

	free(dnsuniq_hour_file);
	free(dnsuniq_day_file);
	free(dnsuniq_week_file);

	(eemo_fn->conf_free_string_array)(server_ips, server_ips_ct);

	INFO_MSG("Finished uninitialising dnsuniqip plugin");

	return ERV_OK;
}

/* Retrieve plugin description */
const char* eemo_dnsuniqip_getdescription(void)
{
	return plugin_description;
}

/* Retrieve plugin status */
eemo_rv eemo_dnsuniqip_status(void)
{
	return ERV_OK;
}

/* Plugin function table */
static eemo_plugin_fn_table dnsuniqip_fn_table =
{
	EEMO_PLUGIN_FN_VERSION,
	&eemo_dnsuniqip_init,
	&eemo_dnsuniqip_uninit,
	&eemo_dnsuniqip_getdescription,
	&eemo_dnsuniqip_status
};

/* Entry point for retrieving plugin function table */
eemo_rv eemo_plugin_get_fn_table(eemo_plugin_fn_table_ptrptr fn_table)
{
	if (fn_table == NULL)
	{
		return ERV_PARAM_INVALID;
	}

	*fn_table = &dnsuniqip_fn_table;

	return ERV_OK;
}

