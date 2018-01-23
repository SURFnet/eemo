/*
 * Copyright (c) 2010-2018 SURFnet bv
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
 * InfluxDB DNS statistics item manager
 */

#include "config.h"
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <assert.h>
#include <sys/wait.h>
#include <unistd.h>
#include "eemo.h"
#include "eemo_api.h"
#include "eemo_plugin_log.h"
#include "dnsinflux_itemmgr.h"
#include "utlist.h"
#include "uthash.h"

/* Item types */
typedef struct _dnsinflux_item
{
	char*			name;
	unsigned long long	value;
	int			is_absolute;
	int			reset_on_flush;
	UT_hash_handle		hh;
}
dnsinflux_item;

typedef struct _dnsinflux_list
{
	char*			name;
	unsigned long long	value;
	int			is_absolute;
	struct _dnsinflux_list*	next;
}
dnsinflux_list;

/* Statistics repositories */
static dnsinflux_item*	di_local_stats	= NULL;
static dnsinflux_item*	di_remote_stats	= NULL;

/* Configuration */
static char*	di_influx_file		= NULL;
static char*	di_influx_cmd		= NULL;
static char*	di_stats_file		= NULL;
static char*	di_hostname		= NULL;
static int	di_stats_interval	= 0;

/* Initialise the item manager */
eemo_rv dnsinflux_itemmgr_init(const char* influx_file, const char* influx_cmd, const char* stats_file, const int stats_interval, const char* hostname)
{
	assert(influx_file != NULL);
	assert(influx_cmd != NULL);
	assert(stats_file != NULL);
	assert(stats_interval > 0);
	assert(hostname != NULL);
	assert(di_local_stats == NULL);
	assert(di_remote_stats == NULL);

	di_influx_file		= strdup(influx_file);
	di_influx_cmd		= strdup(influx_cmd);
	di_stats_file		= strdup(stats_file);
	di_stats_interval	= stats_interval;
	di_hostname		= strdup(hostname);

	INFO_MSG("Initialised DNS InfluxDB plugin item manager");

	return ERV_OK;
}

/* Uninitialise the item manager */
eemo_rv dnsinflux_itemmgr_finalise(void)
{
	dnsinflux_item*	item_it		= NULL;
	dnsinflux_item*	item_tmp	= NULL;
	int		local_count	= 0;
	int		remote_count	= 0;

	/* Clean up items */
	HASH_ITER(hh, di_local_stats, item_it, item_tmp)
	{
		HASH_DEL(di_local_stats, item_it);
		free(item_it->name);
		free(item_it);

		local_count++;
	}

	HASH_ITER(hh, di_remote_stats, item_it, item_tmp)
	{
		HASH_DEL(di_remote_stats, item_it);
		free(item_it->name);
		free(item_it);

		remote_count++;
	}

	di_local_stats = NULL;
	di_remote_stats = NULL;

	free(di_influx_file);
	free(di_influx_cmd);
	free(di_stats_file);
	free(di_hostname);

	di_influx_file = di_influx_cmd = di_stats_file = di_hostname = NULL;

	INFO_MSG("Finalised DNS InfluxDB plugin item manager, cleaned up %d local and %d remote items", local_count, remote_count);

	return ERV_OK;
}

/* Add an item */
static eemo_rv dnsinflux_int_add_item(dnsinflux_item** ht, const char* item_name, const int is_absolute, const int reset_on_flush)
{
	assert(item_name != NULL);
	assert(ht != NULL);

	dnsinflux_item*	new_item	= NULL;

	HASH_FIND_STR(*ht, item_name, new_item);

	if (new_item != NULL)
	{
		ERROR_MSG("Attempt to add item '%s' that already exists", item_name);

		return ERV_GENERAL_ERROR;
	}
	
	new_item = (dnsinflux_item*) malloc(sizeof(dnsinflux_item));

	memset(new_item, 0, sizeof(dnsinflux_item));

	new_item->name			= strdup(item_name);
	new_item->is_absolute		= is_absolute;
	new_item->reset_on_flush	= reset_on_flush;

	HASH_ADD_KEYPTR(hh, *ht, new_item->name, strlen(new_item->name), new_item);

	DEBUG_MSG("Added item '%s'", item_name);

	return ERV_OK;
}

/* Add a new local statistics item */
eemo_rv dnsinflux_add_localstat(const char* item_name, const int is_absolute, const int reset_on_flush)
{
	return dnsinflux_int_add_item(&di_local_stats, item_name, is_absolute, reset_on_flush);
}

/* Add a new remote statistics item */
eemo_rv dnsinflux_add_remotestat(const char* item_name, const int is_absolute, const int reset_on_flush)
{
	return dnsinflux_int_add_item(&di_remote_stats, item_name, is_absolute, reset_on_flush);
}

/* Copy item states into a list and reset the reset-on-flush items */
static dnsinflux_list* dnsinflux_int_copystates(dnsinflux_item* ht)
{

	dnsinflux_list*	itemlist	= NULL;
	dnsinflux_item*	item_it		= NULL;
	dnsinflux_item*	item_tmp	= NULL;

	HASH_ITER(hh, ht, item_it, item_tmp)
	{
		dnsinflux_list*	new_listent	= (dnsinflux_list*) malloc(sizeof(dnsinflux_list));

		memset(new_listent, 0, sizeof(dnsinflux_list));

		new_listent->name		= strdup(item_it->name);
		new_listent->value		= item_it->value;
		new_listent->is_absolute	= item_it->is_absolute;

		/* Reset if necessary */
		if (item_it->reset_on_flush) item_it->value = 0;

		LL_APPEND(itemlist, new_listent);
	}

	return itemlist;
}

typedef struct
{
	time_t		ts;
	dnsinflux_list*	items;
}
dnsinflux_writer_threadparams;

/* Local statistics output thread */
static void* dnsinflux_int_write_localstats_threadproc(void* params)
{
	assert(params != NULL);

	dnsinflux_writer_threadparams*	tp		= (dnsinflux_writer_threadparams*) params;
	struct tm			ts_tm;
	FILE*				out_fd		= fopen(di_stats_file, "w");
	dnsinflux_list*			list_it		= NULL;
	dnsinflux_list*			list_tmp	= NULL;

	DEBUG_MSG("Entering local statistics writer thread");

	/* Ensure the thread resources get clean up on exit */
	pthread_detach(pthread_self());

	if (out_fd == NULL)
	{
		ERROR_MSG("Failed to open %s for writing", di_stats_file);

		LL_FOREACH_SAFE(tp->items, list_it, list_tmp)
		{
			free(list_it->name);
			free(list_it);
		}

		free(tp);

		return NULL;
	}

	gmtime_r(&tp->ts, &ts_tm);

	fprintf(out_fd, "%02d-%02d-%04d %02d:%02d:%02d\n\n", ts_tm.tm_mday, ts_tm.tm_mon+1, ts_tm.tm_year+1900, ts_tm.tm_hour, ts_tm.tm_min, ts_tm.tm_sec);

	LL_FOREACH_SAFE(tp->items, list_it, list_tmp)
	{
		if (list_it->is_absolute)
		{
			fprintf(out_fd, "%s: %llu\n", list_it->name, list_it->value);
			DEBUG_MSG("%s: %llu", list_it->name, list_it->value);
		}
		else
		{
			fprintf(out_fd, "%s: %0.2f\n", list_it->name, (double) list_it->value/(double) di_stats_interval);
			DEBUG_MSG("%s: %0.2f", list_it->name, (double) list_it->value/(double) di_stats_interval);
		}

		free(list_it->name);
		free(list_it);
	}

	fclose(out_fd);

	free(tp);

	DEBUG_MSG("Leaving local statistics writer thread");

	return NULL;
}

/* Flush local stats */
eemo_rv dnsinflux_flush_localstats(const time_t ts)
{
	dnsinflux_writer_threadparams*	tp	= (dnsinflux_writer_threadparams*) malloc(sizeof(dnsinflux_writer_threadparams));
	pthread_t			tid;

	tp->ts = ts;
	tp->items = dnsinflux_int_copystates(di_local_stats);

	if (pthread_create(&tid, NULL, dnsinflux_int_write_localstats_threadproc, tp) != 0)
	{
		ERROR_MSG("Failed to start writer thread for local statistics");

		return ERV_GENERAL_ERROR;
	}

	return ERV_OK;
}

/* Remote statistics output thread */
static void* dnsinflux_int_write_remotestats_threadproc(void* params)
{
	assert(params != NULL);

	dnsinflux_writer_threadparams*	tp		= (dnsinflux_writer_threadparams*) params;
	FILE*				out_fd		= fopen(di_influx_file, "w");
	dnsinflux_list*			list_it		= NULL;
	dnsinflux_list*			list_tmp	= NULL;
	int				exit_status	= 0;
	unsigned long long		nano_epoch	= (tp->ts) * 1000 * 1000;

	DEBUG_MSG("Entering remote statistics writer thread");

	/* Ensure the thread resources get cleaned up on exit */
	pthread_detach(pthread_self());

	if (out_fd == NULL)
	{
		ERROR_MSG("Failed to open %s for writing", di_influx_file);

		LL_FOREACH_SAFE(tp->items, list_it, list_tmp)
		{
			free(list_it->name);
			free(list_it);
		}

		free(tp);

		return NULL;
	}

	LL_FOREACH_SAFE(tp->items, list_it, list_tmp)
	{
		if (list_it->is_absolute)
		{
			fprintf(out_fd, "%s,host=%s value=%llu %llu\n", list_it->name, di_hostname, list_it->value, nano_epoch);
		}
		else
		{
			fprintf(out_fd, "%s,host=%s value=%0.2f %llu\n", list_it->name, di_hostname, (double) list_it->value/(double) di_stats_interval, nano_epoch);
		}

		free(list_it->name);
		free(list_it);
	}

	fclose(out_fd);

	/* Now attempt to execute the specified shell command */
	exit_status = system(di_influx_cmd);

	if (WIFEXITED(exit_status))
	{
		exit_status = WEXITSTATUS(exit_status);

		if (exit_status != 0)
		{
			ERROR_MSG("Execution of %s terminated with non-zero exit status", di_influx_cmd);
		}
	}
	else
	{
		ERROR_MSG("Execution of %s terminated abnormally", di_influx_cmd);
	}

	free(tp);

	DEBUG_MSG("Leaving remote statistics writer thread");

	return NULL;
}

/* Flush remote stats */
eemo_rv dnsinflux_flush_remotestats(const time_t ts)
{
	dnsinflux_writer_threadparams*	tp	= (dnsinflux_writer_threadparams*) malloc(sizeof(dnsinflux_writer_threadparams));
	pthread_t			tid;

	tp->ts = ts;
	tp->items = dnsinflux_int_copystates(di_remote_stats);

	if (pthread_create(&tid, NULL, dnsinflux_int_write_remotestats_threadproc, tp) != 0)
	{
		ERROR_MSG("Failed to start writer thread for remote statistics");

		return ERV_GENERAL_ERROR;
	}

	return ERV_OK;
}

/* Increment value of statistic in a hash table */
static void dnsinflux_int_addto_stat(dnsinflux_item* ht, const char* item_name, const unsigned long long to_add)
{
	assert(item_name != NULL);

	dnsinflux_item*	item	= NULL;

	HASH_FIND_STR(ht, item_name, item);

	if (item == NULL)
	{
		ERROR_MSG("Attempt to add to value of non-existent item '%s'", item_name);
	}
	else
	{
		item->value += to_add;
	}
}

/* Increment value of local stat */
void dnsinflux_inc_localstat(const char* item_name)
{
	dnsinflux_int_addto_stat(di_local_stats, item_name, 1);
}

/* Increment value of remote stat */
void dnsinflux_inc_remotestat(const char* item_name)
{
	dnsinflux_int_addto_stat(di_remote_stats, item_name, 1);
}

/* Add to value of local stat */
void dnsinflux_addto_localstat(const char* item_name, const unsigned long long to_add)
{
	dnsinflux_int_addto_stat(di_local_stats, item_name, to_add);
}

/* Add to value of remote stat */
void dnsinflux_addto_remotestat(const char* item_name, const unsigned long long to_add)
{
	dnsinflux_int_addto_stat(di_remote_stats, item_name, to_add);
}

/* Retrieve value of a statistic from a hash table */
static unsigned long long dnsinflux_int_getstat(dnsinflux_item* ht, const char* item_name)
{
	assert(item_name != NULL);

	dnsinflux_item*	item	= NULL;

	HASH_FIND_STR(ht, item_name, item);

	if (item == NULL)
	{
		ERROR_MSG("Attempt to retrieve value of non-existent item '%s'", item_name);

		return 0;
	}
	else
	{
		return item->value;
	}
}

/* Set the value of a statistic in a hash table */
static void dnsinflux_int_setstat(dnsinflux_item* ht, const char* item_name, const unsigned long long value)
{
	assert(item_name != NULL);

	dnsinflux_item*	item	= NULL;

	HASH_FIND_STR(ht, item_name, item);

	if (item == NULL)
	{
		ERROR_MSG("Attempt to set value of non-existent item '%s'", item_name);
	}
	else
	{
		item->value = value;
	}
}

/* Retrieve value of a local stat */
unsigned long long dnsinflux_get_localstat(const char* item_name)
{
	return dnsinflux_int_getstat(di_local_stats, item_name);
}

/* Set the value of a local stat */
void dnsinflux_set_localstat(const char* item_name, const unsigned long long value)
{
	dnsinflux_int_setstat(di_local_stats, item_name, value);
}

/* Retrieve the value of a remote stat */
unsigned long long dnsinflux_get_remotestat(const char* item_name)
{
	return dnsinflux_int_getstat(di_remote_stats, item_name);
}

/* Set the value of a remote stat */
void dnsinflux_set_remotestat(const char* item_name, const unsigned long long value)
{
	dnsinflux_int_setstat(di_remote_stats, item_name, value);
}

