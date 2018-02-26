/*
 * Copyright (c) 2010-2018 SURFnet bv
 * Copyright (c) 2015-2018 Roland van Rijswijk-Deij
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
 * EDNS0 client subnet monitoring plugin
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

const static char* plugin_description = "EEMO EDNS0 client subnet monitoring plugin " PACKAGE_VERSION;

/* DNS handler handles */
static unsigned long	dns_handler_handle	= 0;

/* Output file */
static char*		edns0_mon_file_base	= NULL;
static FILE*		edns0_mon_file		= NULL;
static char*		on_day_changed_cmd	= NULL;
static char		day_file_name[1024]	= { 0 };

/* Time keeping */
static struct
{
	int	day;
	int	month;
	int	year;
	time_t	next_epoch_day_utc;
}
ecsmon_today = { 0, 0, 0, 0 };

/* Thread that processes files on day change */
void* eemo_ecsmonitor_int_on_day_changed_threadproc(void* param)
{
	assert(param != NULL);

	char*	file_to_process	= (char*) param;
	int	repeat_on_fail	= 100;			/* Try 100 times if command execution fails */
	int	failed		= 1;
	char	exec_cmd[4096]	= { 0 };
	int	backoff_wait	= 1;

	snprintf(exec_cmd, 4096, "out_file=\"%s\" ; %s", file_to_process, on_day_changed_cmd);

	INFO_MSG("Running %s...", exec_cmd);

	while (repeat_on_fail > 0)
	{
		int exitstatus = system(exec_cmd);

		if (WIFEXITED(exitstatus))
		{
			exitstatus = WEXITSTATUS(exitstatus);

			if (exitstatus != 0)
			{
				ERROR_MSG("Execution of %s failed with exit status %d, trying again in %d seconds", exec_cmd, exitstatus, backoff_wait);
			}
			else
			{
				/* Success! */
				failed = 0;
				break;
			}
		}
		else
		{
			ERROR_MSG("Execution of %s was interrupted abnormally, trying again in %d seconds", exec_cmd, backoff_wait);
		}

		sleep(backoff_wait);
		if (backoff_wait < 512) backoff_wait *= 2;
		repeat_on_fail--;
	}

	if (failed)
	{
		ERROR_MSG("Execution of %s failed, giving up", exec_cmd);
	}
	else
	{
		INFO_MSG("Execution of %s succeeded", exec_cmd);
	}

	free(file_to_process);

	pthread_detach(pthread_self());

	return NULL;
}

/* Open file for the current day */
static int eemo_ecsmonitor_int_open_day_file(time_t ts)
{
	struct tm	utc_time;
	char*		tzone		= NULL;

	if (edns0_mon_file != NULL)
	{
		char*	file_to_process	= NULL;

		/* The file is already open, check if we have passed to the next day */
		if (ts < ecsmon_today.next_epoch_day_utc)
		{
			return 0;
		}

		/* We have progressed to the next day */
		fclose(edns0_mon_file);
		edns0_mon_file = NULL;

		/* Start an "on day changed" thread */
		if (on_day_changed_cmd != NULL)
		{
			pthread_t	on_day_changed_tid;

			file_to_process = strdup(day_file_name);

			if (pthread_create(&on_day_changed_tid, NULL, eemo_ecsmonitor_int_on_day_changed_threadproc, (void*) file_to_process) != 0)
			{
				ERROR_MSG("Failed to launch thread in which to execute %s", on_day_changed_cmd);

				free(file_to_process);
			}
		}
	}

	/* Determine the current day and the next epoch day */
	gmtime_r((const time_t*) &ts, &utc_time);

	ecsmon_today.day	= utc_time.tm_mday;
	ecsmon_today.month	= utc_time.tm_mon + 1;
	ecsmon_today.year	= utc_time.tm_year + 1900;

	/* Now compute the next UTC day epoch time */
	utc_time.tm_hour = utc_time.tm_min = utc_time.tm_sec = 0;

	tzone = getenv("TZ");
	
	if (tzone != NULL) tzone = strdup(tzone);

	setenv("TZ", "", 1);

	tzset();

	ecsmon_today.next_epoch_day_utc = mktime(&utc_time);

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

	/* Who cares about leap seconds :-) */
	ecsmon_today.next_epoch_day_utc += 86400;

	DEBUG_MSG("Next epoch day at %zd", ecsmon_today.next_epoch_day_utc);

	/* Open the new output CSV file */
	snprintf(day_file_name, 1024, "%s.%04d%02d%02d", edns0_mon_file_base, ecsmon_today.year, ecsmon_today.month, ecsmon_today.day);

	edns0_mon_file = fopen(day_file_name, "a");

	if (edns0_mon_file == NULL)
	{
		ERROR_MSG("Failed to open %s for writing", day_file_name);

		return -1;
	}

	/* Write CSV header */
	if (ftell(edns0_mon_file) == 0)
	{
		fprintf(edns0_mon_file, "timestamp;qtype;q_src;ecs_ip;ecs_scope;q_as;q_geoip;ecs_ip_as;ecs_ip_prefix;ecs_ip_geoip;qname\n");
	}

	INFO_MSG("Started new file on %04d-%02d-%02d (%s)", ecsmon_today.year, ecsmon_today.month, ecsmon_today.day, day_file_name);

	return 0;
}

/* DNS handler */
eemo_rv eemo_ecsmonitor_dns_handler(eemo_ip_packet_info ip_info, int is_tcp, const eemo_dns_packet* pkt)
{
	/* Skip responses immediately */
	if (pkt->qr_flag) return ERV_SKIPPED;

	/* Check if this query has EDNS0 client subnet information */
	if (pkt->has_edns0 && pkt->has_edns0_client_subnet && (pkt->questions != NULL))
	{
		if (eemo_ecsmonitor_int_open_day_file(ip_info.ts.tv_sec) != 0)
		{
			ERROR_MSG("Failed to open (new) output CSV");

			return ERV_SKIPPED;
		}

		fprintf(edns0_mon_file, "%u;%u;%s;%s;%u;%s;%s;%s;%s",
			(unsigned int) ip_info.ts.tv_sec,
			pkt->questions->qtype,
			ip_info.ip_src,
			pkt->edns0_client_subnet_ip,
			pkt->edns0_client_subnet_src_scope,
			ip_info.src_as_short,
			ip_info.src_geo_ip,
			pkt->edns0_client_subnet_as_short,
			pkt->edns0_client_subnet_geo_ip);

		if (pkt->questions->qname != NULL)
		{
			fprintf(edns0_mon_file, ";%s\n", pkt->questions->qname);
		}
		else
		{
			fprintf(edns0_mon_file, ";(NULL)\n");
		}

		return ERV_HANDLED;
	}
	else
	{
		return ERV_SKIPPED;
	}
}

/* Plugin initialisation */
eemo_rv eemo_ecsmonitor_init(eemo_export_fn_table_ptr eemo_fn, const char* conf_base_path)
{
	/* Initialise logging for the plugin */
	eemo_init_plugin_log(eemo_fn->log);

	INFO_MSG("Initialising ecsmonitor plugin");

	if (((eemo_fn->conf_get_string)(conf_base_path, "out_file", &edns0_mon_file_base, NULL) != ERV_OK) || (edns0_mon_file_base == NULL))
	{
		ERROR_MSG("Could not get output file for EDNS0 client subnet monitoring plugin from the configuration");

		return ERV_CONFIG_ERROR;
	}

	if ((eemo_fn->conf_get_string)(conf_base_path, "on_day_changed_cmd", &on_day_changed_cmd, NULL) != ERV_OK)
	{
		ERROR_MSG("Failed to get the command to execute on a day change from the configuration");

		return ERV_CONFIG_ERROR;
	}

	/* Register DNS handler */
	if ((eemo_fn->reg_dns_handler)(&eemo_ecsmonitor_dns_handler, PARSE_QUERY, &dns_handler_handle) != ERV_OK)
	{
		ERROR_MSG("Failed to register ecsmonitor DNS handler");

		(eemo_fn->unreg_dns_handler)(dns_handler_handle);

		return ERV_GENERAL_ERROR;
	}

	INFO_MSG("Demo plugin initialisation complete");

	return ERV_OK;
}

/* Plugin uninitialisation */
eemo_rv eemo_ecsmonitor_uninit(eemo_export_fn_table_ptr eemo_fn)
{
	INFO_MSG("Uninitialising ecsmonitor plugin");

	/* Unregister DNS handler */
	if ((eemo_fn->unreg_dns_handler)(dns_handler_handle) != ERV_OK)
	{
		ERROR_MSG("Failed to unregister ecsmonitor DNS handler");
	}

	if (edns0_mon_file != NULL)
	{
		fclose(edns0_mon_file);
	}

	free(edns0_mon_file_base);
	free(on_day_changed_cmd);

	INFO_MSG("Finished uninitialising ecsmonitor plugin");

	return ERV_OK;
}

/* Retrieve plugin description */
const char* eemo_ecsmonitor_getdescription(void)
{
	return plugin_description;
}

/* Retrieve plugin status */
eemo_rv eemo_ecsmonitor_status(void)
{
	return ERV_OK;
}

/* Plugin function table */
static eemo_plugin_fn_table ecsmonitor_fn_table =
{
	EEMO_PLUGIN_FN_VERSION,
	&eemo_ecsmonitor_init,
	&eemo_ecsmonitor_uninit,
	&eemo_ecsmonitor_getdescription,
	&eemo_ecsmonitor_status
};

/* Entry point for retrieving plugin function table */
eemo_rv eemo_plugin_get_fn_table(eemo_plugin_fn_table_ptrptr fn_table)
{
	if (fn_table == NULL)
	{
		return ERV_PARAM_INVALID;
	}

	*fn_table = &ecsmonitor_fn_table;

	return ERV_OK;
}

