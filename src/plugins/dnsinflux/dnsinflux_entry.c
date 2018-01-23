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
 * InfluxDB DNS statistics plugin library entry functions
 */

#include "config.h"
#include <stdlib.h>
#include "eemo.h"
#include "eemo_api.h"
#include "eemo_plugin_log.h"
#include "dnsinflux_itemmgr.h"
#include "dnsinflux_collector.h"

const static char* plugin_description = "EEMO InfluxDB DNS statistics plugin " PACKAGE_VERSION;

/* Handler handle */
static unsigned long stats_dns_handler_handle = 0;

/* Plugin initialisation */
eemo_rv eemo_dnsinflux_init(eemo_export_fn_table_ptr eemo_fn, const char* conf_base_path)
{
	char**	ips		= NULL;
	int	ipcount		= 0;
	char*	hostname	= NULL;
	char*	influxfile	= NULL;
	char*	influxcmd	= NULL;
	char*	statsfile	= NULL;
	int	stats_frequency	= 300;
	int	i		= 0;
	eemo_rv	rv		= ERV_OK;

	/* Initialise logging for the plugin */
	eemo_init_plugin_log(eemo_fn->log);

	/* Retrieve configuration */
	if (((eemo_fn->conf_get_string)(conf_base_path, "stats_file", &statsfile, NULL) != ERV_OK) ||
	    (statsfile == NULL))
	{
		ERROR_MSG("Failed to get stats_file configuration item");

		return ERV_CONFIG_ERROR;
	}

	if (((eemo_fn->conf_get_string)(conf_base_path, "hostname", &hostname, NULL) != ERV_OK) ||
	    (hostname == NULL))
	{
		ERROR_MSG("Failed to get hostname configuration item");

		return ERV_CONFIG_ERROR;
	}

	if (((eemo_fn->conf_get_string)(conf_base_path, "influx_file", &influxfile, NULL) != ERV_OK) ||
	    (influxfile == NULL))
	{
		ERROR_MSG("Failed to get influx_file configuration item");

		return ERV_CONFIG_ERROR;
	}

	if (((eemo_fn->conf_get_string)(conf_base_path, "influx_cmd", &influxcmd, NULL) != ERV_OK) ||
	    (influxcmd == NULL))
	{
		ERROR_MSG("Failed to get influx_cmd configuration item");

		return ERV_CONFIG_ERROR;
	}

	if (((eemo_fn->conf_get_string_array)(conf_base_path, "listen_ips", &ips, &ipcount) != ERV_OK) ||
	    (ipcount <= 0) || (ipcount % 2 != 0))
	{
		ERROR_MSG("Failed to get listen_ips configuration item");

		return ERV_CONFIG_ERROR;
	}

	/* Register CIDR blocks */
	for (i = 0; i < ipcount; i += 2)
	{
		if ((eemo_fn->cm_add_block)(ips[i], ips[i+1]) != ERV_OK)
		{
			ERROR_MSG("Failed to add listening subnet %s (%s)", ips[i], ips[i+1]);
		}
		else
		{
			INFO_MSG("Added listening subnet %s (%s)", ips[i], ips[i+1]);
		}
	}

	if (((eemo_fn->conf_get_int)(conf_base_path, "stats_frequency", &stats_frequency, stats_frequency) != ERV_OK) ||
	    (stats_frequency <= 0))
	{
		ERROR_MSG("Failed to get stats_frequency configuration item");

		return ERV_CONFIG_ERROR;
	}

	/* Initialise the item manager module */
	if (dnsinflux_itemmgr_init(influxfile, influxcmd, statsfile, stats_frequency, hostname) != ERV_OK)
	{
		ERROR_MSG("Failed to initialise item manager module");

		return ERV_GENERAL_ERROR;
	}

	/* Initialise the collector module */
	if (dnsinflux_collector_init(stats_frequency, eemo_fn) != ERV_OK)
	{
		ERROR_MSG("Failed to initialise statistics collector module");

		return ERV_GENERAL_ERROR;
	}

	/* Clean up */
	(eemo_fn->conf_free_string_array)(ips, ipcount);
	free(statsfile);
	free(hostname);
	free(influxfile);
	free(influxcmd);

	/* Register DNS query handler */
	rv = (eemo_fn->reg_dns_handler)(&dnsinflux_handleqr, PARSE_QUERY | PARSE_RESPONSE, &stats_dns_handler_handle);

	if (rv != ERV_OK)
	{
		ERROR_MSG("Failed to register DNS query handler");

		return rv;
	}

	return ERV_OK;
}

/* Plugin uninitialisation */
eemo_rv eemo_dnsinflux_uninit(eemo_export_fn_table_ptr eemo_fn)
{
	/* Unregister DNS query handler */
	if ((eemo_fn->unreg_dns_handler)(stats_dns_handler_handle) != ERV_OK)
	{
		ERROR_MSG("Failed to unregister DNS query handler");
	}

	/* Clean up modules */
	dnsinflux_collector_finalise();
	dnsinflux_itemmgr_finalise();

	return ERV_OK;
}

/* Retrieve plugin description */
const char* eemo_dnsinflux_getdescription(void)
{
	return plugin_description;
}

/* Retrieve plugin status */
eemo_rv eemo_dnsinflux_status(void)
{
	return ERV_OK;
}

/* Plugin function table */
static eemo_plugin_fn_table dnsinflux_fn_table =
{
	EEMO_PLUGIN_FN_VERSION,
	&eemo_dnsinflux_init,
	&eemo_dnsinflux_uninit,
	&eemo_dnsinflux_getdescription,
	&eemo_dnsinflux_status
};

/* Entry point for retrieving plugin function table */
eemo_rv eemo_plugin_get_fn_table(eemo_plugin_fn_table_ptrptr fn_table)
{
	if (fn_table == NULL)
	{
		return ERV_PARAM_INVALID;
	}

	*fn_table = &dnsinflux_fn_table;

	return ERV_OK;
}

