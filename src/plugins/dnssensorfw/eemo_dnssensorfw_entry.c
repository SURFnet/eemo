/* $Id$ */

/*
 * Copyright (c) 2010-2012 SURFnet bv
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
 * DNS sensor forwarding module
 */

#include "config.h"
#include <stdlib.h>
#include "eemo.h"
#include "eemo_api.h"
#include "eemo_plugin_log.h"
#include "eemo_dnssensorfw_ipfw.h"
#include "ether_handler.h"
#include "ip_handler.h"
#include "icmp_handler.h"

const static char* plugin_description = "EEMO DNS IP/ICMP to sensor forwarding plugin " PACKAGE_VERSION;

/* Default reconnect time-out is 1800 seconds (half an hour) */
#define DEFAULT_INTERVAL 1800

/* Plugin initialisation */
eemo_rv eemo_dnssensorfw_init(eemo_export_fn_table_ptr eemo_fn, const char* conf_base_path)
{
	char*	sensor_hostname		= NULL;
	int	sensor_port		= 0;
	int	reconn_maxinterval	= 0;
	eemo_rv rv			= ERV_OK;

	/* Initialise logging for the plugin */
	eemo_init_plugin_log(eemo_fn->log);

	/* Retrieve configuration */
	if (((eemo_fn->conf_get_string)(conf_base_path, "sensor_hostname", &sensor_hostname, NULL) != ERV_OK) ||
	    (sensor_hostname == NULL))
	{
		return ERV_CONFIG_ERROR;
	}

	if (((eemo_fn->conf_get_int)(conf_base_path, "sensor_port", &sensor_port, 0) != ERV_OK) ||
	    (sensor_port == 0))
	{
		return ERV_CONFIG_ERROR;
	}

	if ((eemo_fn->conf_get_int)(conf_base_path, "sensor_reconnect_maxinterval", &reconn_maxinterval, DEFAULT_INTERVAL) != ERV_OK)
	{
		return ERV_CONFIG_ERROR;
	}

	/* Initialise the IP/ICMP to DNS sensor forwarder */
	eemo_dnssensorfw_ipfw_init(sensor_hostname, sensor_port, reconn_maxinterval);

	/* Register packet handler for IPv4 and IPv6 packets */
	rv = (eemo_fn->reg_ether_handler)(ETHER_IPV4, &eemo_dnssensorfw_ipfw_handle_pkt);

	if (rv != ERV_OK)
	{
		ERROR_MSG("Failed to register IPv4 packet handler");

		return rv;
	}

	rv = (eemo_fn->reg_ether_handler)(ETHER_IPV6, &eemo_dnssensorfw_ipfw_handle_pkt);

	if (rv != ERV_OK)
	{
		ERROR_MSG("Failed to register IPv6 packet handler");

		return rv;
	}

	return ERV_OK;
}

/* Plugin uninitialisation */
eemo_rv eemo_dnssensorfw_uninit(eemo_export_fn_table_ptr eemo_fn)
{
	eemo_rv rv = ERV_OK;

	/* Unregister packet handler for IPv4 and IPv6 packets */
	rv = (eemo_fn->unreg_ether_handler)(ETHER_IPV4);

	if (rv != ERV_OK)
	{
		ERROR_MSG("Failed to unregister IPv4 packet handler");
	}

	rv = (eemo_fn->unreg_ether_handler)(ETHER_IPV6);

	if (rv != ERV_OK)
	{
		ERROR_MSG("Failed to unregister IPv6 packet handler");
	}

	eemo_dnssensorfw_ipfw_uninit(eemo_fn->conf_free_string_array);

	return ERV_OK;
}

/* Retrieve plugin description */
const char* eemo_dnssensorfw_getdescription(void)
{
	return plugin_description;
}

/* Retrieve plugin status */
eemo_rv eemo_dnssensorfw_status(void)
{
	return ERV_OK;
}

/* Plugin function table */
static eemo_plugin_fn_table dnssensorfw_fn_table =
{
	EEMO_PLUGIN_FN_VERSION,
	&eemo_dnssensorfw_init,
	&eemo_dnssensorfw_uninit,
	&eemo_dnssensorfw_getdescription,
	&eemo_dnssensorfw_status
};

/* Entry point for retrieving plugin function table */
eemo_rv eemo_plugin_get_fn_table(eemo_plugin_fn_table_ptrptr fn_table)
{
	if (fn_table == NULL)
	{
		return ERV_PARAM_INVALID;
	}

	*fn_table = &dnssensorfw_fn_table;

	return ERV_OK;
}

