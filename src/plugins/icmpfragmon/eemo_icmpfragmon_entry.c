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
 * ICMP fragment reassembly time-out monitoring
 */

#include "config.h"
#include <stdlib.h>
#include "eemo.h"
#include "eemo_api.h"
#include "eemo_plugin_log.h"
#include "eemo_icmpfragmon_aggr.h"

const static char* plugin_description = "EEMO ICMP fragment reassembly time-out monitoring " PACKAGE_VERSION;

/* ICMP handler handles */
unsigned long icmp_ip4_handler_handle = 0;
unsigned long icmp_ip6_handler_handle = 0;

/* Plugin initialisation */
eemo_rv eemo_icmpfragmon_init(eemo_export_fn_table_ptr eemo_fn, const char* conf_base_path)
{
	char*	server		= NULL;
	int	port		= 0;
	int	max_packet_size	= 0;
	int	sensor_id	= 0;
	eemo_rv rv		= ERV_OK;

	/* Initialise logging for the plugin */
	eemo_init_plugin_log(eemo_fn->log);

	/* Retrieve configuration */
	if (((eemo_fn->conf_get_string)(conf_base_path, "server", &server, NULL) != ERV_OK) ||
	    (server == NULL))
	{
		return ERV_CONFIG_ERROR;
	}

	if (((eemo_fn->conf_get_int)(conf_base_path, "port", &port, 0) != ERV_OK) ||
	    (port == 0))
	{
		return ERV_CONFIG_ERROR;
	}

	if (((eemo_fn->conf_get_int)(conf_base_path, "max_packet_size", &max_packet_size, IFM_UDP_MAXSIZE) != ERV_OK) ||
	    (max_packet_size < 100))
	{
		if (max_packet_size < 100)
		{
			ERROR_MSG("Specified packet size (%d bytes) is too small, minimum packet size must be 100 bytes");
		}

		return ERV_CONFIG_ERROR;
	}

	if ((eemo_fn->conf_get_int)(conf_base_path, "sensor", &sensor_id, 0) != ERV_OK)
	{
		free(server);

		return ERV_CONFIG_ERROR;
	}

	/* Initialise the plugin */
	eemo_icmpfragmon_aggr_init(server, port, max_packet_size, sensor_id);

	/* Register ICMP handlers */
	rv = (eemo_fn->reg_icmp_handler)(ICMPv4_TYPE_TIME_EXCEEDED, ICMPv4_CODE_REASSEMBLY_FAIL, IP_TYPE_V4, &eemo_icmpfragmon_handle_icmp, &icmp_ip4_handler_handle);

	if (rv != ERV_OK)
	{
		ERROR_MSG("Failed to register ICMPv4 handler for fragment reassembly time-out");

		return rv;
	}

	rv = (eemo_fn->reg_icmp_handler)(ICMPv6_TYPE_TIME_EXCEEDED, ICMPv6_CODE_REASSEMBLY_FAIL, IP_TYPE_V6, &eemo_icmpfragmon_handle_icmp, &icmp_ip6_handler_handle);

	if (rv != ERV_OK)
	{
		ERROR_MSG("Failed to register ICMPv6 handler for fragment reassembly time-out");

		return rv;
	}

	return ERV_OK;
}

/* Plugin uninitialisation */
eemo_rv eemo_icmpfragmon_uninit(eemo_export_fn_table_ptr eemo_fn)
{
	/* Unregister ICMP handler */
	if (eemo_fn->unreg_icmp_handler(icmp_ip4_handler_handle) != ERV_OK)
	{
		ERROR_MSG("Failed to unregister ICMPv4 handler for fragment reassembly time-out");
	}

	if (eemo_fn->unreg_icmp_handler(icmp_ip6_handler_handle) != ERV_OK)
	{
		ERROR_MSG("Failed to unregister ICMPv6 handler for fragment reassembly time-out");
	}

	eemo_icmpfragmon_aggr_uninit(eemo_fn->conf_free_string_array);

	return ERV_OK;
}

/* Retrieve plugin description */
const char* eemo_icmpfragmon_getdescription(void)
{
	return plugin_description;
}

/* Retrieve plugin status */
eemo_rv eemo_icmpfragmon_status(void)
{
	return ERV_OK;
}

/* Plugin function table */
static eemo_plugin_fn_table icmpfragmon_fn_table =
{
	EEMO_PLUGIN_FN_VERSION,
	&eemo_icmpfragmon_init,
	&eemo_icmpfragmon_uninit,
	&eemo_icmpfragmon_getdescription,
	&eemo_icmpfragmon_status
};

/* Entry point for retrieving plugin function table */
eemo_rv eemo_plugin_get_fn_table(eemo_plugin_fn_table_ptrptr fn_table)
{
	if (fn_table == NULL)
	{
		return ERV_PARAM_INVALID;
	}

	*fn_table = &icmpfragmon_fn_table;

	return ERV_OK;
}

