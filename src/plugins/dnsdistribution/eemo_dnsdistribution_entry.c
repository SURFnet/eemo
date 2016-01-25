/*
 * Copyright (c) 2010-2016 SURFnet bv
 * Copyright (c) 2015-2016 Kaspar Hageman
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
 * DNS statistics plugin library entry functions
 */

#include "config.h"
#include <stdlib.h>
#include "eemo.h"
#include "eemo_api.h"
#include "eemo_plugin_log.h"
#include "eemo_dnsdistribution_stats.h"

const static char* plugin_description = "EEMO DNS distribution statistics (in progress) plugin " PACKAGE_VERSION;

/* Handler handle */
static unsigned long stats_dns_handler_handle = 0;

/* Plugin initialisation */
eemo_rv eemo_dnsdistribution_init(eemo_export_fn_table_ptr eemo_fn, const char* conf_base_path)
{
	char*	file_general			= NULL;
	char*	file_qname_popularity		= NULL;
	char*	file_ttl			= NULL;
	char*	file_sigs_per_resp		= NULL;
	char*	file_rcodes			= NULL;
	char** 	resolver_ips			= NULL;
	int 	resolver_ip_count		= 0;
	char**	ignore_ips			= NULL;
	int	ignore_ip_count			= 0;
	int	emit_interval			= 0;
	int	emit_qname_ctr			= 0;
	eemo_rv rv				= ERV_OK;

	/* Initialise logging for the plugin */
	eemo_init_plugin_log(eemo_fn->log);

	/* Retrieve configuration */
	if (((eemo_fn->conf_get_string)(conf_base_path, "stats_file_general", &file_general, NULL) != ERV_OK) ||
	    (file_general == NULL))
	{
		return ERV_CONFIG_ERROR;
	}

	if (((eemo_fn->conf_get_string)(conf_base_path, "stats_file_qname_popularity", &file_qname_popularity, NULL) != ERV_OK) ||
	    (file_qname_popularity == NULL))
	{
		return ERV_CONFIG_ERROR;
	}

	if (((eemo_fn->conf_get_string)(conf_base_path, "stats_file_ttl", &file_ttl, NULL) != ERV_OK) ||
            (file_ttl == NULL))
        {
                return ERV_CONFIG_ERROR;
        }

	if (((eemo_fn->conf_get_string)(conf_base_path, "stats_file_sigs_per_resp", &file_sigs_per_resp, NULL) != ERV_OK) ||
            (file_sigs_per_resp == NULL))
        {
                return ERV_CONFIG_ERROR;
        }

	if (((eemo_fn->conf_get_string)(conf_base_path, "stats_file_rcodes", &file_rcodes, NULL) != ERV_OK) ||
            (file_rcodes == NULL))
        {
                return ERV_CONFIG_ERROR;
        }

	if (((eemo_fn->conf_get_string_array)(conf_base_path, "resolver_ips", &resolver_ips, &resolver_ip_count) != ERV_OK))
        {
                return ERV_CONFIG_ERROR;
        }
	
	if (((eemo_fn->conf_get_string_array)(conf_base_path, "ignore_ips", &ignore_ips, &ignore_ip_count) != ERV_OK))
        {
                return ERV_CONFIG_ERROR;
        }

	if ((eemo_fn->conf_get_int)(conf_base_path, "emit_interval", &emit_interval, 0) != ERV_OK)
	{
		return ERV_CONFIG_ERROR;
	}

	if ((eemo_fn->conf_get_int)(conf_base_path, "emit_qname_ctr", &emit_qname_ctr, 1) != ERV_OK)
	{
		return ERV_CONFIG_ERROR;
	}

	/* Initialise the DNS statistics counter */
	eemo_dnsdistribution_stats_init(file_general, file_qname_popularity, file_ttl, file_sigs_per_resp, file_rcodes, resolver_ips, resolver_ip_count, ignore_ips, ignore_ip_count, emit_interval, emit_qname_ctr);

	/* Register DNS query handler */
	rv = (eemo_fn->reg_dns_handler)(&eemo_dnsdistribution_stats_handleqr, PARSE_QUERY | PARSE_RESPONSE | PARSE_CANONICALIZE_NAME, &stats_dns_handler_handle);

	if (rv != ERV_OK)
	{
		ERROR_MSG("Failed to register DNS query handler");

		return rv;
	}

	return ERV_OK;
}

/* Plugin uninitialisation */
eemo_rv eemo_dnsdistribution_uninit(eemo_export_fn_table_ptr eemo_fn)
{
	/* Unregister DNS query handler */
	if ((eemo_fn->unreg_dns_handler)(stats_dns_handler_handle) != ERV_OK)
	{
		ERROR_MSG("Failed to unregister DNS query handler");
	}

	eemo_dnsdistribution_stats_uninit(eemo_fn->conf_free_string_array);

	return ERV_OK;
}

/* Retrieve plugin description */
const char* eemo_dnsdistribution_getdescription(void)
{
	return plugin_description;
}

/* Retrieve plugin status */
eemo_rv eemo_dnsdistribution_status(void)
{
	return ERV_OK;
}

/* Plugin function table */
static eemo_plugin_fn_table dnsdistribution_fn_table =
{
	EEMO_PLUGIN_FN_VERSION,
	&eemo_dnsdistribution_init,
	&eemo_dnsdistribution_uninit,
	&eemo_dnsdistribution_getdescription,
	&eemo_dnsdistribution_status
};

/* Entry point for retrieving plugin function table */
eemo_rv eemo_plugin_get_fn_table(eemo_plugin_fn_table_ptrptr fn_table)
{
	if (fn_table == NULL)
	{
		return ERV_PARAM_INVALID;
	}

	*fn_table = &dnsdistribution_fn_table;

	return ERV_OK;
}

