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
 * DNS statistics plugin library entry functions
 */

#include "config.h"
#include <stdlib.h>
#include "eemo.h"
#include "eemo_api.h"
#include "eemo_plugin_log.h"
#include "eemo_dnsqrlog.h"

const static char* plugin_description = "EEMO DNS query/response logging plugin " PACKAGE_VERSION;

/* Handler handle */
static unsigned long qrlog_dns_handler_handle = 0;

/* Plugin initialisation */
eemo_rv eemo_dnsqrlog_entry(eemo_export_fn_table_ptr eemo_fn, const char* conf_base_path)
{
	char** 	ips 		= NULL;
	int 	ipcount 	= 0;
	char**	domains		= NULL;
	int	domcount	= 0;
	char*	logfile		= NULL;
	eemo_rv rv		= ERV_OK;

	/* Initialise logging for the plugin */
	eemo_init_plugin_log(eemo_fn->log);

	/* Retrieve configuration */
	if ((eemo_fn->conf_get_string_array)(conf_base_path, "listen_ips", &ips, &ipcount) != ERV_OK)
	{
		return ERV_CONFIG_ERROR;
	}

	if ((eemo_fn->conf_get_string_array)(conf_base_path, "log_domains", &domains, &domcount) != ERV_OK)
	{
		(eemo_fn->conf_free_string_array)(ips, ipcount);

		return ERV_CONFIG_ERROR;
	}
	
	if ((eemo_fn->conf_get_string)(conf_base_path, "log_file", &logfile, "qrlog.txt") != ERV_OK)
	{
		(eemo_fn->conf_free_string_array)(ips, ipcount);
		(eemo_fn->conf_free_string_array)(domains, domcount);
		
		return ERV_CONFIG_ERROR;
	}

	/* Initialise the DNS statistics counter */
	eemo_dnsqrlog_init(ips, ipcount, domains, domcount, logfile);

	/* Register DNS query handler */
	rv = (eemo_fn->reg_dns_handler)(&eemo_dnsqrlog_handleqr, PARSE_QUERY | PARSE_RESPONSE | PARSE_RDATA_TO_STR, &qrlog_dns_handler_handle);
	
	free(logfile);

	if (rv != ERV_OK)
	{
		ERROR_MSG("Failed to register DNS query handler");

		return rv;
	}

	return ERV_OK;
}

/* Plugin uninitialisation */
eemo_rv eemo_dnsqrlog_exit(eemo_export_fn_table_ptr eemo_fn)
{
	/* Unregister DNS query handler */
	if ((eemo_fn->unreg_dns_handler)(qrlog_dns_handler_handle) != ERV_OK)
	{
		ERROR_MSG("Failed to unregister DNS query handler");
	}

	eemo_dnsqrlog_uninit(eemo_fn->conf_free_string_array);

	return ERV_OK;
}

/* Retrieve plugin description */
const char* eemo_dnsqrlog_getdescription(void)
{
	return plugin_description;
}

/* Retrieve plugin status */
eemo_rv eemo_dnsqrlog_status(void)
{
	return ERV_OK;
}

/* Plugin function table */
static eemo_plugin_fn_table dnsqrlog_fn_table =
{
	EEMO_PLUGIN_FN_VERSION,
	&eemo_dnsqrlog_entry,
	&eemo_dnsqrlog_exit,
	&eemo_dnsqrlog_getdescription,
	&eemo_dnsqrlog_status
};

/* Entry point for retrieving plugin function table */
eemo_rv eemo_plugin_get_fn_table(eemo_plugin_fn_table_ptrptr fn_table)
{
	if (fn_table == NULL)
	{
		return ERV_PARAM_INVALID;
	}

	*fn_table = &dnsqrlog_fn_table;

	return ERV_OK;
}

