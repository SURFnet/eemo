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
 * Demo plugin library entry functions
 */

#include "config.h"
#include <stdlib.h>
#include "eemo.h"
#include "eemo_api.h"
#include "eemo_plugin_log.h"
#include "udp_handler.h"
#include "tcp_handler.h"

const static char* plugin_description = "EEMO demo plugin " PACKAGE_VERSION;

/* Sample UDP handler */
eemo_rv eemo_demo_udp_handler(eemo_packet_buf* pkt, eemo_ip_packet_info ip_info, u_short srcport, u_short dstport)
{
	INFO_MSG("UDPv%d packet from %s:%d to %s:%d", ip_info.ip_type, ip_info.ip_src, srcport, ip_info.ip_dst, dstport);

	return ERV_OK;
}

/* Sample TCP handler */
eemo_rv eemo_demo_tcp_handler(eemo_packet_buf* pkt, eemo_ip_packet_info ip_info, eemo_tcp_packet_info tcp_info)
{
	INFO_MSG("TCPv%d packet from %s:%d to %s:%d", ip_info.ip_type, ip_info.ip_src, tcp_info.srcport, ip_info.ip_dst, tcp_info.dstport);

	return ERV_OK;
}

/* Plugin initialisation */
eemo_rv eemo_demo_init(eemo_export_fn_table_ptr eemo_fn, const char* conf_base_path)
{
	/* Initialise logging for the plugin */
	eemo_init_plugin_log(eemo_fn->log);

	INFO_MSG("Initialising demo plugin");

	/* Register UDP handler */
	if ((eemo_fn->reg_udp_handler)(UDP_ANY_PORT, UDP_ANY_PORT, &eemo_demo_udp_handler) != ERV_OK)
	{
		ERROR_MSG("Failed to register demo UDP handler");

		return ERV_GENERAL_ERROR;
	}

	/* Register TCP handler */
	if ((eemo_fn->reg_tcp_handler)(TCP_ANY_PORT, TCP_ANY_PORT, &eemo_demo_tcp_handler) != ERV_OK)
	{
		ERROR_MSG("Failed to register demo TCP handler");

		(eemo_fn->unreg_udp_handler)(UDP_ANY_PORT, UDP_ANY_PORT);

		return ERV_GENERAL_ERROR;
	}

	INFO_MSG("Demo plugin initialisation complete");

	return ERV_OK;
}

/* Plugin uninitialisation */
eemo_rv eemo_demo_uninit(eemo_export_fn_table_ptr eemo_fn)
{
	INFO_MSG("Uninitialising demo plugin");

	/* Unregister UDP handler */
	if ((eemo_fn->unreg_udp_handler)(UDP_ANY_PORT, UDP_ANY_PORT) != ERV_OK)
	{
		ERROR_MSG("Failed to unregister demo UDP handler");
	}

	/* Unregister TCP handler */
	if ((eemo_fn->unreg_tcp_handler)(TCP_ANY_PORT, TCP_ANY_PORT) != ERV_OK)
	{
		ERROR_MSG("Failed to unregister demo TCP handler");
	}

	INFO_MSG("Finished uninitialising demo plugin");

	return ERV_OK;
}

/* Retrieve plugin description */
const char* eemo_demo_getdescription(void)
{
	return plugin_description;
}

/* Retrieve plugin status */
eemo_rv eemo_demo_status(void)
{
	return ERV_OK;
}

/* Plugin function table */
static eemo_plugin_fn_table demo_fn_table =
{
	EEMO_PLUGIN_FN_VERSION,
	&eemo_demo_init,
	&eemo_demo_uninit,
	&eemo_demo_getdescription,
	&eemo_demo_status
};

/* Entry point for retrieving plugin function table */
eemo_rv eemo_plugin_get_fn_table(eemo_plugin_fn_table_ptrptr fn_table)
{
	if (fn_table == NULL)
	{
		return ERV_PARAM_INVALID;
	}

	*fn_table = &demo_fn_table;

	return ERV_OK;
}

