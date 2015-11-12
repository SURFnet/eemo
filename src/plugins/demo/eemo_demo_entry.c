/* $Id$ */

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

/* TCP and UDP handler handles */
static unsigned long 		udp_handler_handle 	= 0;
static unsigned long 		tcp_handler_handle 	= 0;
static unsigned long		dns_handler_handle	= 0;

/* Counters */
static unsigned long long	tcp_counter		= 0;
static unsigned long long	udp_counter		= 0;
static unsigned long long	all_counter		= 0;
static unsigned long long	dns_counter		= 0;
static unsigned long long	dns_q_counter		= 0;
static unsigned long long	dns_r_counter		= 0;

static eemo_export_fn_table_ptr	eemo_fn_exp		= NULL;

/* Sample UDP handler */
eemo_rv eemo_demo_udp_handler(const eemo_packet_buf* pkt, eemo_ip_packet_info ip_info, u_short srcport, u_short dstport, u_short length)
{
	const char*	cidr_desc	= NULL;

	DEBUG_MSG("UDPv%d packet from %s:%d (%s,%s,%s) to %s:%d (%s,%s,%s) (UDP size %d)", ip_info.ip_type, ip_info.ip_src, srcport, ip_info.src_as_short, ip_info.src_as_full, ip_info.src_geo_ip, ip_info.ip_dst, dstport, ip_info.dst_as_short, ip_info.dst_as_full, ip_info.dst_geo_ip, length);

	udp_counter++;
	all_counter++;

	/* Do CIDR matching */
	if (ip_info.ip_type == 4)
	{
		if ((eemo_fn_exp->cm_match_v4)(ip_info.src_addr.v4, &cidr_desc) == ERV_OK)
		{
			DEBUG_MSG("%s matches CIDR block with description '%s'", ip_info.ip_src, cidr_desc);
		}

		if ((eemo_fn_exp->cm_match_v4)(ip_info.dst_addr.v4, &cidr_desc) == ERV_OK)
		{
			DEBUG_MSG("%s matches CIDR block with description '%s'", ip_info.ip_dst, cidr_desc);
		}
	}
	else
	{
		if ((eemo_fn_exp->cm_match_v6)(ip_info.src_addr.v6, &cidr_desc) == ERV_OK)
		{
			DEBUG_MSG("%s matches CIDR block with description '%s'", ip_info.ip_src, cidr_desc);
		}

		if ((eemo_fn_exp->cm_match_v6)(ip_info.dst_addr.v6, &cidr_desc) == ERV_OK)
		{
			DEBUG_MSG("%s matches CIDR block with description '%s'", ip_info.ip_dst, cidr_desc);
		}
	}

	return ERV_HANDLED;
}

/* Sample TCP handler */
eemo_rv eemo_demo_tcp_handler(const eemo_packet_buf* pkt, eemo_ip_packet_info ip_info, eemo_tcp_packet_info tcp_info)
{
	DEBUG_MSG("TCPv%d packet from %s:%d to %s:%d", ip_info.ip_type, ip_info.ip_src, tcp_info.srcport, ip_info.ip_dst, tcp_info.dstport);

	tcp_counter++;
	all_counter++;

	return ERV_HANDLED;
}

/* Sample DNS handler */
eemo_rv eemo_demo_dns_handler(eemo_ip_packet_info ip_info, int is_tcp, const eemo_dns_packet* pkt)
{
	dns_counter++;

	if (pkt->qr_flag)
	{
		dns_r_counter++;
	}
	else
	{
		dns_q_counter++;
	}

	return ERV_HANDLED;
}

/* Plugin initialisation */
eemo_rv eemo_demo_init(eemo_export_fn_table_ptr eemo_fn, const char* conf_base_path)
{
	eemo_fn_exp = eemo_fn;

	/* Initialise logging for the plugin */
	eemo_init_plugin_log(eemo_fn->log);

	INFO_MSG("Initialising demo plugin");

	/* Register UDP handler */
	if ((eemo_fn->reg_udp_handler)(UDP_ANY_PORT, UDP_ANY_PORT, &eemo_demo_udp_handler, &udp_handler_handle) != ERV_OK)
	{
		ERROR_MSG("Failed to register demo UDP handler");

		return ERV_GENERAL_ERROR;
	}

	/* Register TCP handler */
	if ((eemo_fn->reg_tcp_handler)(TCP_ANY_PORT, TCP_ANY_PORT, &eemo_demo_tcp_handler, &tcp_handler_handle) != ERV_OK)
	{
		ERROR_MSG("Failed to register demo TCP handler");

		(eemo_fn->unreg_udp_handler)(udp_handler_handle);

		return ERV_GENERAL_ERROR;
	}

	/* Register DNS handler */
	if ((eemo_fn->reg_dns_handler)(&eemo_demo_dns_handler, PARSE_QUERY | PARSE_RESPONSE, &dns_handler_handle) != ERV_OK)
	{
		ERROR_MSG("Failed to register demo DNS handler");

		(eemo_fn->unreg_dns_handler)(dns_handler_handle);

		return ERV_GENERAL_ERROR;
	}

	/* Add some CIDR blocks */
	if ((eemo_fn->cm_add_block)("8.8.4.0/24", "Google Public DNS v4 /24") != ERV_OK)
	{
		ERROR_MSG("Failed to add CIDR block");

		return ERV_GENERAL_ERROR;
	}

	if ((eemo_fn->cm_add_block)("8.8.0.0/16", "Google Public DNS v4 /16") != ERV_OK)
	{
		ERROR_MSG("Failed to add CIDR block");

		return ERV_GENERAL_ERROR;
	}

	if ((eemo_fn->cm_add_block)("2001:4860:4860::8888/126", "Google Public DNS v6 /126") != ERV_OK)
	{
		ERROR_MSG("Failed to add CIDR block");

		return ERV_GENERAL_ERROR;
	}

	if ((eemo_fn->cm_add_block)("2001:4860:4860::/48", "Google Public DNS v6 /48") != ERV_OK)
	{
		ERROR_MSG("Failed to add CIDR block");

		return ERV_GENERAL_ERROR;
	}

	INFO_MSG("Demo plugin initialisation complete");

	return ERV_OK;
}

/* Plugin uninitialisation */
eemo_rv eemo_demo_uninit(eemo_export_fn_table_ptr eemo_fn)
{
	INFO_MSG("Uninitialising demo plugin");

	INFO_MSG("Counters: UDP [%llu] TCP [%llu] ALL [%llu] DNS [%llu] DNSQ [%llu] DNSR[%llu]", udp_counter, tcp_counter, all_counter, dns_counter, dns_q_counter, dns_r_counter);

	/* Unregister DNS handler */
	if ((eemo_fn->unreg_dns_handler)(dns_handler_handle) != ERV_OK)
	{
		ERROR_MSG("Failed to unregister demo DNS handler");
	}

	/* Unregister UDP handler */
	if ((eemo_fn->unreg_udp_handler)(udp_handler_handle) != ERV_OK)
	{
		ERROR_MSG("Failed to unregister demo UDP handler");
	}

	/* Unregister TCP handler */
	if ((eemo_fn->unreg_tcp_handler)(tcp_handler_handle) != ERV_OK)
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

