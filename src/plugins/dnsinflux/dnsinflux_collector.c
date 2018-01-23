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
 * InfluxDB DNS statistics collector
 */

#include "config.h"
#include <time.h>
#include <stdlib.h>
#include <assert.h>
#include "eemo.h"
#include "eemo_api.h"
#include "eemo_plugin_log.h"
#include "dnsinflux_collector.h"
#include "dnsinflux_itemmgr.h"

/* EEMO function table */
static eemo_export_fn_table_ptr	eemo_fn	= NULL;

/* Collector state */
static time_t	next_epoch_day		= 0;
static time_t	next_stats_output	= 0;
static int	di_stats_interval	= 0;

#define CURRENT_QPS		"Current queries per second            "
#define TOTAL_QUERIES		"Total queries                         "
#define QUERIES_TODAY		"Queries today                         "
#define QUERIES_YESTERDAY	"Queries yesterday                     "
#define CURRENT_INBOUND		"Current inbound DNS traffic (bytes/s) "
#define CURRENT_OUTBOUND	"Current outbound DNS traffic (bytes/s)"

/* Initialise the collector module */
eemo_rv dnsinflux_collector_init(const int stats_interval, eemo_export_fn_table_ptr eemo_fn_table)
{
	assert(stats_interval > 0);
	assert(eemo_fn_table != NULL);

	eemo_fn = eemo_fn_table;

	di_stats_interval = stats_interval;

	/* Register local statistics */
	dnsinflux_add_localstat(CURRENT_QPS		, 0, 1);
	dnsinflux_add_localstat(TOTAL_QUERIES		, 1, 0);
	dnsinflux_add_localstat(QUERIES_TODAY		, 1, 0);
	dnsinflux_add_localstat(QUERIES_YESTERDAY	, 1, 0);
	dnsinflux_add_localstat(CURRENT_INBOUND		, 0, 1);
	dnsinflux_add_localstat(CURRENT_OUTBOUND	, 0, 1);

	/* Register remote statistics */

	/* General inbound (query) statistics */
	dnsinflux_add_remotestat("q_ctr",			1, 1);
	dnsinflux_add_remotestat("dnstraf_inbound",		1, 1);
	dnsinflux_add_remotestat("q_v4_ctr",			1, 1);
	dnsinflux_add_remotestat("q_v6_ctr",			1, 1);
	dnsinflux_add_remotestat("q_udp_ctr",			1, 1);
	dnsinflux_add_remotestat("q_tcp_ctr",			1, 1);
	dnsinflux_add_remotestat("q_malformed_ctr",		1, 1);

	/* General outbound (response) statistics */
	dnsinflux_add_remotestat("r_ctr",			1, 1);
	dnsinflux_add_remotestat("dnstraf_outbound",		1, 1);
	dnsinflux_add_remotestat("r_v4_ctr",			1, 1);
	dnsinflux_add_remotestat("r_v6_ctr",			1, 1);
	dnsinflux_add_remotestat("r_frag_ctr",			1, 1);
	dnsinflux_add_remotestat("r_unfrag_ctr",		1, 1);
	dnsinflux_add_remotestat("r_frag_v4_ctr",		1, 1);
	dnsinflux_add_remotestat("r_unfrag_v4_ctr",		1, 1);
	dnsinflux_add_remotestat("r_frag_v6_ctr",		1, 1);
	dnsinflux_add_remotestat("r_unfrag_v6_ctr",		1, 1);
	dnsinflux_add_remotestat("r_udp_ctr",			1, 1);
	dnsinflux_add_remotestat("r_tcp_ctr",			1, 1);

	/* Query classes */
	dnsinflux_add_remotestat("q_class_IN_ctr",		1, 1);
	dnsinflux_add_remotestat("q_class_CS_ctr",		1, 1);
	dnsinflux_add_remotestat("q_class_CH_ctr",		1, 1);
	dnsinflux_add_remotestat("q_class_HS_ctr",		1, 1);
	dnsinflux_add_remotestat("q_class_ANY_ctr",		1, 1);
	dnsinflux_add_remotestat("q_class_UNKNOWN_ctr",		1, 1);

	/* Query types */
	dnsinflux_add_remotestat("q_type_A_ctr",		1, 1);
	dnsinflux_add_remotestat("q_type_AAAA_ctr",		1, 1);
	dnsinflux_add_remotestat("q_type_AFSDB_ctr",		1, 1);
	dnsinflux_add_remotestat("q_type_APL_ctr",		1, 1);
	dnsinflux_add_remotestat("q_type_CAA_ctr",		1, 1);
	dnsinflux_add_remotestat("q_type_CERT_ctr",		1, 1);
	dnsinflux_add_remotestat("q_type_CNAME_ctr",		1, 1);
	dnsinflux_add_remotestat("q_type_DHCID_ctr",		1, 1);
	dnsinflux_add_remotestat("q_type_DLV_ctr",		1, 1);
	dnsinflux_add_remotestat("q_type_DNAME_ctr",		1, 1);
	dnsinflux_add_remotestat("q_type_DNSKEY_ctr",		1, 1);
	dnsinflux_add_remotestat("q_type_DS_ctr",		1, 1);
	dnsinflux_add_remotestat("q_type_HIP_ctr",		1, 1);
	dnsinflux_add_remotestat("q_type_IPSECKEY_ctr",		1, 1);
	dnsinflux_add_remotestat("q_type_KEY_ctr",		1, 1);
	dnsinflux_add_remotestat("q_type_KX_ctr",		1, 1);
	dnsinflux_add_remotestat("q_type_LOC_ctr",		1, 1);
	dnsinflux_add_remotestat("q_type_MX_ctr",		1, 1);
	dnsinflux_add_remotestat("q_type_NAPTR_ctr",		1, 1);
	dnsinflux_add_remotestat("q_type_NS_ctr",		1, 1);
	dnsinflux_add_remotestat("q_type_NSEC_ctr",		1, 1);
	dnsinflux_add_remotestat("q_type_NSEC3_ctr",		1, 1);
	dnsinflux_add_remotestat("q_type_NSEC3PARAM_ctr",	1, 1);
	dnsinflux_add_remotestat("q_type_PTR_ctr",		1, 1);
	dnsinflux_add_remotestat("q_type_RRSIG_ctr",		1, 1);
	dnsinflux_add_remotestat("q_type_RP_ctr",		1, 1);
	dnsinflux_add_remotestat("q_type_SIG_ctr",		1, 1);
	dnsinflux_add_remotestat("q_type_SOA_ctr",		1, 1);
	dnsinflux_add_remotestat("q_type_SPF_ctr",		1, 1);
	dnsinflux_add_remotestat("q_type_SRV_ctr",		1, 1);
	dnsinflux_add_remotestat("q_type_SSHFP_ctr",		1, 1);
	dnsinflux_add_remotestat("q_type_TA_ctr",		1, 1);
	dnsinflux_add_remotestat("q_type_TKEY_ctr",		1, 1);
	dnsinflux_add_remotestat("q_type_TLSA_ctr",		1, 1);
	dnsinflux_add_remotestat("q_type_TSIG_ctr",		1, 1);
	dnsinflux_add_remotestat("q_type_TXT_ctr",		1, 1);
	dnsinflux_add_remotestat("q_type_ANY_ctr",		1, 1);
	dnsinflux_add_remotestat("q_type_AXFR_ctr",		1, 1);
	dnsinflux_add_remotestat("q_type_IXFR_ctr",		1, 1);
	dnsinflux_add_remotestat("q_type_OPT_ctr",		1, 1);
	dnsinflux_add_remotestat("q_type_UNKNOWN_ctr",		1, 1);

	/* Query flags */
	dnsinflux_add_remotestat("q_aa_set_ctr",		1, 1);
	dnsinflux_add_remotestat("q_tc_set_ctr",		1, 1);
	dnsinflux_add_remotestat("q_rd_set_ctr",		1, 1);
	dnsinflux_add_remotestat("q_ra_set_ctr",		1, 1);
	dnsinflux_add_remotestat("q_ad_set_ctr",		1, 1);
	dnsinflux_add_remotestat("q_cd_set_ctr",		1, 1);
	dnsinflux_add_remotestat("q_edns0_do_set_ctr",		1, 1);

	/* Query EDNS0 information */
	dnsinflux_add_remotestat("q_has_edns0_ctr",		1, 1);
	dnsinflux_add_remotestat("q_no_edns0_ctr",		1, 1);
	dnsinflux_add_remotestat("q_edns0_do_set_ctr",		1, 1);
	dnsinflux_add_remotestat("q_edns0_do_unset_ctr",	1, 1);
	dnsinflux_add_remotestat("q_edns0_maxsize_le_512_ctr",	1, 1);
	dnsinflux_add_remotestat("q_edns0_maxsize_le_1280_ctr",	1, 1);
	dnsinflux_add_remotestat("q_edns0_maxsize_le_1500_ctr",	1, 1);
	dnsinflux_add_remotestat("q_edns0_maxsize_le_4096_ctr",	1, 1);
	dnsinflux_add_remotestat("q_edns0_maxsize_gt_4096_ctr",	1, 1);
	dnsinflux_add_remotestat("q_edns0_has_ecs_ctr",		1, 1);
	dnsinflux_add_remotestat("q_edns0_has_no_ecs_ctr",	1, 1);

	/* Response classes */
	dnsinflux_add_remotestat("r_class_IN_ctr",		1, 1);
	dnsinflux_add_remotestat("r_class_CS_ctr",		1, 1);
	dnsinflux_add_remotestat("r_class_CH_ctr",		1, 1);
	dnsinflux_add_remotestat("r_class_HS_ctr",		1, 1);
	dnsinflux_add_remotestat("r_class_ANY_ctr",		1, 1);
	dnsinflux_add_remotestat("r_class_UNKNOWN_ctr",		1, 1);

	/* Response types */
	dnsinflux_add_remotestat("r_type_A_ctr",		1, 1);
	dnsinflux_add_remotestat("r_type_AAAA_ctr",		1, 1);
	dnsinflux_add_remotestat("r_type_AFSDB_ctr",		1, 1);
	dnsinflux_add_remotestat("r_type_APL_ctr",		1, 1);
	dnsinflux_add_remotestat("r_type_CAA_ctr",		1, 1);
	dnsinflux_add_remotestat("r_type_CERT_ctr",		1, 1);
	dnsinflux_add_remotestat("r_type_CNAME_ctr",		1, 1);
	dnsinflux_add_remotestat("r_type_DHCID_ctr",		1, 1);
	dnsinflux_add_remotestat("r_type_DLV_ctr",		1, 1);
	dnsinflux_add_remotestat("r_type_DNAME_ctr",		1, 1);
	dnsinflux_add_remotestat("r_type_DNSKEY_ctr",		1, 1);
	dnsinflux_add_remotestat("r_type_DS_ctr",		1, 1);
	dnsinflux_add_remotestat("r_type_HIP_ctr",		1, 1);
	dnsinflux_add_remotestat("r_type_IPSECKEY_ctr",		1, 1);
	dnsinflux_add_remotestat("r_type_KEY_ctr",		1, 1);
	dnsinflux_add_remotestat("r_type_KX_ctr",		1, 1);
	dnsinflux_add_remotestat("r_type_LOC_ctr",		1, 1);
	dnsinflux_add_remotestat("r_type_MX_ctr",		1, 1);
	dnsinflux_add_remotestat("r_type_NAPTR_ctr",		1, 1);
	dnsinflux_add_remotestat("r_type_NS_ctr",		1, 1);
	dnsinflux_add_remotestat("r_type_NSEC_ctr",		1, 1);
	dnsinflux_add_remotestat("r_type_NSEC3_ctr",		1, 1);
	dnsinflux_add_remotestat("r_type_NSEC3PARAM_ctr",	1, 1);
	dnsinflux_add_remotestat("r_type_PTR_ctr",		1, 1);
	dnsinflux_add_remotestat("r_type_RRSIG_ctr",		1, 1);
	dnsinflux_add_remotestat("r_type_RP_ctr",		1, 1);
	dnsinflux_add_remotestat("r_type_SIG_ctr",		1, 1);
	dnsinflux_add_remotestat("r_type_SOA_ctr",		1, 1);
	dnsinflux_add_remotestat("r_type_SPF_ctr",		1, 1);
	dnsinflux_add_remotestat("r_type_SRV_ctr",		1, 1);
	dnsinflux_add_remotestat("r_type_SSHFP_ctr",		1, 1);
	dnsinflux_add_remotestat("r_type_TA_ctr",		1, 1);
	dnsinflux_add_remotestat("r_type_TKEY_ctr",		1, 1);
	dnsinflux_add_remotestat("r_type_TLSA_ctr",		1, 1);
	dnsinflux_add_remotestat("r_type_TSIG_ctr",		1, 1);
	dnsinflux_add_remotestat("r_type_TXT_ctr",		1, 1);
	dnsinflux_add_remotestat("r_type_ANY_ctr",		1, 1);
	dnsinflux_add_remotestat("r_type_AXFR_ctr",		1, 1);
	dnsinflux_add_remotestat("r_type_IXFR_ctr",		1, 1);
	dnsinflux_add_remotestat("r_type_OPT_ctr",		1, 1);
	dnsinflux_add_remotestat("r_type_UNKNOWN_ctr",		1, 1);

	/* Response flags */
	dnsinflux_add_remotestat("r_aa_set_ctr",		1, 1);
	dnsinflux_add_remotestat("r_tc_set_ctr",		1, 1);
	dnsinflux_add_remotestat("r_rd_set_ctr",		1, 1);
	dnsinflux_add_remotestat("r_ra_set_ctr",		1, 1);
	dnsinflux_add_remotestat("r_ad_set_ctr",		1, 1);
	dnsinflux_add_remotestat("r_cd_set_ctr",		1, 1);

	/* Response EDNS0 information */
	dnsinflux_add_remotestat("r_has_edns0_ctr",		1, 1);
	dnsinflux_add_remotestat("r_no_edns0_ctr",		1, 1);
	dnsinflux_add_remotestat("r_edns0_do_set_ctr",		1, 1);
	dnsinflux_add_remotestat("r_edns0_do_unset_ctr",	1, 1);
	dnsinflux_add_remotestat("r_edns0_has_ecs_ctr",		1, 1);
	dnsinflux_add_remotestat("r_edns0_has_no_ecs_ctr",	1, 1);

	/* Response size */
	dnsinflux_add_remotestat("r_rsize_le_512_ctr",		1, 1);
	dnsinflux_add_remotestat("r_rsize_le_1280_ctr",		1, 1);
	dnsinflux_add_remotestat("r_rsize_le_1500_ctr",		1, 1);
	dnsinflux_add_remotestat("r_rsize_le_4096_ctr",		1, 1);
	dnsinflux_add_remotestat("r_rsize_gt_4096_ctr",		1, 1);

	/* Response status codes */
	dnsinflux_add_remotestat("r_rcode_nodata_ctr",		1, 1);
	dnsinflux_add_remotestat("r_rcode_referral_ctr",	1, 1);
	dnsinflux_add_remotestat("r_rcode_unknown_ctr",		1, 1);
	dnsinflux_add_remotestat("r_rcode_noerror_ctr",		1, 1);
	dnsinflux_add_remotestat("r_rcode_formerr_ctr",		1, 1);
	dnsinflux_add_remotestat("r_rcode_servfail_ctr",	1, 1);
	dnsinflux_add_remotestat("r_rcode_nxdomain_ctr",	1, 1);
	dnsinflux_add_remotestat("r_rcode_notimpl_ctr",		1, 1);
	dnsinflux_add_remotestat("r_rcode_refused_ctr",		1, 1);
	dnsinflux_add_remotestat("r_rcode_unknown_ctr",		1, 1);

	/* DNS notification */
	dnsinflux_add_remotestat("notify_in_ctr",		1, 1);
	dnsinflux_add_remotestat("notify_out_ctr",		1, 1);

	INFO_MSG("Initialised DNS InfluxDB statistics collector");

	return ERV_OK;
}

/* Finalise the collector module */
eemo_rv dnsinflux_collector_finalise(void)
{
	INFO_MSG("Finalised DNS InfluxDB statistics collector");

	return ERV_OK;
}

/* Handle DNS queries */
static eemo_rv dnsinflux_handle_q(eemo_ip_packet_info ip_info, int is_tcp, const eemo_dns_packet* dns_packet)
{
	const char*	cidr_desc	= NULL;

	/* Check if this is an inbound query to the prefix we are monitoring */
	if (((ip_info.ip_type == 4) && ((eemo_fn->cm_match_v4)(ip_info.dst_addr.v4, &cidr_desc) == ERV_OK)) ||
	    ((ip_info.ip_type == 6) && ((eemo_fn->cm_match_v6)(ip_info.dst_addr.v6, &cidr_desc) == ERV_OK)))
	{
		/* Update local statistics */
		dnsinflux_inc_localstat(CURRENT_QPS);
		dnsinflux_inc_localstat(TOTAL_QUERIES);
		dnsinflux_inc_localstat(QUERIES_TODAY);
		dnsinflux_addto_localstat(CURRENT_INBOUND, dns_packet->udp_len);

		/* Update remote statistics */

		/* Update general inbound query statistics */
		dnsinflux_inc_remotestat("q_ctr");
		dnsinflux_addto_remotestat("dnstraf_inbound", dns_packet->udp_len);
		
		switch(ip_info.ip_type)
		{
		case 4:
			dnsinflux_inc_remotestat("q_v4_ctr");
			break;
		case 6:
			dnsinflux_inc_remotestat("q_v6_ctr");
			break;
		default:
			ERROR_MSG("Unknown IP version %d", ip_info.ip_type);
		}

		if (is_tcp)
		{
			dnsinflux_inc_remotestat("q_tcp_ctr");
		}
		else
		{
			dnsinflux_inc_remotestat("q_udp_ctr");
		}

		/* Log information about the query */
		if (dns_packet->opcode == DNS_OPCODE_NOTIFY)
		{
			dnsinflux_inc_remotestat("notify_in_ctr");
		}
		else if (dns_packet->questions != NULL)
		{
			eemo_dns_query*	q_it	= NULL;

			LL_FOREACH(dns_packet->questions, q_it)
			{
				/* Query class */
				switch(q_it->qclass)
				{
				case DNS_QCLASS_IN:
					dnsinflux_inc_remotestat("q_class_IN_ctr");
					break;
				case DNS_QCLASS_CS:
					dnsinflux_inc_remotestat("q_class_CS_ctr");
					break;
				case DNS_QCLASS_CH:
					dnsinflux_inc_remotestat("q_class_CH_ctr");
					break;
				case DNS_QCLASS_HS:
					dnsinflux_inc_remotestat("q_class_HS_ctr");
					break;
				case DNS_QCLASS_ANY:
					dnsinflux_inc_remotestat("q_class_ANY_ctr");
					break;
				default:
					dnsinflux_inc_remotestat("q_class_UNKNOWN_ctr");
				}

				/* Log query type */
				switch(q_it->qtype)
				{
				case DNS_QTYPE_A:
					dnsinflux_inc_remotestat("q_type_A_ctr");
					break;
				case DNS_QTYPE_AAAA:
					dnsinflux_inc_remotestat("q_type_AAAA_ctr");
					break;
				case DNS_QTYPE_AFSDB:
					dnsinflux_inc_remotestat("q_type_AFSDB_ctr");
					break;
				case DNS_QTYPE_APL:
					dnsinflux_inc_remotestat("q_type_APL_ctr");
					break;
				case DNS_QTYPE_CAA:
					dnsinflux_inc_remotestat("q_type_CAA_ctr");
					break;
				case DNS_QTYPE_CERT:
					dnsinflux_inc_remotestat("q_type_CERT_ctr");
					break;
				case DNS_QTYPE_CNAME:
					dnsinflux_inc_remotestat("q_type_CNAME_ctr");
					break;
				case DNS_QTYPE_DHCID:
					dnsinflux_inc_remotestat("q_type_DHCID_ctr");
					break;
				case DNS_QTYPE_DLV:
					dnsinflux_inc_remotestat("q_type_DLV_ctr");
					break;
				case DNS_QTYPE_DNAME:
					dnsinflux_inc_remotestat("q_type_DNAME_ctr");
					break;
				case DNS_QTYPE_DNSKEY:
					dnsinflux_inc_remotestat("q_type_DNSKEY_ctr");
					break;
				case DNS_QTYPE_DS:
					dnsinflux_inc_remotestat("q_type_DS_ctr");
					break;
				case DNS_QTYPE_HIP:
					dnsinflux_inc_remotestat("q_type_HIP_ctr");
					break;
				case DNS_QTYPE_IPSECKEY:
					dnsinflux_inc_remotestat("q_type_IPSECKEY_ctr");
					break;
				case DNS_QTYPE_KEY:
					dnsinflux_inc_remotestat("q_type_KEY_ctr");
					break;
				case DNS_QTYPE_KX:
					dnsinflux_inc_remotestat("q_type_KX_ctr");
					break;
				case DNS_QTYPE_LOC:
					dnsinflux_inc_remotestat("q_type_LOC_ctr");
					break;
				case DNS_QTYPE_MX:
					dnsinflux_inc_remotestat("q_type_MX_ctr");
					break;
				case DNS_QTYPE_NAPTR:
					dnsinflux_inc_remotestat("q_type_NAPTR_ctr");
					break;
				case DNS_QTYPE_NS:
					dnsinflux_inc_remotestat("q_type_NS_ctr");
					break;
				case DNS_QTYPE_NSEC:
					dnsinflux_inc_remotestat("q_type_NSEC_ctr");
					break;
				case DNS_QTYPE_NSEC3:
					dnsinflux_inc_remotestat("q_type_NSEC3_ctr");
					break;
				case DNS_QTYPE_NSEC3PARAM:
					dnsinflux_inc_remotestat("q_type_NSEC3PARAM_ctr");
					break;
				case DNS_QTYPE_PTR:
					dnsinflux_inc_remotestat("q_type_PTR_ctr");
					break;
				case DNS_QTYPE_RRSIG:
					dnsinflux_inc_remotestat("q_type_RRSIG_ctr");
					break;
				case DNS_QTYPE_RP:
					dnsinflux_inc_remotestat("q_type_RP_ctr");
					break;
				case DNS_QTYPE_SIG:
					dnsinflux_inc_remotestat("q_type_SIG_ctr");
					break;
				case DNS_QTYPE_SOA:
					dnsinflux_inc_remotestat("q_type_SOA_ctr");
					break;
				case DNS_QTYPE_SPF:
					dnsinflux_inc_remotestat("q_type_SPF_ctr");
					break;
				case DNS_QTYPE_SRV:
					dnsinflux_inc_remotestat("q_type_SRV_ctr");
					break;
				case DNS_QTYPE_SSHFP:
					dnsinflux_inc_remotestat("q_type_SSHFP_ctr");
					break;
				case DNS_QTYPE_TA:
					dnsinflux_inc_remotestat("q_type_TA_ctr");
					break;
				case DNS_QTYPE_TKEY:
					dnsinflux_inc_remotestat("q_type_TKEY_ctr");
					break;
				case DNS_QTYPE_TLSA:
					dnsinflux_inc_remotestat("q_type_TLSA_ctr");
					break;
				case DNS_QTYPE_TSIG:
					dnsinflux_inc_remotestat("q_type_TSIG_ctr");
					break;
				case DNS_QTYPE_TXT:
					dnsinflux_inc_remotestat("q_type_TXT_ctr");
					break;
				case DNS_QTYPE_ANY:
					dnsinflux_inc_remotestat("q_type_ANY_ctr");
					break;
				case DNS_QTYPE_AXFR:
					dnsinflux_inc_remotestat("q_type_AXFR_ctr");
					break;
				case DNS_QTYPE_IXFR:
					dnsinflux_inc_remotestat("q_type_IXFR_ctr");
					break;
				case DNS_QTYPE_OPT:
					dnsinflux_inc_remotestat("q_type_OPT_ctr");
					break;
				default:
					dnsinflux_inc_remotestat("q_type_UNKNOWN_ctr");
				}
			}
		}
		else
		{
			dnsinflux_inc_remotestat("q_malformed_ctr");
		}

		/* Log packet flags */
		if (dns_packet->aa_flag)
		{
			dnsinflux_inc_remotestat("q_aa_set_ctr");
		}

		if (dns_packet->tc_flag)
		{
			dnsinflux_inc_remotestat("q_tc_set_ctr");
		}

		if (dns_packet->rd_flag)
		{
			dnsinflux_inc_remotestat("q_rd_set_ctr");
		}
		
		if (dns_packet->ra_flag)
		{
			dnsinflux_inc_remotestat("q_ra_set_ctr");
		}

		if (dns_packet->ad_flag)
		{
			dnsinflux_inc_remotestat("q_ad_set_ctr");
		}

		if (dns_packet->cd_flag)
		{
			dnsinflux_inc_remotestat("q_cd_set_ctr");
		}

		/* Log EDNS0 information */
		if (dns_packet->has_edns0)
		{
			dnsinflux_inc_remotestat("q_has_edns0_ctr");

			if (dns_packet->edns0_do)
			{
				dnsinflux_inc_remotestat("q_edns0_do_set_ctr");
			}
			else
			{
				dnsinflux_inc_remotestat("q_edns0_do_unset_ctr");
			}

			if (dns_packet->edns0_max_size <= 512)
			{
				dnsinflux_inc_remotestat("q_edns0_maxsize_le_512_ctr");
			}
			else if (dns_packet->edns0_max_size <= 1280)
			{
				dnsinflux_inc_remotestat("q_edns0_maxsize_le_1280_ctr");
			}
			else if (dns_packet->edns0_max_size <= 1500)
			{
				dnsinflux_inc_remotestat("q_edns0_maxsize_le_1500_ctr");
			}
			else if (dns_packet->edns0_max_size <= 4096)
			{
				dnsinflux_inc_remotestat("q_edns0_maxsize_le_4096_ctr");
			}
			else
			{
				dnsinflux_inc_remotestat("q_edns0_maxsize_gt_4096_ctr");
			}

			if (dns_packet->has_edns0_client_subnet)
			{
				dnsinflux_inc_remotestat("q_edns0_has_ecs_ctr");
			}
			else
			{
				dnsinflux_inc_remotestat("q_edns0_has_no_ecs_ctr");
			}
		}
		else
		{
			dnsinflux_inc_remotestat("q_no_edns0_ctr");
		}

		return ERV_HANDLED;
	}
	else
	{
		return ERV_SKIPPED;
	}
}

/* Handle responses */
static eemo_rv dnsinflux_handle_r(eemo_ip_packet_info ip_info, int is_tcp, const eemo_dns_packet* dns_packet)
{
	const char*		cidr_desc	= NULL;
	eemo_dns_rr*		answer_it	= NULL;
	unsigned long long	rsize		= 0;

	/* Check if this is an outbound response from the prefix we are monitoring */
	if (((ip_info.ip_type == 4) && ((eemo_fn->cm_match_v4)(ip_info.src_addr.v4, &cidr_desc) == ERV_OK)) ||
	    ((ip_info.ip_type == 6) && ((eemo_fn->cm_match_v6)(ip_info.src_addr.v6, &cidr_desc) == ERV_OK)))
	{
		/* Update local statistics */
		dnsinflux_addto_localstat(CURRENT_OUTBOUND, dns_packet->udp_len);
	
		/* Update general inbound query statistics */
		dnsinflux_inc_remotestat("r_ctr");
		dnsinflux_addto_remotestat("dnstraf_outbound", dns_packet->udp_len);
		
		switch(ip_info.ip_type)
		{
		case 4:
			dnsinflux_inc_remotestat("r_v4_ctr");
			
			if (dns_packet->is_fragmented)
			{
				dnsinflux_inc_remotestat("r_frag_v4_ctr");
				dnsinflux_inc_remotestat("r_frag_ctr");
			}
			else
			{
				dnsinflux_inc_remotestat("r_unfrag_v4_ctr");
				dnsinflux_inc_remotestat("r_unfrag_ctr");
			}

			break;
		case 6:
			dnsinflux_inc_remotestat("r_v6_ctr");
			
			if (dns_packet->is_fragmented)
			{
				dnsinflux_inc_remotestat("r_frag_v6_ctr");
				dnsinflux_inc_remotestat("r_frag_ctr");
			}
			else
			{
				dnsinflux_inc_remotestat("r_unfrag_v6_ctr");
				dnsinflux_inc_remotestat("r_unfrag_ctr");
			}
			break;
		default:
			ERROR_MSG("Unknown IP version %d", ip_info.ip_type);
		}

		if (is_tcp)
		{
			dnsinflux_inc_remotestat("r_tcp_ctr");
		}
		else
		{
			dnsinflux_inc_remotestat("r_udp_ctr");
		}

		/* Count answer classes and types */
		LL_FOREACH(dns_packet->answers, answer_it)
		{
			/* Log answer class */
			switch(answer_it->class)
			{
			case DNS_QCLASS_IN:
				dnsinflux_inc_remotestat("r_class_IN_ctr");
				break;
			case DNS_QCLASS_CS:
				dnsinflux_inc_remotestat("r_class_CS_ctr");
				break;
			case DNS_QCLASS_CH:
				dnsinflux_inc_remotestat("r_class_CH_ctr");
				break;
			case DNS_QCLASS_HS:
				dnsinflux_inc_remotestat("r_class_HS_ctr");
				break;
			case DNS_QCLASS_ANY:
				dnsinflux_inc_remotestat("r_class_ANY_ctr");
				break;
			default:
				dnsinflux_inc_remotestat("r_class_UNKNOWN_ctr");
			}

			/* Log answer type */
			switch(answer_it->type)
			{
			case DNS_QTYPE_A:
				dnsinflux_inc_remotestat("r_type_A_ctr");
				break;
			case DNS_QTYPE_AAAA:
				dnsinflux_inc_remotestat("r_type_AAAA_ctr");
				break;
			case DNS_QTYPE_AFSDB:
				dnsinflux_inc_remotestat("r_type_AFSDB_ctr");
				break;
			case DNS_QTYPE_APL:
				dnsinflux_inc_remotestat("r_type_APL_ctr");
				break;
			case DNS_QTYPE_CAA:
				dnsinflux_inc_remotestat("r_type_CAA_ctr");
				break;
			case DNS_QTYPE_CERT:
				dnsinflux_inc_remotestat("r_type_CERT_ctr");
				break;
			case DNS_QTYPE_CNAME:
				dnsinflux_inc_remotestat("r_type_CNAME_ctr");
				break;
			case DNS_QTYPE_DHCID:
				dnsinflux_inc_remotestat("r_type_DHCID_ctr");
				break;
			case DNS_QTYPE_DLV:
				dnsinflux_inc_remotestat("r_type_DLV_ctr");
				break;
			case DNS_QTYPE_DNAME:
				dnsinflux_inc_remotestat("r_type_DNAME_ctr");
				break;
			case DNS_QTYPE_DNSKEY:
				dnsinflux_inc_remotestat("r_type_DNSKEY_ctr");
				break;
			case DNS_QTYPE_DS:
				dnsinflux_inc_remotestat("r_type_DS_ctr");
				break;
			case DNS_QTYPE_HIP:
				dnsinflux_inc_remotestat("r_type_HIP_ctr");
				break;
			case DNS_QTYPE_IPSECKEY:
				dnsinflux_inc_remotestat("r_type_IPSECKEY_ctr");
				break;
			case DNS_QTYPE_KEY:
				dnsinflux_inc_remotestat("r_type_KEY_ctr");
				break;
			case DNS_QTYPE_KX:
				dnsinflux_inc_remotestat("r_type_KX_ctr");
				break;
			case DNS_QTYPE_LOC:
				dnsinflux_inc_remotestat("r_type_LOC_ctr");
				break;
			case DNS_QTYPE_MX:
				dnsinflux_inc_remotestat("r_type_MX_ctr");
				break;
			case DNS_QTYPE_NAPTR:
				dnsinflux_inc_remotestat("r_type_NAPTR_ctr");
				break;
			case DNS_QTYPE_NS:
				dnsinflux_inc_remotestat("r_type_NS_ctr");
				break;
			case DNS_QTYPE_NSEC:
				dnsinflux_inc_remotestat("r_type_NSEC_ctr");
				break;
			case DNS_QTYPE_NSEC3:
				dnsinflux_inc_remotestat("r_type_NSEC3_ctr");
				break;
			case DNS_QTYPE_NSEC3PARAM:
				dnsinflux_inc_remotestat("r_type_NSEC3PARAM_ctr");
				break;
			case DNS_QTYPE_PTR:
				dnsinflux_inc_remotestat("r_type_PTR_ctr");
				break;
			case DNS_QTYPE_RRSIG:
				dnsinflux_inc_remotestat("r_type_RRSIG_ctr");
				break;
			case DNS_QTYPE_RP:
				dnsinflux_inc_remotestat("r_type_RP_ctr");
				break;
			case DNS_QTYPE_SIG:
				dnsinflux_inc_remotestat("r_type_SIG_ctr");
				break;
			case DNS_QTYPE_SOA:
				dnsinflux_inc_remotestat("r_type_SOA_ctr");
				break;
			case DNS_QTYPE_SPF:
				dnsinflux_inc_remotestat("r_type_SPF_ctr");
				break;
			case DNS_QTYPE_SRV:
				dnsinflux_inc_remotestat("r_type_SRV_ctr");
				break;
			case DNS_QTYPE_SSHFP:
				dnsinflux_inc_remotestat("r_type_SSHFP_ctr");
				break;
			case DNS_QTYPE_TA:
				dnsinflux_inc_remotestat("r_type_TA_ctr");
				break;
			case DNS_QTYPE_TKEY:
				dnsinflux_inc_remotestat("r_type_TKEY_ctr");
				break;
			case DNS_QTYPE_TLSA:
				dnsinflux_inc_remotestat("r_type_TLSA_ctr");
				break;
			case DNS_QTYPE_TSIG:
				dnsinflux_inc_remotestat("r_type_TSIG_ctr");
				break;
			case DNS_QTYPE_TXT:
				dnsinflux_inc_remotestat("r_type_TXT_ctr");
				break;
			case DNS_QTYPE_ANY:
				dnsinflux_inc_remotestat("r_type_ANY_ctr");
				break;
			case DNS_QTYPE_AXFR:
				dnsinflux_inc_remotestat("r_type_AXFR_ctr");
				break;
			case DNS_QTYPE_IXFR:
				dnsinflux_inc_remotestat("r_type_IXFR_ctr");
				break;
			case DNS_QTYPE_OPT:
				dnsinflux_inc_remotestat("r_type_OPT_ctr");
				break;
			default:
				dnsinflux_inc_remotestat("r_type_UNKNOWN_ctr");
			}
		}

		/* Log packet flags */
		if (dns_packet->aa_flag)
		{
			dnsinflux_inc_remotestat("r_aa_set_ctr");
		}

		if (dns_packet->tc_flag)
		{
			dnsinflux_inc_remotestat("r_tc_set_ctr");
		}

		if (dns_packet->rd_flag)
		{
			dnsinflux_inc_remotestat("r_rd_set_ctr");
		}
		
		if (dns_packet->ra_flag)
		{
			dnsinflux_inc_remotestat("r_ra_set_ctr");
		}

		if (dns_packet->ad_flag)
		{
			dnsinflux_inc_remotestat("r_ad_set_ctr");
		}

		if (dns_packet->cd_flag)
		{
			dnsinflux_inc_remotestat("r_cd_set_ctr");
		}

		/* Log EDNS0 information */
		if (dns_packet->has_edns0)
		{
			dnsinflux_inc_remotestat("r_has_edns0_ctr");

			if (dns_packet->edns0_do)
			{
				dnsinflux_inc_remotestat("r_edns0_do_set_ctr");
			}
			else
			{
				dnsinflux_inc_remotestat("r_edns0_do_unset_ctr");
			}

			if (dns_packet->has_edns0_client_subnet)
			{
				dnsinflux_inc_remotestat("r_edns0_has_ecs_ctr");
			}
			else
			{
				dnsinflux_inc_remotestat("r_edns0_has_no_ecs_ctr");
			}
		}
		else
		{
			dnsinflux_inc_remotestat("r_no_edns0_ctr");
		}

		/* Log response size information */
		rsize = dns_packet->udp_len + (ip_info.ip_type == 4 ? 28 : 48);

		if (rsize <= 512)
		{
			dnsinflux_inc_remotestat("r_rsize_le_512_ctr");
		}
		else if (rsize <= 1280)
		{
			dnsinflux_inc_remotestat("r_rsize_le_1280_ctr");
		}
		else if (rsize <= 1500)
		{
			dnsinflux_inc_remotestat("r_rsize_le_1500_ctr");
		}
		else if (rsize <= 4096)
		{
			dnsinflux_inc_remotestat("r_rsize_le_4096_ctr");
		}
		else
		{
			dnsinflux_inc_remotestat("r_rsize_gt_4096_ctr");
		}

		/* Count RCODEs */
		switch (dns_packet->rcode)
		{
		case DNS_RCODE_NOERROR:
			if (dns_packet->opcode == DNS_OPCODE_NOTIFY)
			{
				/* This was a notification */
				dnsinflux_inc_remotestat("notify_out_ctr");
			}
			else if (dns_packet->answers == NULL)
			{
				int		has_soa_in_auth	= 0;
				int		has_ns_in_auth	= 0;
				int		auth_count	= 0;
				eemo_dns_rr*	aut_it		= NULL;

				LL_FOREACH(dns_packet->authorities, aut_it)
				{
					auth_count++;

					if (aut_it->type == DNS_QTYPE_SOA)
					{
						has_soa_in_auth = 1;
						break;
					}
					else if (aut_it->type == DNS_QTYPE_NS)
					{
						has_ns_in_auth = 1;
						break;
					}
				}

				if (has_soa_in_auth)
				{
					/* This is a NODATA answer */
					dnsinflux_inc_remotestat("r_rcode_nodata_ctr");
				}
				else if (has_ns_in_auth)
				{
					/* This is a referral */
					dnsinflux_inc_remotestat("r_rcode_referral_ctr");
				}
				else
				{
					if (!dns_packet->tc_flag)
					{
						/* The packet isn't truncated, this is weird... */
						DEBUG_MSG("Response for %s (qtype %d) with empty answer section that is not a referral or NODATA answer (answer has %d authority records)", (dns_packet->questions == NULL) ? "<unknown>" : dns_packet->questions->qname, (dns_packet->questions == NULL) ? -1 : dns_packet->questions->qtype, auth_count);

						dnsinflux_inc_remotestat("r_rcode_unknown_ctr");
					}
					else
					{
						/* Truncated, ignore it */
					}
				}
			}
			else
			{
				dnsinflux_inc_remotestat("r_rcode_noerror_ctr");
			}
			break;
		case DNS_RCODE_FORMERR:
			dnsinflux_inc_remotestat("r_rcode_formerr_ctr");
			break;
		case DNS_RCODE_SERVFAIL:
			dnsinflux_inc_remotestat("r_rcode_servfail_ctr");
			break;
		case DNS_RCODE_NXDOMAIN:
			dnsinflux_inc_remotestat("r_rcode_nxdomain_ctr");
			break;
		case DNS_RCODE_NOTIMPL:
			dnsinflux_inc_remotestat("r_rcode_notimpl_ctr");
			break;
		case DNS_RCODE_REFUSED:
			dnsinflux_inc_remotestat("r_rcode_refused_ctr");
			break;
		default:
			dnsinflux_inc_remotestat("r_rcode_unknown_ctr");
			break;
		}

		return ERV_HANDLED;
	}
	else
	{
		return ERV_SKIPPED;
	}
}

/* Handle DNS query/response packets */
eemo_rv dnsinflux_handleqr(eemo_ip_packet_info ip_info, int is_tcp, const eemo_dns_packet* dns_packet)
{
	eemo_rv	rv	= ERV_HANDLED;

	if (dns_packet->qr_flag)
	{
		rv = dnsinflux_handle_r(ip_info, is_tcp, dns_packet);
	}
	else
	{
		rv = dnsinflux_handle_q(ip_info, is_tcp, dns_packet);
	}

	/* Check if we've reached a new day */
	if (next_epoch_day == 0)
	{
		struct tm	printdate;

		next_epoch_day = ((ip_info.ts.tv_sec/86400) * 86400) + 86400;

		gmtime_r(&next_epoch_day, &printdate);

		INFO_MSG("The next day is %02d-%02d-%04d", printdate.tm_mday, printdate.tm_mon+1, printdate.tm_year+1900);
	}

	if (ip_info.ts.tv_sec >= next_epoch_day)
	{
		struct tm	printdate;

		next_epoch_day += 86400;

		gmtime_r(&next_epoch_day, &printdate);

		INFO_MSG("The next day is %02d-%02d-%04d", printdate.tm_mday, printdate.tm_mon+1, printdate.tm_year+1900);

		dnsinflux_set_localstat(QUERIES_YESTERDAY, dnsinflux_get_localstat(QUERIES_TODAY));
		dnsinflux_set_localstat(QUERIES_TODAY, 0);
	}

	/* See if we need to output statistics */
	if (next_stats_output == 0)
	{
		next_stats_output = ((ip_info.ts.tv_sec / di_stats_interval) * di_stats_interval) + di_stats_interval;

		DEBUG_MSG("Next statistics at %u (it is now %u)", next_stats_output, ip_info.ts.tv_sec);
	}

	if (ip_info.ts.tv_sec >= next_stats_output)
	{
		DEBUG_MSG("Flushing statistics");

		dnsinflux_flush_localstats(ip_info.ts.tv_sec);
		dnsinflux_flush_remotestats(ip_info.ts.tv_sec);

		next_stats_output += di_stats_interval;
	}

	return rv;
}

