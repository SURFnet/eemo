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
 * DNS statistics plug-in query counter code
 */

#include "config.h"
#include "eemo.h"
#include "eemo_log.h"
#include "eemo_dnsstats_stats.h"
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

#define IP_ANY	"*"

/* The counters */

/* Query classes */
struct
{
	unsigned long long IN;
	unsigned long long CS;
	unsigned long long CH;
	unsigned long long HS;
	unsigned long long ANY;
	unsigned long long UNSPECIFIED;
	unsigned long long UNKNOWN;
}
qclass_ctr;

/* Query types */
struct
{
	unsigned long long UNSPECIFIED;
	unsigned long long A;
	unsigned long long AAAA;
	unsigned long long AFSDB;
	unsigned long long APL;
	unsigned long long CERT;
	unsigned long long CNAME;
	unsigned long long DHCID;
	unsigned long long DLV;
	unsigned long long DNAME;
	unsigned long long DNSKEY;
	unsigned long long DS;
	unsigned long long HIP;
	unsigned long long IPSECKEY;
	unsigned long long KEY;
	unsigned long long KX;
	unsigned long long LOC;
	unsigned long long MX;
	unsigned long long NAPTR;
	unsigned long long NS;
	unsigned long long NSEC;
	unsigned long long NSEC3;
	unsigned long long NSEC3PARAM;
	unsigned long long PTR;
	unsigned long long RRSIG;
	unsigned long long RP;
	unsigned long long SIG;
	unsigned long long SOA;
	unsigned long long SPF;
	unsigned long long SRV;
	unsigned long long SSHFP;
	unsigned long long TA;
	unsigned long long TKEY;
	unsigned long long TSIG;
	unsigned long long TXT;
	unsigned long long ANY;
	unsigned long long AXFR;
	unsigned long long IXFR;
	unsigned long long OPT;
	unsigned long long UNKNOWN;
}
qtype_ctr;

/* IP types */
struct
{
	unsigned long long V4;
	unsigned long long V6;
}
iptype_ctr;

/* Transmission protocol types */
struct
{
	unsigned long long UDP;
	unsigned long long TCP;
}
proto_ctr;

/* Configuration */
char** 	stat_ips 		= NULL;
int 	stat_ipcount 		= 0;
int	stat_emit_interval	= 0;
char*	stat_file		= NULL;
int	stat_append		= 0;
int	stat_reset		= 1;

/* Statistics file */
FILE*	stat_fp			= NULL;

/* Signal handler for alarms & user signals */
void signal_handler(int signum)
{
	if (signum == SIGUSR1)
	{
		DEBUG_MSG("Received user signal to dump statistics");
	}
	else if (signum == SIGALRM)
	{
		DEBUG_MSG("Received automated alarm to dump statistics");
	}

	/* Open the file for writing if necessary */
	if (!stat_append)
	{
		stat_fp = fopen(stat_file, "w");
	}

	if (stat_fp != NULL)
	{
		/* Write the statistics to the file */
		fprintf(stat_fp, ""
		"qclass_ctr_UNSPECIFIED:%llu "
		"qclass_ctr_IN:%llu "
		"qclass_ctr_CS:%llu "
		"qclass_ctr_CH:%llu "
		"qclass_ctr_HS:%llu "
		"qclass_ctr_ANY:%llu "
		"qclass_ctr_UNKNOWN:%llu "
		"qtype_ctr_UNSPECIFIED:%llu "
		"qtype_ctr_A:%llu "
		"qtype_ctr_AAAA:%llu "
		"qtype_ctr_AFSDB:%llu "
		"qtype_ctr_APL:%llu "
		"qtype_ctr_CERT:%llu "
		"qtype_ctr_CNAME:%llu "
		"qtype_ctr_DHCID:%llu "
		"qtype_ctr_DLV:%llu "
		"qtype_ctr_DNAME:%llu "
		"qtype_ctr_DNSKEY:%llu "
		"qtype_ctr_DS:%llu "
		"qtype_ctr_HIP:%llu "
		"qtype_ctr_IPSECKEY:%llu "
		"qtype_ctr_KEY:%llu "
		"qtype_ctr_KX:%llu "
		"qtype_ctr_LOC:%llu "
		"qtype_ctr_MX:%llu "
		"qtype_ctr_NAPTR:%llu "
		"qtype_ctr_NS:%llu "
		"qtype_ctr_NSEC:%llu "
		"qtype_ctr_NSEC3:%llu "
		"qtype_ctr_NSEC3PARAM:%llu "
		"qtype_ctr_PTR:%llu "
		"qtype_ctr_RRSIG:%llu "
		"qtype_ctr_RP:%llu "
		"qtype_ctr_SIG:%llu "
		"qtype_ctr_SOA:%llu "
		"qtype_ctr_SPF:%llu "
		"qtype_ctr_SRV:%llu "
		"qtype_ctr_SSHFP:%llu "
		"qtype_ctr_TA:%llu "
		"qtype_ctr_TKEY:%llu "
		"qtype_ctr_TSIG:%llu "
		"qtype_ctr_TXT:%llu "
		"qtype_ctr_ANY:%llu "
		"qtype_ctr_AXFR:%llu "
		"qtype_ctr_IXFR:%llu "
		"qtype_ctr_OPT:%llu "
		"qtype_ctr_UNKNOWN:%llu "
		"iptype_ctr_V4:%llu "
		"iptype_ctr_V6:%llu "
		"proto_ctr_TCP:%llu "
		"proto_ctr_UDP:%llu\n",
		qclass_ctr.UNSPECIFIED,
		qclass_ctr.IN,
		qclass_ctr.CS,
		qclass_ctr.CH,
		qclass_ctr.HS,
		qclass_ctr.ANY,
		qclass_ctr.UNKNOWN,
		qtype_ctr.UNSPECIFIED,
		qtype_ctr.A,
		qtype_ctr.AAAA,
		qtype_ctr.AFSDB,
		qtype_ctr.APL,
		qtype_ctr.CERT,
		qtype_ctr.CNAME,
		qtype_ctr.DHCID,
		qtype_ctr.DLV,
		qtype_ctr.DNAME,
		qtype_ctr.DNSKEY,
		qtype_ctr.DS,
		qtype_ctr.HIP,
		qtype_ctr.IPSECKEY,
		qtype_ctr.KEY,
		qtype_ctr.KX,
		qtype_ctr.LOC,
		qtype_ctr.MX,
		qtype_ctr.NAPTR,
		qtype_ctr.NS,
		qtype_ctr.NSEC,
		qtype_ctr.NSEC3,
		qtype_ctr.NSEC3PARAM,
		qtype_ctr.PTR,
		qtype_ctr.RRSIG,
		qtype_ctr.RP,
		qtype_ctr.SIG,
		qtype_ctr.SOA,
		qtype_ctr.SPF,
		qtype_ctr.SRV,
		qtype_ctr.SSHFP,
		qtype_ctr.TA,
		qtype_ctr.TKEY,
		qtype_ctr.TSIG,
		qtype_ctr.TXT,
		qtype_ctr.ANY,
		qtype_ctr.AXFR,
		qtype_ctr.IXFR,
		qtype_ctr.OPT,
		qtype_ctr.UNKNOWN,
		iptype_ctr.V4,
		iptype_ctr.V6,
		proto_ctr.TCP,
		proto_ctr.UDP);

		fflush(stat_fp);

		/* Reset the statistics if necessary */
		if (stat_reset)
		{
			eemo_dnsstats_stats_reset();
		}
	}

	/* Close the file if necessary */
	if (!stat_append && (stat_fp != NULL))
	{
		fclose(stat_fp);
	}

	/* Set the new alarm if necessary */
	if (signum == SIGALRM)
	{
		alarm(stat_emit_interval);
	}
}

/* Reset statistics */
void eemo_dnsstats_stats_reset(void)
{
	memset(&qclass_ctr, 0, sizeof(qclass_ctr));
	memset(&qtype_ctr, 0, sizeof(qtype_ctr));
	memset(&iptype_ctr, 0, sizeof(iptype_ctr));
	memset(&proto_ctr, 0, sizeof(proto_ctr));

	DEBUG_MSG("DNS statistics reset");
}

/* Initialise the DNS query counter module */
void eemo_dnsstats_stats_init(char** ips, int ip_count, int emit_interval, char* stats_file, int append_file, int reset)
{
	int i = 0;

	stat_ips = ips;
	stat_ipcount = ip_count;

	INFO_MSG("Listening to %d IP addresses", stat_ipcount);

	for (i = 0; i < stat_ipcount; i++)
	{
		INFO_MSG("Listening for queries to IP %s", ips[i]);
	}

	stat_emit_interval = emit_interval;

	INFO_MSG("Emitting statistics every %d seconds", emit_interval);

	stat_file = stats_file;

	INFO_MSG("Writing statistics to the file called %s", stat_file);

	stat_append = append_file;

	INFO_MSG("Will %soverwrite the file when new statistics are available", stat_append ? "not " : "");

	stat_reset = reset;

	INFO_MSG("Will %sreset statistics once they have been written to file", stat_reset ? "" : "not ");

	if (stat_append)
	{
		stat_fp = fopen(stat_file, "w");

		if (stat_fp != NULL)
		{
			INFO_MSG("Opened %s to write statistics to", stat_file);
		}
		else
		{
			ERROR_MSG("Failed to open %s for writing", stat_file);
		}
	}

	eemo_dnsstats_stats_reset();
	
	/* Register signal handler */
	signal(SIGUSR1, signal_handler);
	signal(SIGALRM, signal_handler);

	/* Set the alarm */
	alarm(stat_emit_interval);
}

/* Uninitialise the DNS query counter module */
void eemo_dnsstats_stats_uninit(eemo_conf_free_string_array_fn free_strings)
{
	/* Unregister signal handlers */
	alarm(0);
	signal(SIGUSR1, SIG_DFL);
	signal(SIGALRM, SIG_DFL);

	/* Close the file */
	if (stat_append && (stat_fp != NULL))
	{
		fclose(stat_fp);

		DEBUG_MSG("Closed %s", stat_file);
	}
	else
	{
		INFO_MSG("Statistics file %s was not open", stat_file);
	}

	(free_strings)(stat_ips, stat_ipcount);
	free(stat_file);
}

/* Handle DNS query packets and log the statistics */
eemo_rv eemo_dnsstats_stats_handleq(eemo_ip_packet_info ip_info, u_short qclass, u_short qtype, u_short flags, char* qname, int is_tcp)
{
	int i = 0;

	/* Either count all messages or check whether this messages matches any of the IPs we're monitoring */
	if (stat_ipcount > 0)
	{
		int ip_match = 0;
	
		/* Check if this query is directed at the server we're supposed to monitor */
		for (i = 0; i < stat_ipcount; i++)
		{
			if (!strcmp(stat_ips[i], ip_info.ip_dst) || !strcmp(stat_ips[i], IP_ANY))
			{
				ip_match = 1;
				break;
			}
		}
	
		if (!ip_match)
		{
			return ERV_SKIPPED;
		}
	}

	/* Log query class */
	switch(qclass)
	{
	case DNS_QCLASS_UNSPECIFIED:
		qclass_ctr.UNSPECIFIED++;
		break;
	case DNS_QCLASS_IN:
		qclass_ctr.IN++;
		break;
	case DNS_QCLASS_CS:
		qclass_ctr.CS++;
		break;
	case DNS_QCLASS_CH:
		qclass_ctr.CH++;
		break;
	case DNS_QCLASS_HS:
		qclass_ctr.HS++;
		break;
	case DNS_QCLASS_ANY:
		qclass_ctr.ANY++;
		break;
	default:
		qclass_ctr.UNKNOWN++;
	}

	/* Log query type */
	switch(qtype)
	{
	case DNS_QTYPE_UNSPECIFIED:
		qtype_ctr.UNSPECIFIED++;
		break;
	case DNS_QTYPE_A:
		qtype_ctr.A++;
		break;
	case DNS_QTYPE_AAAA:
		qtype_ctr.AAAA++;
		break;
	case DNS_QTYPE_AFSDB:
		qtype_ctr.AFSDB++;
		break;
	case DNS_QTYPE_APL:
		qtype_ctr.APL++;
		break;
	case DNS_QTYPE_CERT:
		qtype_ctr.CERT++;
		break;
	case DNS_QTYPE_CNAME:
		qtype_ctr.CNAME++;
		break;
	case DNS_QTYPE_DHCID:
		qtype_ctr.DHCID++;
		break;
	case DNS_QTYPE_DLV:
		qtype_ctr.DLV++;
		break;
	case DNS_QTYPE_DNAME:
		qtype_ctr.DNAME++;
		break;
	case DNS_QTYPE_DNSKEY:
		qtype_ctr.DNSKEY++;
		break;
	case DNS_QTYPE_DS:
		qtype_ctr.DS++;
		break;
	case DNS_QTYPE_HIP:
		qtype_ctr.HIP++;
		break;
	case DNS_QTYPE_IPSECKEY:
		qtype_ctr.IPSECKEY++;
		break;
	case DNS_QTYPE_KEY:
		qtype_ctr.KEY++;
		break;
	case DNS_QTYPE_KX:
		qtype_ctr.KX++;
		break;
	case DNS_QTYPE_LOC:
		qtype_ctr.LOC++;
		break;
	case DNS_QTYPE_MX:
		qtype_ctr.MX++;
		break;
	case DNS_QTYPE_NAPTR:
		qtype_ctr.NAPTR++;
		break;
	case DNS_QTYPE_NS:
		qtype_ctr.NS++;
		break;
	case DNS_QTYPE_NSEC:
		qtype_ctr.NSEC++;
		break;
	case DNS_QTYPE_NSEC3:
		qtype_ctr.NSEC3++;
		break;
	case DNS_QTYPE_NSEC3PARAM:
		qtype_ctr.NSEC3PARAM++;
		break;
	case DNS_QTYPE_PTR:
		qtype_ctr.PTR++;
		break;
	case DNS_QTYPE_RRSIG:
		qtype_ctr.RRSIG++;
		break;
	case DNS_QTYPE_RP:
		qtype_ctr.RP++;
		break;
	case DNS_QTYPE_SIG:
		qtype_ctr.SIG++;
		break;
	case DNS_QTYPE_SOA:
		qtype_ctr.SOA++;
		break;
	case DNS_QTYPE_SPF:
		qtype_ctr.SPF++;
		break;
	case DNS_QTYPE_SRV:
		qtype_ctr.SRV++;
		break;
	case DNS_QTYPE_SSHFP:
		qtype_ctr.SSHFP++;
		break;
	case DNS_QTYPE_TA:
		qtype_ctr.TA++;
		break;
	case DNS_QTYPE_TKEY:
		qtype_ctr.TKEY++;
		break;
	case DNS_QTYPE_TSIG:
		qtype_ctr.TSIG++;
		break;
	case DNS_QTYPE_TXT:
		qtype_ctr.TXT++;
		break;
	case DNS_QTYPE_ANY:
		qtype_ctr.ANY++;
		break;
	case DNS_QTYPE_AXFR:
		qtype_ctr.AXFR++;
		break;
	case DNS_QTYPE_IXFR:
		qtype_ctr.IXFR++;
		break;
	case DNS_QTYPE_OPT:
		qtype_ctr.OPT++;
		break;
	default:
		qtype_ctr.UNKNOWN++;
	}

	/* Log IP type */
	switch(ip_info.ip_type)
	{
	case IP_TYPE_V4:
		iptype_ctr.V4++;
		break;
	case IP_TYPE_V6:
		iptype_ctr.V6++;
		break;
	}

	/* Log protocol type */
	if (is_tcp)
	{
		proto_ctr.TCP++;
	}
	else
	{
		proto_ctr.UDP++;
	}

	return ERV_HANDLED;
}

