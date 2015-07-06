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
 * DNS statistics plug-in query counter code
 */

#include "config.h"
#include "eemo.h"
#include "eemo_log.h"
#include "eemo_dnszabbix_stats.h"
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

/* Response classes */
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
rclass_ctr;

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

/* Response types */
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
rtype_ctr;

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

/* EDNS0 */
struct
{
	unsigned long long EDNS0_NO;
	unsigned long long EDNS0_BELOW_512;
	unsigned long long EDNS0_512_TO_999;
	unsigned long long EDNS0_1000_TO_1499;
	unsigned long long EDNS0_1500_TO_1999;
	unsigned long long EDNS0_2000_TO_2499;
	unsigned long long EDNS0_2500_TO_2999;
	unsigned long long EDNS0_3000_TO_3499;
	unsigned long long EDNS0_3500_TO_3999;
	unsigned long long EDNS0_4000_TO_4499;
	unsigned long long EDNS0_ABOVE_4500;
	unsigned long long EDNS0_DO_SET;
	unsigned long long EDNS0_DO_UNSET;
	unsigned long long EDNS0_W_ECS;
	unsigned long long EDNS0_WO_ECS;
	unsigned long long EDNS0_EXP_OPT;
}
edns0_ctr;

/* Response size */
struct
{
	unsigned long long RSIZE_BELOW_512;
	unsigned long long RSIZE_512_TO_1023;
	unsigned long long RSIZE_1024_TO_1535;
	unsigned long long RSIZE_1536_TO_2047;
	unsigned long long RSIZE_2048_TO_2559;
	unsigned long long RSIZE_2560_TO_3071;
	unsigned long long RSIZE_3072_TO_3583;
	unsigned long long RSIZE_3584_TO_4095;
	unsigned long long RSIZE_ABOVE_4096;
	unsigned long long RSIZE_TOTAL;
	unsigned long long RSIZE_COUNTED;
}
rsize_ctr;

/* Response codes */
struct
{
	unsigned long long RCODE_NOERROR;
	unsigned long long RCODE_NODATA;
	unsigned long long RCODE_REFERRAL;
	unsigned long long RCODE_FORMERR;
	unsigned long long RCODE_SERVFAIL;
	unsigned long long RCODE_NXDOMAIN;
	unsigned long long RCODE_NOTIMPL;
	unsigned long long RCODE_REFUSED;
	unsigned long long RCODE_UNKNOWN;
}
rcode_ctr;

/* Response fragmentation */
struct
{
	unsigned long long R_FRAG;
	unsigned long long R_UNFRAG;
}
rfrag_ctr;

/* Response flags */
struct
{
	unsigned long long RFLAG_TC;
}
rflags_ctr;

/* Configuration */
char** 	stat_ips 		= NULL;
int 	stat_ipcount 		= 0;
char*	stat_file		= NULL;
char*	zabbix_host_id		= NULL;

/* Statistics file */
FILE*	stat_fp			= NULL;

/* Write statistics to file */
void write_stats(void)
{
	unsigned long long	EDNS0_TOTAL 		= 0;
	float 			EDNS0_PCT_ON	 	= 0.0f;
	float 			EDNS0_PCT_OFF		= 0.0f;
	float			EDNS0_PCT_LT_512	= 0.0f;
	float			EDNS0_PCT_512_999	= 0.0f;
	float			EDNS0_PCT_1000_1499	= 0.0f;
	float			EDNS0_PCT_1500_1999	= 0.0f;
	float			EDNS0_PCT_2000_2499	= 0.0f;
	float			EDNS0_PCT_2500_2999	= 0.0f;
	float			EDNS0_PCT_3000_3499	= 0.0f;
	float			EDNS0_PCT_3500_3999	= 0.0f;
	float			EDNS0_PCT_4000_4499	= 0.0f;
	float			EDNS0_PCT_GT_4500	= 0.0f;
	float			EDNS0_PCT_DO_SET	= 0.0f;
	float			EDNS0_PCT_DO_UNSET	= 0.0f;
	float			EDNS0_PCT_WO_ECS	= 0.0f;
	float			EDNS0_PCT_W_ECS		= 0.0f;
	unsigned long long	QUERY_TOTAL		= 0;
	float			R_FRAG_PCT		= 0.0f;
	float			R_UNFRAG_PCT		= 0.0f;
	unsigned long long	R_FRAG_UNFRAG_TOTAL	= 0;
	float			RSIZE_PCT_LT_512	= 0.0f;
	float			RSIZE_PCT_512_1023	= 0.0f;
	float			RSIZE_PCT_1024_1535	= 0.0f;
	float			RSIZE_PCT_1536_2047	= 0.0f;
	float			RSIZE_PCT_2048_2559	= 0.0f;
	float			RSIZE_PCT_2560_3071	= 0.0f;
	float			RSIZE_PCT_3072_3583	= 0.0f;
	float			RSIZE_PCT_3584_4095	= 0.0f;
	float			RSIZE_PCT_GT_4096	= 0.0f;
	float			RSIZE_AVERAGE		= 0.0f;
	
	/* Open the file for writing */
	stat_fp = fopen(stat_file, "w");

	if (stat_fp != NULL)
	{
		/* Calculate the EDNS0 percentages */
		EDNS0_TOTAL =	(edns0_ctr.EDNS0_BELOW_512 +
				 edns0_ctr.EDNS0_512_TO_999 +
				 edns0_ctr.EDNS0_1000_TO_1499 +
				 edns0_ctr.EDNS0_1500_TO_1999 +
				 edns0_ctr.EDNS0_2000_TO_2499 +
				 edns0_ctr.EDNS0_2500_TO_2999 +
				 edns0_ctr.EDNS0_3000_TO_3499 +
				 edns0_ctr.EDNS0_3500_TO_3999 +
				 edns0_ctr.EDNS0_4000_TO_4499 +
				 edns0_ctr.EDNS0_ABOVE_4500);
		
		QUERY_TOTAL =	(iptype_ctr.V4 + iptype_ctr.V6);

		/* Prevent division by zero! */
		if (QUERY_TOTAL > 0)
		{
			EDNS0_PCT_ON		= (EDNS0_TOTAL * 100.0f)				/ (float) QUERY_TOTAL;
			EDNS0_PCT_OFF		= (((float) QUERY_TOTAL - EDNS0_TOTAL) * 100.0f) 	/ (float) QUERY_TOTAL;
		}

		/*  Prevent division by zero! */
		if (EDNS0_TOTAL > 0)
		{
			EDNS0_PCT_LT_512	= (edns0_ctr.EDNS0_BELOW_512 * 100.0f)			/ (float) EDNS0_TOTAL;
			EDNS0_PCT_512_999	= (edns0_ctr.EDNS0_512_TO_999 * 100.0f)			/ (float) EDNS0_TOTAL;
			EDNS0_PCT_1000_1499	= (edns0_ctr.EDNS0_1000_TO_1499 * 100.0f)		/ (float) EDNS0_TOTAL;
			EDNS0_PCT_1500_1999	= (edns0_ctr.EDNS0_1500_TO_1999 * 100.0f)		/ (float) EDNS0_TOTAL;
			EDNS0_PCT_2000_2499	= (edns0_ctr.EDNS0_2000_TO_2499 * 100.0f)		/ (float) EDNS0_TOTAL;
			EDNS0_PCT_2500_2999	= (edns0_ctr.EDNS0_2500_TO_2999 * 100.0f)		/ (float) EDNS0_TOTAL;
			EDNS0_PCT_3000_3499	= (edns0_ctr.EDNS0_3000_TO_3499 * 100.0f)		/ (float) EDNS0_TOTAL;
			EDNS0_PCT_3500_3999	= (edns0_ctr.EDNS0_3500_TO_3999 * 100.0f)		/ (float) EDNS0_TOTAL;
			EDNS0_PCT_4000_4499	= (edns0_ctr.EDNS0_4000_TO_4499 * 100.0f)		/ (float) EDNS0_TOTAL;
			EDNS0_PCT_GT_4500	= (edns0_ctr.EDNS0_ABOVE_4500 * 100.0f)			/ (float) EDNS0_TOTAL;
			EDNS0_PCT_DO_SET	= (edns0_ctr.EDNS0_DO_SET * 100.0f)			/ (float) EDNS0_TOTAL;
			EDNS0_PCT_DO_UNSET	= (edns0_ctr.EDNS0_DO_UNSET * 100.0f)			/ (float) EDNS0_TOTAL;
			EDNS0_PCT_W_ECS		= (edns0_ctr.EDNS0_W_ECS * 100.0f)			/ (float) EDNS0_TOTAL;
			EDNS0_PCT_WO_ECS	= (edns0_ctr.EDNS0_WO_ECS * 100.0f)			/ (float) EDNS0_TOTAL;
		}

		/* Calculate fragmentation percentages */
		R_FRAG_UNFRAG_TOTAL = (rfrag_ctr.R_FRAG + rfrag_ctr.R_UNFRAG);

		if (R_FRAG_UNFRAG_TOTAL > 0)
		{
			R_FRAG_PCT		= (rfrag_ctr.R_FRAG * 100.0f)			/ (float) R_FRAG_UNFRAG_TOTAL;
			R_UNFRAG_PCT		= (rfrag_ctr.R_UNFRAG * 100.0f)			/ (float) R_FRAG_UNFRAG_TOTAL;
		}

		/* Calculate bucketed response size percentages */
		if (rsize_ctr.RSIZE_COUNTED > 0)
		{
			RSIZE_PCT_LT_512	= (rsize_ctr.RSIZE_BELOW_512 * 100.0f)		/ (float) rsize_ctr.RSIZE_COUNTED;
			RSIZE_PCT_512_1023	= (rsize_ctr.RSIZE_512_TO_1023 * 100.0f)	/ (float) rsize_ctr.RSIZE_COUNTED;
			RSIZE_PCT_1024_1535	= (rsize_ctr.RSIZE_1024_TO_1535 * 100.0f)	/ (float) rsize_ctr.RSIZE_COUNTED;
			RSIZE_PCT_1536_2047	= (rsize_ctr.RSIZE_1536_TO_2047 * 100.0f)	/ (float) rsize_ctr.RSIZE_COUNTED;
			RSIZE_PCT_2048_2559	= (rsize_ctr.RSIZE_2048_TO_2559 * 100.0f)	/ (float) rsize_ctr.RSIZE_COUNTED;
			RSIZE_PCT_2560_3071	= (rsize_ctr.RSIZE_2560_TO_3071 * 100.0f)	/ (float) rsize_ctr.RSIZE_COUNTED;
			RSIZE_PCT_3072_3583	= (rsize_ctr.RSIZE_3072_TO_3583 * 100.0f)	/ (float) rsize_ctr.RSIZE_COUNTED;
			RSIZE_PCT_3584_4095	= (rsize_ctr.RSIZE_3584_TO_4095 * 100.0f)	/ (float) rsize_ctr.RSIZE_COUNTED;
			RSIZE_PCT_GT_4096	= (rsize_ctr.RSIZE_ABOVE_4096 * 100.0f)		/ (float) rsize_ctr.RSIZE_COUNTED;
		}

		/* Calculate average response size over measurement period */
		if (rsize_ctr.RSIZE_COUNTED > 0)
		{
			RSIZE_AVERAGE = (float) ((float) rsize_ctr.RSIZE_TOTAL / (float) rsize_ctr.RSIZE_COUNTED);
		}

#define EMIT_INT(key,val) fprintf(stat_fp, "%s %s %llu\n", zabbix_host_id, key, val)
#define EMIT_PCT(key,val) fprintf(stat_fp, "%s %s %0.2f\n", zabbix_host_id, key, val)

		EMIT_INT("qclass.ctr.UNSPECIFIED", 	qclass_ctr.UNSPECIFIED);
		EMIT_INT("qclass.ctr.IN",		qclass_ctr.IN);
		EMIT_INT("qclass.ctr.CS",		qclass_ctr.CS);
		EMIT_INT("qclass.ctr.CH",		qclass_ctr.CH);
		EMIT_INT("qclass.ctr.HS",		qclass_ctr.HS);
		EMIT_INT("qclass.ctr.ANY",		qclass_ctr.ANY);
		EMIT_INT("qclass.ctr.UNKNOWN",		qclass_ctr.UNKNOWN);
		EMIT_INT("qtype.ctr.UNSPECIFIED", 	qtype_ctr.UNSPECIFIED);
		EMIT_INT("qtype.ctr.A", 		qtype_ctr.A);
		EMIT_INT("qtype.ctr.AAAA", 		qtype_ctr.AAAA);
		EMIT_INT("qtype.ctr.AFSDB", 		qtype_ctr.AFSDB);
		EMIT_INT("qtype.ctr.APL", 		qtype_ctr.APL);
		EMIT_INT("qtype.ctr.CERT",		qtype_ctr.CERT);
		EMIT_INT("qtype.ctr.CNAME", 		qtype_ctr.CNAME);
		EMIT_INT("qtype.ctr.DHCID",		qtype_ctr.DHCID);
		EMIT_INT("qtype.ctr.DLV", 		qtype_ctr.DLV);
		EMIT_INT("qtype.ctr.DNAME", 		qtype_ctr.DNAME);
		EMIT_INT("qtype.ctr.DNSKEY", 		qtype_ctr.DNSKEY);
		EMIT_INT("qtype.ctr.DS", 		qtype_ctr.DS);
		EMIT_INT("qtype.ctr.HIP", 		qtype_ctr.HIP);
		EMIT_INT("qtype.ctr.IPSECKEY", 		qtype_ctr.IPSECKEY);
		EMIT_INT("qtype.ctr.KEY", 		qtype_ctr.KEY);
		EMIT_INT("qtype.ctr.KX", 		qtype_ctr.KX);
		EMIT_INT("qtype.ctr.LOC", 		qtype_ctr.LOC);
		EMIT_INT("qtype.ctr.MX", 		qtype_ctr.MX);
		EMIT_INT("qtype.ctr.NAPTR", 		qtype_ctr.NAPTR);
		EMIT_INT("qtype.ctr.NS", 		qtype_ctr.NS);
		EMIT_INT("qtype.ctr.NSEC", 		qtype_ctr.NSEC);
		EMIT_INT("qtype.ctr.NSEC3", 		qtype_ctr.NSEC3);
		EMIT_INT("qtype.ctr.NSEC3PARAM", 	qtype_ctr.NSEC3PARAM);
		EMIT_INT("qtype.ctr.PTR", 		qtype_ctr.PTR);
		EMIT_INT("qtype.ctr.RRSIG", 		qtype_ctr.RRSIG);
		EMIT_INT("qtype.ctr.RP", 		qtype_ctr.RP);
		EMIT_INT("qtype.ctr.SIG", 		qtype_ctr.SIG);
		EMIT_INT("qtype.ctr.SOA", 		qtype_ctr.SOA);
		EMIT_INT("qtype.ctr.SPF", 		qtype_ctr.SPF);
		EMIT_INT("qtype.ctr.SRV", 		qtype_ctr.SRV);
		EMIT_INT("qtype.ctr.SSHFP", 		qtype_ctr.SSHFP);
		EMIT_INT("qtype.ctr.TA", 		qtype_ctr.TA);
		EMIT_INT("qtype.ctr.TKEY", 		qtype_ctr.TKEY);
		EMIT_INT("qtype.ctr.TSIG", 		qtype_ctr.TSIG);
		EMIT_INT("qtype.ctr.TXT", 		qtype_ctr.TXT);
		EMIT_INT("qtype.ctr.ANY", 		qtype_ctr.ANY);
		EMIT_INT("qtype.ctr.AXFR", 		qtype_ctr.AXFR);
		EMIT_INT("qtype.ctr.IXFR", 		qtype_ctr.IXFR);
		EMIT_INT("qtype.ctr.OPT", 		qtype_ctr.OPT);
		EMIT_INT("qtype.ctr.UNKNOWN", 		qtype_ctr.UNKNOWN);
		EMIT_INT("iptype.ctr.V4",		iptype_ctr.V4);
		EMIT_INT("iptype.ctr.V6",		iptype_ctr.V6);
		EMIT_INT("proto.ctr.TCP",		proto_ctr.TCP);
		EMIT_INT("proto.ctr.UDP",		proto_ctr.UDP);
		EMIT_INT("edns0.ctr.NO",		edns0_ctr.EDNS0_NO);
		EMIT_INT("edns0.ctr.below512",		edns0_ctr.EDNS0_BELOW_512);
		EMIT_INT("edns0.ctr.512to999",		edns0_ctr.EDNS0_512_TO_999);
		EMIT_INT("edns0.ctr.1000to1499",	edns0_ctr.EDNS0_1000_TO_1499);
		EMIT_INT("edns0.ctr.1500to1999",	edns0_ctr.EDNS0_1500_TO_1999);
		EMIT_INT("edns0.ctr.2000to2499",	edns0_ctr.EDNS0_2000_TO_2499);
		EMIT_INT("edns0.ctr.2500to2999",	edns0_ctr.EDNS0_2500_TO_2999);
		EMIT_INT("edns0.ctr.3000to3499",	edns0_ctr.EDNS0_3000_TO_3499);
		EMIT_INT("edns0.ctr.3500to3999",	edns0_ctr.EDNS0_3500_TO_3999);
		EMIT_INT("edns0.ctr.4000to4499",	edns0_ctr.EDNS0_4000_TO_4499);
		EMIT_INT("edns0.ctr.above4500",		edns0_ctr.EDNS0_ABOVE_4500);
		EMIT_INT("edns0.ctr.do_set",		edns0_ctr.EDNS0_DO_SET);
		EMIT_INT("edns0.ctr.do_unset",		edns0_ctr.EDNS0_DO_UNSET);
		EMIT_INT("edns0.ctr.wo_ecs",		edns0_ctr.EDNS0_WO_ECS);
		EMIT_INT("edns0.ctr.w_ecs",		edns0_ctr.EDNS0_W_ECS);
		EMIT_INT("edns0.ctr.exp_opt",		edns0_ctr.EDNS0_EXP_OPT);
		EMIT_INT("edns0.ctr.total",		EDNS0_TOTAL);
		EMIT_PCT("edns0.pct.on", 		EDNS0_PCT_ON);
		EMIT_PCT("edns0.pct.off", 		EDNS0_PCT_OFF);
		EMIT_PCT("edns0.pct.below512", 		EDNS0_PCT_LT_512);
		EMIT_PCT("edns0.pct.512to999", 		EDNS0_PCT_512_999);
		EMIT_PCT("edns0.pct.1000to1499", 	EDNS0_PCT_1000_1499);
		EMIT_PCT("edns0.pct.1500to1999", 	EDNS0_PCT_1500_1999);
		EMIT_PCT("edns0.pct.2000to2499", 	EDNS0_PCT_2000_2499);
		EMIT_PCT("edns0.pct.2500to2999", 	EDNS0_PCT_2500_2999);
		EMIT_PCT("edns0.pct.3000to3499", 	EDNS0_PCT_3000_3499);
		EMIT_PCT("edns0.pct.3500to3999", 	EDNS0_PCT_3500_3999);
		EMIT_PCT("edns0.pct.4000to4499", 	EDNS0_PCT_4000_4499);
		EMIT_PCT("edns0.pct.above4500", 	EDNS0_PCT_GT_4500);
		EMIT_PCT("edns0.pct.do_set", 		EDNS0_PCT_DO_SET);
		EMIT_PCT("edns0.pct.do_unset", 		EDNS0_PCT_DO_UNSET);
		EMIT_PCT("edns0.pct.wo_ecs", 		EDNS0_PCT_WO_ECS);
		EMIT_PCT("edns0.pct.w_ecs", 		EDNS0_PCT_W_ECS);
		EMIT_INT("query.ctr.total",		QUERY_TOTAL);
		EMIT_INT("rclass.ctr.UNSPECIFIED", 	rclass_ctr.UNSPECIFIED);
		EMIT_INT("rclass.ctr.IN", 		rclass_ctr.IN);
		EMIT_INT("rclass.ctr.CS", 		rclass_ctr.CS);
		EMIT_INT("rclass.ctr.CH",		rclass_ctr.CH);
		EMIT_INT("rclass.ctr.HS", 		rclass_ctr.HS);
		EMIT_INT("rclass.ctr.ANY", 		rclass_ctr.ANY);
		EMIT_INT("rclass.ctr.UNKNOWN", 		rclass_ctr.UNKNOWN);
		EMIT_INT("rtype.ctr.UNSPECIFIED", 	rtype_ctr.UNSPECIFIED);
		EMIT_INT("rtype.ctr.A", 		rtype_ctr.A);
		EMIT_INT("rtype.ctr.AAAA", 		rtype_ctr.AAAA);
		EMIT_INT("rtype.ctr.AFSDB", 		rtype_ctr.AFSDB);
		EMIT_INT("rtype.ctr.APL", 		rtype_ctr.APL);
		EMIT_INT("rtype.ctr.CERT",		rtype_ctr.CERT);
		EMIT_INT("rtype.ctr.CNAME",		rtype_ctr.CNAME);
		EMIT_INT("rtype.ctr.DHCID",		rtype_ctr.DHCID);
		EMIT_INT("rtype.ctr.DLV",		rtype_ctr.DLV);
		EMIT_INT("rtype.ctr.DNAME",		rtype_ctr.DNAME);
		EMIT_INT("rtype.ctr.DNSKEY",		rtype_ctr.DNSKEY);
		EMIT_INT("rtype.ctr.DS",		rtype_ctr.DS);
		EMIT_INT("rtype.ctr.HIP",		rtype_ctr.HIP);
		EMIT_INT("rtype.ctr.IPSECKEY",		rtype_ctr.IPSECKEY);
		EMIT_INT("rtype.ctr.KEY",		rtype_ctr.KEY);
		EMIT_INT("rtype.ctr.KX",		rtype_ctr.KX);
		EMIT_INT("rtype.ctr.LOC",		rtype_ctr.LOC);
		EMIT_INT("rtype.ctr.MX",		rtype_ctr.MX);
		EMIT_INT("rtype.ctr.NAPTR",		rtype_ctr.NAPTR);
		EMIT_INT("rtype.ctr.NS",		rtype_ctr.NS);
		EMIT_INT("rtype.ctr.NSEC",		rtype_ctr.NSEC);
		EMIT_INT("rtype.ctr.NSEC3",		rtype_ctr.NSEC3);
		EMIT_INT("rtype.ctr.NSEC3PARAM",	rtype_ctr.NSEC3PARAM);
		EMIT_INT("rtype.ctr.PTR",		rtype_ctr.PTR);
		EMIT_INT("rtype.ctr.RRSIG",		rtype_ctr.RRSIG);
		EMIT_INT("rtype.ctr.RP",		rtype_ctr.RP);
		EMIT_INT("rtype.ctr.SIG",		rtype_ctr.SIG);
		EMIT_INT("rtype.ctr.SOA",		rtype_ctr.SOA);
		EMIT_INT("rtype.ctr.SPF",		rtype_ctr.SPF);
		EMIT_INT("rtype.ctr.SRV",		rtype_ctr.SRV);
		EMIT_INT("rtype.ctr.SSHFP",		rtype_ctr.SSHFP);
		EMIT_INT("rtype.ctr.TA",		rtype_ctr.TA);
		EMIT_INT("rtype.ctr.TKEY",		rtype_ctr.TKEY);
		EMIT_INT("rtype.ctr.TSIG",		rtype_ctr.TSIG);
		EMIT_INT("rtype.ctr.TXT",		rtype_ctr.TXT);
		EMIT_INT("rtype.ctr.ANY",		rtype_ctr.ANY);
		EMIT_INT("rtype.ctr.AXFR",		rtype_ctr.AXFR);
		EMIT_INT("rtype.ctr.IXFR",		rtype_ctr.IXFR);
		EMIT_INT("rtype.ctr.OPT",		rtype_ctr.OPT);
		EMIT_INT("rtype.ctr.UNKNOWN",		rtype_ctr.UNKNOWN);
		EMIT_INT("rsize.ctr.below512",		rsize_ctr.RSIZE_BELOW_512);
		EMIT_INT("rsize.ctr.512to1024",		rsize_ctr.RSIZE_512_TO_1023);
		EMIT_INT("rsize.ctr.1024to1535",	rsize_ctr.RSIZE_1024_TO_1535);
		EMIT_INT("rsize.ctr.1536to2047",	rsize_ctr.RSIZE_1536_TO_2047);
		EMIT_INT("rsize.ctr.2048to2559",	rsize_ctr.RSIZE_2048_TO_2559);
		EMIT_INT("rsize.ctr.2560to3071",	rsize_ctr.RSIZE_2560_TO_3071);
		EMIT_INT("rsize.ctr.3072to3583",	rsize_ctr.RSIZE_3072_TO_3583);
		EMIT_INT("rsize.ctr.3584to4095",	rsize_ctr.RSIZE_3584_TO_4095);
		EMIT_INT("rsize.ctr.above4096",		rsize_ctr.RSIZE_ABOVE_4096);
		EMIT_INT("rsize.ctr.total",		rsize_ctr.RSIZE_TOTAL);
		EMIT_INT("rsize.ctr.counted",		rsize_ctr.RSIZE_COUNTED);
		EMIT_INT("rcode.ctr.NOERROR",		rcode_ctr.RCODE_NOERROR);
		EMIT_INT("rcode.ctr.NODATA",		rcode_ctr.RCODE_NODATA);
		EMIT_INT("rcode.ctr.REFERRAL",		rcode_ctr.RCODE_REFERRAL);
		EMIT_INT("rcode.ctr.FORMERR",		rcode_ctr.RCODE_FORMERR);
		EMIT_INT("rcode.ctr.SERVFAIL",		rcode_ctr.RCODE_SERVFAIL);
		EMIT_INT("rcode.ctr.NXDOMAIN",		rcode_ctr.RCODE_NXDOMAIN);
		EMIT_INT("rcode.ctr.NOTIMPL",		rcode_ctr.RCODE_NOTIMPL);
		EMIT_INT("rcode.ctr.REFUSED",		rcode_ctr.RCODE_REFUSED);
		EMIT_INT("rcode.ctr.UNKNOWN",		rcode_ctr.RCODE_UNKNOWN);
		EMIT_INT("rfrag.ctr.frag",		rfrag_ctr.R_FRAG);
		EMIT_INT("rfrag.ctr.unfrag",		rfrag_ctr.R_UNFRAG);
		EMIT_PCT("rfrag.pct.frag",		R_FRAG_PCT);
		EMIT_PCT("rfrag.pct.unfrag",		R_UNFRAG_PCT);
		EMIT_INT("rfrag.ctr.total",		R_FRAG_UNFRAG_TOTAL);
		EMIT_PCT("rsize.pct.below512",		RSIZE_PCT_LT_512);
		EMIT_PCT("rsize.pct.512to1023",		RSIZE_PCT_512_1023);
		EMIT_PCT("rsize.pct.1024to1535",	RSIZE_PCT_1024_1535);
		EMIT_PCT("rsize.pct.1536to2047",	RSIZE_PCT_1536_2047);
		EMIT_PCT("rsize.pct.2048to2559",	RSIZE_PCT_2048_2559);
		EMIT_PCT("rsize.pct.2560to3071",	RSIZE_PCT_2560_3071);
		EMIT_PCT("rsize.pct.3072to3583",	RSIZE_PCT_3072_3583);
		EMIT_PCT("rsize.pct.3584to4095",	RSIZE_PCT_3584_4095);
		EMIT_PCT("rsize.pct.above4096",		RSIZE_PCT_GT_4096);
		EMIT_PCT("rsize.avg", 			RSIZE_AVERAGE);
		EMIT_INT("rflags.ctr.tc",		rflags_ctr.RFLAG_TC);

		fflush(stat_fp);

		/* Reset the statistics */
		eemo_dnszabbix_stats_reset();

		fclose(stat_fp);
	}

	stat_fp = NULL;
}

/* Signal handler for alarms & user signals */
void signal_handler(int signum)
{
	if (signum == SIGUSR1)
	{
		DEBUG_MSG("Received user signal to dump statistics");
	}
	
	/* Write statistics to file */
	write_stats();
}

/* Reset statistics */
void eemo_dnszabbix_stats_reset(void)
{
	memset(&qclass_ctr, 0, sizeof(qclass_ctr));
	memset(&rclass_ctr, 0, sizeof(qclass_ctr));
	memset(&qtype_ctr, 0, sizeof(qtype_ctr));
	memset(&rtype_ctr, 0, sizeof(qtype_ctr));
	memset(&iptype_ctr, 0, sizeof(iptype_ctr));
	memset(&proto_ctr, 0, sizeof(proto_ctr));
	memset(&edns0_ctr, 0, sizeof(edns0_ctr));
	memset(&rsize_ctr, 0, sizeof(rsize_ctr));
	memset(&rcode_ctr, 0, sizeof(rcode_ctr));
	memset(&rfrag_ctr, 0, sizeof(rfrag_ctr));
	memset(&rflags_ctr, 0, sizeof(rflags_ctr));

	DEBUG_MSG("DNS statistics reset");
}

/* Initialise the DNS query counter module */
void eemo_dnszabbix_stats_init(char** ips, int ip_count, char* stats_file, char* zabbix_host)
{
	int i = 0;

	stat_ips = ips;
	stat_ipcount = ip_count;

	INFO_MSG("Listening to %d IP addresses", stat_ipcount);

	for (i = 0; i < stat_ipcount; i++)
	{
		INFO_MSG("Listening for queries to IP %s", ips[i]);
	}

	stat_file = stats_file;

	INFO_MSG("Writing statistics to the file called %s", stat_file);

	zabbix_host_id = zabbix_host;

	INFO_MSG("Writing statistics for Zabbix host '%s'", zabbix_host_id);

	eemo_dnszabbix_stats_reset();
	
	/* Register signal handler */
	signal(SIGUSR1, signal_handler);
}

/* Uninitialise the DNS query counter module */
void eemo_dnszabbix_stats_uninit(eemo_conf_free_string_array_fn free_strings)
{
	/* Unregister signal handlers */
	signal(SIGUSR1, SIG_DFL);
	
	/* Write statistics one more time before exiting */
	write_stats();

	(free_strings)(stat_ips, stat_ipcount);
	free(stat_file);
	free(zabbix_host_id);
}

/* Handle DNS query packets and log the statistics */
eemo_rv eemo_dnszabbix_stats_handleqr(eemo_ip_packet_info ip_info, int is_tcp, const eemo_dns_packet* dns_packet)
{
	int i = 0;
	eemo_dns_query* query_it = NULL;
	eemo_dns_rr* answer_it = NULL;

	if (dns_packet->qr_flag)
	{
		/* This is a response */

		/* Count only valid responses */
		if (!dns_packet->is_valid)
		{
			return ERV_SKIPPED;
		}
		
		/* Check whether we should count this response */
		if (stat_ipcount > 0)
		{
			int ip_match = 0;

			/* Check if this query originates from the server we're supposed to monitor */
			for (i = 0; i < stat_ipcount; i++)
			{
				if (!strcmp(stat_ips[i], ip_info.ip_src) || !strcmp(stat_ips[i], IP_ANY))
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

		/* Count fragmented vs. unfragmented responses */
		if (dns_packet->is_fragmented)
		{
			rfrag_ctr.R_FRAG++;
		}
		else
		{
			rfrag_ctr.R_UNFRAG++;
		}

		/* Count answer classes and types */
		LL_FOREACH(dns_packet->answers, answer_it)
		{
			/* Log answer class */
			switch(answer_it->class)
			{
			case DNS_QCLASS_UNSPECIFIED:
				rclass_ctr.UNSPECIFIED++;
				break;
			case DNS_QCLASS_IN:
				rclass_ctr.IN++;
				break;
			case DNS_QCLASS_CS:
				rclass_ctr.CS++;
				break;
			case DNS_QCLASS_CH:
				rclass_ctr.CH++;
				break;
			case DNS_QCLASS_HS:
				rclass_ctr.HS++;
				break;
			case DNS_QCLASS_ANY:
				rclass_ctr.ANY++;
				break;
			default:
				rclass_ctr.UNKNOWN++;
			}
		
			/* Log answer type */
			switch(answer_it->type)
			{
			case DNS_QTYPE_UNSPECIFIED:
				rtype_ctr.UNSPECIFIED++;
				break;
			case DNS_QTYPE_A:
				rtype_ctr.A++;
				break;
			case DNS_QTYPE_AAAA:
				rtype_ctr.AAAA++;
				break;
			case DNS_QTYPE_AFSDB:
				rtype_ctr.AFSDB++;
				break;
			case DNS_QTYPE_APL:
				rtype_ctr.APL++;
				break;
			case DNS_QTYPE_CERT:
				rtype_ctr.CERT++;
				break;
			case DNS_QTYPE_CNAME:
				rtype_ctr.CNAME++;
				break;
			case DNS_QTYPE_DHCID:
				rtype_ctr.DHCID++;
				break;
			case DNS_QTYPE_DLV:
				rtype_ctr.DLV++;
				break;
			case DNS_QTYPE_DNAME:
				rtype_ctr.DNAME++;
				break;
			case DNS_QTYPE_DNSKEY:
				rtype_ctr.DNSKEY++;
				break;
			case DNS_QTYPE_DS:
				rtype_ctr.DS++;
				break;
			case DNS_QTYPE_HIP:
				rtype_ctr.HIP++;
				break;
			case DNS_QTYPE_IPSECKEY:
				rtype_ctr.IPSECKEY++;
				break;
			case DNS_QTYPE_KEY:
				rtype_ctr.KEY++;
				break;
			case DNS_QTYPE_KX:
				rtype_ctr.KX++;
				break;
			case DNS_QTYPE_LOC:
				rtype_ctr.LOC++;
				break;
			case DNS_QTYPE_MX:
				rtype_ctr.MX++;
				break;
			case DNS_QTYPE_NAPTR:
				rtype_ctr.NAPTR++;
				break;
			case DNS_QTYPE_NS:
				rtype_ctr.NS++;
				break;
			case DNS_QTYPE_NSEC:
				rtype_ctr.NSEC++;
				break;
			case DNS_QTYPE_NSEC3:
				rtype_ctr.NSEC3++;
				break;
			case DNS_QTYPE_NSEC3PARAM:
				rtype_ctr.NSEC3PARAM++;
				break;
			case DNS_QTYPE_PTR:
				rtype_ctr.PTR++;
				break;
			case DNS_QTYPE_RRSIG:
				rtype_ctr.RRSIG++;
				break;
			case DNS_QTYPE_RP:
				rtype_ctr.RP++;
				break;
			case DNS_QTYPE_SIG:
				rtype_ctr.SIG++;
				break;
			case DNS_QTYPE_SOA:
				rtype_ctr.SOA++;
				break;
			case DNS_QTYPE_SPF:
				rtype_ctr.SPF++;
				break;
			case DNS_QTYPE_SRV:
				rtype_ctr.SRV++;
				break;
			case DNS_QTYPE_SSHFP:
				rtype_ctr.SSHFP++;
				break;
			case DNS_QTYPE_TA:
				rtype_ctr.TA++;
				break;
			case DNS_QTYPE_TKEY:
				rtype_ctr.TKEY++;
				break;
			case DNS_QTYPE_TSIG:
				rtype_ctr.TSIG++;
				break;
			case DNS_QTYPE_TXT:
				rtype_ctr.TXT++;
				break;
			case DNS_QTYPE_ANY:
				rtype_ctr.ANY++;
				break;
			case DNS_QTYPE_AXFR:
				rtype_ctr.AXFR++;
				break;
			case DNS_QTYPE_IXFR:
				rtype_ctr.IXFR++;
				break;
			case DNS_QTYPE_OPT:
				rtype_ctr.OPT++;
				break;
			default:
				rtype_ctr.UNKNOWN++;
			}
		}

		/* Count RCODEs */
		switch (dns_packet->rcode)
		{
		case DNS_RCODE_NOERROR:
			if (dns_packet->answers == NULL)
			{
				int		has_soa_in_auth	= 0;
				int		has_ns_in_auth	= 0;
				eemo_dns_rr*	aut_it		= NULL;

				LL_FOREACH(dns_packet->authorities, aut_it)
				{
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
					rcode_ctr.RCODE_NODATA++;
				}
				else if (has_ns_in_auth)
				{
					/* This is a referral */
					rcode_ctr.RCODE_REFERRAL++;
				}
				else
				{
					WARNING_MSG("Response for %s with empty answer section that is not a referral or NODATA answer", (dns_packet->questions == NULL) ? "<unknown>" : dns_packet->questions->qname);

					rcode_ctr.RCODE_UNKNOWN++;
				}
			}
			else
			{
				rcode_ctr.RCODE_NOERROR++;
			}
			break;
		case DNS_RCODE_FORMERR:
			rcode_ctr.RCODE_FORMERR++;
			break;
		case DNS_RCODE_SERVFAIL:
			rcode_ctr.RCODE_SERVFAIL++;
			break;
		case DNS_RCODE_NXDOMAIN:
			rcode_ctr.RCODE_NXDOMAIN++;
			break;
		case DNS_RCODE_NOTIMPL:
			rcode_ctr.RCODE_NOTIMPL++;
			break;
		case DNS_RCODE_REFUSED:
			rcode_ctr.RCODE_REFUSED++;
			break;
		default:
			rcode_ctr.RCODE_UNKNOWN++;
			break;
		}

		/* Count response size in buckets; only count response > 0 bytes */
		if (dns_packet->udp_len > 0)
		{
			if (dns_packet->udp_len < 512)
			{
				rsize_ctr.RSIZE_BELOW_512++;
			}
			else if (dns_packet->udp_len < 1024)
			{
				rsize_ctr.RSIZE_512_TO_1023++;
			}
			else if (dns_packet->udp_len < 1536)
			{
				rsize_ctr.RSIZE_1024_TO_1535++;
			}
			else if (dns_packet->udp_len < 2048)
			{
				rsize_ctr.RSIZE_1536_TO_2047++;
			}
			else if (dns_packet->udp_len < 2560)
			{
				rsize_ctr.RSIZE_2048_TO_2559++;
			}
			else if (dns_packet->udp_len < 3072)
			{
				rsize_ctr.RSIZE_2560_TO_3071++;
			}
			else if (dns_packet->udp_len < 3584)
			{
				rsize_ctr.RSIZE_3072_TO_3583++;
			}
			else if (dns_packet->udp_len < 4096)
			{
				rsize_ctr.RSIZE_3584_TO_4095++;
			}
			else
			{
				rsize_ctr.RSIZE_ABOVE_4096++;
			}

			rsize_ctr.RSIZE_TOTAL += dns_packet->udp_len;
			rsize_ctr.RSIZE_COUNTED++;
		}

		/* Count flags */
		if (dns_packet->tc_flag) rflags_ctr.RFLAG_TC++;

		return ERV_HANDLED;
	}
	else
	{
		/* This is a query */

		/* Count only valid queries */
		if (!dns_packet->is_valid)
		{
			return ERV_SKIPPED;
		}

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
	
		LL_FOREACH(dns_packet->questions, query_it)
		{
			/* Log query class */
			switch(query_it->qclass)
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
			switch(query_it->qtype)
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
		}
	
		/* Log EDNS0 data */
		if (dns_packet->has_edns0)
		{
			if (dns_packet->edns0_do)
			{
				edns0_ctr.EDNS0_DO_SET++;
			}
			else
			{
				edns0_ctr.EDNS0_DO_UNSET++;
			}

			/* Log EDNS0 buffer size */
			if (dns_packet->edns0_max_size < 512)
			{
				edns0_ctr.EDNS0_BELOW_512++;
			}
			else if ((dns_packet->edns0_max_size >= 512) && (dns_packet->edns0_max_size < 1000))
			{
				edns0_ctr.EDNS0_512_TO_999++;
			}
			else if ((dns_packet->edns0_max_size >= 1000) && (dns_packet->edns0_max_size < 1500))
			{
				edns0_ctr.EDNS0_1000_TO_1499++;
			}
			else if ((dns_packet->edns0_max_size >= 1500) && (dns_packet->edns0_max_size < 2000))
			{
				edns0_ctr.EDNS0_1500_TO_1999++;
			}
			else if ((dns_packet->edns0_max_size >= 2000) && (dns_packet->edns0_max_size < 2500))
			{
				edns0_ctr.EDNS0_2000_TO_2499++;
			}
			else if ((dns_packet->edns0_max_size >= 2500) && (dns_packet->edns0_max_size < 3000))
			{
				edns0_ctr.EDNS0_2500_TO_2999++;
			}
			else if ((dns_packet->edns0_max_size >= 3000) && (dns_packet->edns0_max_size < 3500))
			{
				edns0_ctr.EDNS0_3000_TO_3499++;
			}
			else if ((dns_packet->edns0_max_size >= 3500) && (dns_packet->edns0_max_size < 4000))
			{
				edns0_ctr.EDNS0_3500_TO_3999++;
			}
			else if ((dns_packet->edns0_max_size >= 4000) && (dns_packet->edns0_max_size < 4500))
			{
				edns0_ctr.EDNS0_4000_TO_4499++;
			}
			else
			{
				edns0_ctr.EDNS0_ABOVE_4500++;
			}

			if (dns_packet->has_edns0_client_subnet)
			{
				edns0_ctr.EDNS0_W_ECS++;
			}
			else
			{
				edns0_ctr.EDNS0_WO_ECS++;
			}

			if (dns_packet->has_edns0_exp_opt)
			{
				edns0_ctr.EDNS0_EXP_OPT++;
			}
		}
		else
		{
			edns0_ctr.EDNS0_NO++;
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
}

