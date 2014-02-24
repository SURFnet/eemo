/* $Id$ */

/*
 * Copyright (c) 2010-2014 SURFnet bv
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
 * DNS query/response logging
 */

#include "config.h"
#include "eemo.h"
#include "eemo_log.h"
#include "eemo_dnsqrlog.h"
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <time.h>

#define IP_ANY	"*"

/* Configuration */
char** 	qrlog_ips 			= NULL;
int		qrlog_ipcount		= 0;
char**	qrlog_domains		= NULL;
int		qrlog_domaincount	= 0;

/* Log file */
FILE*	qrlog_file			= NULL;

/* Initialise DNS query/response logging */
void eemo_dnsqrlog_init(char** ips, int ip_count, char** domains, int domain_count, const char* qrlogfile)
{
	int i = 0;

	qrlog_ips = ips;
	qrlog_ipcount = ip_count;
	qrlog_domains = domains;
	qrlog_domaincount = domain_count;
	
	INFO_MSG("Listening to %d IP addresses", qrlog_ipcount);

	for (i = 0; i < qrlog_ipcount; i++)
	{
		INFO_MSG("Listening for queries to or responses from IP %s", ips[i]);
	}

	if (qrlog_domaincount > 0)
	{
		for (i = 0; i < qrlog_domaincount; i++)
		{
			INFO_MSG("Logging queries for domain %s", qrlog_domains[i]);
		}
	}
	else
	{
		INFO_MSG("Forwarding queries for ALL domains");
	}
	
	qrlog_file = fopen(qrlogfile, "a");
	
	if (qrlog_file == NULL)
	{
		ERROR_MSG("Could not open %s for writing", qrlogfile);
	}
}

/* Uninitialise DNS query forwarding */
void eemo_dnsqrlog_uninit(eemo_conf_free_string_array_fn free_strings)
{
	if (qrlog_file) fclose(qrlog_file);
	
	(free_strings)(qrlog_ips, qrlog_ipcount);
	(free_strings)(qrlog_domains, qrlog_domaincount);
}

/* Does the specified IP match one of the IPs we should be logging for? */
int eemo_dnsqrlog_ipmatch(const char* ip)
{
	int ip_match = 0;
	int i = 0;
	
	if (qrlog_ipcount > 0)
	{
		for (i = 0; i < qrlog_ipcount; i++)
		{
			if (!strcmp(qrlog_ips[i], ip) || !strcmp(qrlog_ips[i], IP_ANY))
			{
				ip_match = 1;
				break;
			}
		}
	}
	else
	{
		ip_match = 1; /* log all queries/responses */
	}
	
	return ip_match;
}

/* Does the specified query name match one of the domains we should be logging for? */
int eemo_dnsqrlog_qnamematch(const char* qname)
{
	int qname_match = 0;
	int i = 0;
	int comp_len = 0;
	int comp_index = 0;
	
	if (qrlog_domaincount > 0)
	{
		/* Check if this query matches one of the domains for which we're forwarding queries */
		for (i = 0; i < qrlog_domaincount; i++)
		{
			/* If the length of the query name is less than the domain name length skip it */
			if (strlen(qname) < strlen(qrlog_domains[i]))
			{
				continue;
			}
	
			/* Compare the last <domainnamelen> characters to check for a match */
			comp_len = strlen(qrlog_domains[i]);
			comp_index = strlen(qname) - comp_len;
	
			if (!strncasecmp(&qname[comp_index], qrlog_domains[i], comp_len))
			{
				qname_match = 1;
				break;
			}
		}
	}
	else
	{
		qname_match = 1; /* log all queries/responses */
	}
	
	return qname_match;
}

/* Query class to string */
const char* qclass_to_str(unsigned short qclass)
{
	const char* STR_QCLASS_UNSPECIFIED	= "UNSPECIFIED";
	const char* STR_QCLASS_IN			= "IN";
	const char* STR_QCLASS_CS			= "CS";
	const char* STR_QCLASS_CH			= "CH";
	const char* STR_QCLASS_HS			= "HS";
	const char* STR_QCLASS_ANY			= "ANY";
	
	switch(qclass)
	{
	case DNS_QCLASS_IN:
		return STR_QCLASS_IN;
	case DNS_QCLASS_CS:
		return STR_QCLASS_CS;
	case DNS_QCLASS_CH:
		return STR_QCLASS_CH;
	case DNS_QCLASS_HS:
		return STR_QCLASS_HS;
	case DNS_QCLASS_ANY:
		return STR_QCLASS_ANY;
	case DNS_QCLASS_UNSPECIFIED:
	default:
		return STR_QCLASS_UNSPECIFIED;
	}
}

/* Query type to string */
const char* qtype_to_str(unsigned short qtype)
{
	const char* STR_QTYPE_UNSPECIFIED 	= "UNSPECIFIED";
	const char* STR_QTYPE_A 			= "A";
	const char* STR_QTYPE_AAAA 			= "AAAA";
	const char* STR_QTYPE_AFSDB 		= "AFSDB";
	const char* STR_QTYPE_APL 			= "APL";
	const char* STR_QTYPE_CERT 			= "CERT";
	const char* STR_QTYPE_CNAME 		= "CNAME";
	const char* STR_QTYPE_DHCID 		= "DHCID";
	const char* STR_QTYPE_DLV 			= "DLV";
	const char* STR_QTYPE_DNAME 		= "DNAME";
	const char* STR_QTYPE_DNSKEY 		= "DNSKEY";
	const char* STR_QTYPE_DS 			= "DS";
	const char* STR_QTYPE_HIP 			= "HIP";
	const char* STR_QTYPE_IPSECKEY 		= "IPSECKEY";
	const char* STR_QTYPE_KEY 			= "KEY";
	const char* STR_QTYPE_KX 			= "KX";
	const char* STR_QTYPE_LOC 			= "LOC";
	const char* STR_QTYPE_MX 			= "MX";
	const char* STR_QTYPE_NAPTR 		= "NAPTR";
	const char* STR_QTYPE_NS 			= "NS";
	const char* STR_QTYPE_NSEC 			= "NSEC";
	const char* STR_QTYPE_NSEC3 		= "NSEC3";
	const char* STR_QTYPE_NSEC3PARAM 	= "NSEC3PARAM";
	const char* STR_QTYPE_PTR 			= "PTR";
	const char* STR_QTYPE_RRSIG 		= "RRSIG";
	const char* STR_QTYPE_RP 			= "RP";
	const char* STR_QTYPE_SIG 			= "SIG";
	const char* STR_QTYPE_SOA 			= "SOA";
	const char* STR_QTYPE_SPF 			= "SPF";
	const char* STR_QTYPE_SRV 			= "SRV";
	const char* STR_QTYPE_SSHFP 		= "SSHFP";
	const char* STR_QTYPE_TA 			= "TA";
	const char* STR_QTYPE_TKEY 			= "TKEY";
	const char* STR_QTYPE_TSIG 			= "TSIG";
	const char* STR_QTYPE_TXT 			= "TXT";
	const char* STR_QTYPE_ANY 			= "ANY";
	
	switch(qtype)
	{
	case DNS_QTYPE_A:
		return STR_QTYPE_A;
	case DNS_QTYPE_AAAA:
		return STR_QTYPE_AAAA;
	case DNS_QTYPE_AFSDB:
		return STR_QTYPE_AFSDB;
	case DNS_QTYPE_APL:
		return STR_QTYPE_APL;
	case DNS_QTYPE_CERT:
		return STR_QTYPE_CERT;
	case DNS_QTYPE_CNAME:
		return STR_QTYPE_CNAME;
	case DNS_QTYPE_DHCID:
		return STR_QTYPE_DHCID;
	case DNS_QTYPE_DLV:
		return STR_QTYPE_DLV;
	case DNS_QTYPE_DNAME:
		return STR_QTYPE_DNAME;
	case DNS_QTYPE_DNSKEY:
		return STR_QTYPE_DNSKEY;
	case DNS_QTYPE_DS:
		return STR_QTYPE_DS;
	case DNS_QTYPE_HIP:
		return STR_QTYPE_HIP;
	case DNS_QTYPE_IPSECKEY:
		return STR_QTYPE_IPSECKEY;
	case DNS_QTYPE_KEY:
		return STR_QTYPE_KEY;
	case DNS_QTYPE_KX:
		return STR_QTYPE_KX;
	case DNS_QTYPE_LOC:
		return STR_QTYPE_LOC;
	case DNS_QTYPE_MX:
		return STR_QTYPE_MX;
	case DNS_QTYPE_NAPTR:
		return STR_QTYPE_NAPTR;
	case DNS_QTYPE_NS:
		return STR_QTYPE_NS;
	case DNS_QTYPE_NSEC:
		return STR_QTYPE_NSEC;
	case DNS_QTYPE_NSEC3:
		return STR_QTYPE_NSEC3;
	case DNS_QTYPE_NSEC3PARAM:
		return STR_QTYPE_NSEC3PARAM;
	case DNS_QTYPE_PTR:
		return STR_QTYPE_PTR;
	case DNS_QTYPE_RRSIG:
		return STR_QTYPE_RRSIG;
	case DNS_QTYPE_RP:
		return STR_QTYPE_RP;
	case DNS_QTYPE_SIG:
		return STR_QTYPE_SIG;
	case DNS_QTYPE_SOA:
		return STR_QTYPE_SOA;
	case DNS_QTYPE_SPF:
		return STR_QTYPE_SPF;
	case DNS_QTYPE_SRV:
		return STR_QTYPE_SRV;
	case DNS_QTYPE_SSHFP:
		return STR_QTYPE_SSHFP;
	case DNS_QTYPE_TA:
		return STR_QTYPE_TA;
	case DNS_QTYPE_TKEY:
		return STR_QTYPE_TKEY;
	case DNS_QTYPE_TSIG:
		return STR_QTYPE_TSIG;
	case DNS_QTYPE_TXT:
		return STR_QTYPE_TXT;
	case DNS_QTYPE_ANY:
		return STR_QTYPE_ANY;
	case DNS_QTYPE_UNSPECIFIED:
	default:
		return STR_QTYPE_UNSPECIFIED;
	}
}

/* Rcode to string */
const char* rcode_to_str(unsigned short rcode)
{
	const char* STR_RCODE_NOERROR	= "NOERROR";
	const char* STR_RCODE_FORMERR	= "FORMERR";
	const char* STR_RCODE_SERVFAIL	= "SERVFAIL";
	const char* STR_RCODE_NXDOMAIN	= "NXDOMAIN";
	const char* STR_RCODE_NOTIMPL	= "NOTIMPL";
	const char* STR_RCODE_REFUSED	= "REFUSED";
	const char* STR_RCODE_UNKNOWN	= "UNKNOWN";
	
	switch(rcode)
	{
	case DNS_RCODE_NOERROR:
		return STR_RCODE_NOERROR;
	case DNS_RCODE_FORMERR:
		return STR_RCODE_FORMERR;
	case DNS_RCODE_SERVFAIL:
		return STR_RCODE_SERVFAIL;
	case DNS_RCODE_NXDOMAIN:
		return STR_RCODE_NXDOMAIN;
	case DNS_RCODE_NOTIMPL:
		return STR_RCODE_NOTIMPL;
	case DNS_RCODE_REFUSED:
		return STR_RCODE_REFUSED;
	default:
		return STR_RCODE_UNKNOWN;
	}
}

/* Handle DNS query packets */
eemo_rv eemo_dnsqrlog_handleqr(eemo_ip_packet_info ip_info, int is_tcp, const eemo_dns_packet* dns_packet)
{
	eemo_dns_query* query_it = NULL;
	eemo_dns_rr* answ_it = NULL;
	unsigned long now = (unsigned long) time(NULL);
	
	if (dns_packet->qr_flag == 0)	/* this is a query */
	{
		/* Check if the query was directed to one of the IPs we're monitoring */
		if (!eemo_dnsqrlog_ipmatch(ip_info.ip_dst))
		{
			return ERV_SKIPPED;
		}
		
		LL_FOREACH(dns_packet->questions, query_it)
		{
			/* Check if the query name matches one of the domains we're monitoring */
			if (!eemo_dnsqrlog_qnamematch(query_it->qname))
			{
				continue;
			}
			
			/* Log the query */
			if (qrlog_file)
			{
				fprintf(qrlog_file, "%lu, Q(Q), %s, %s, %s, %s\n", now, ip_info.ip_src, qclass_to_str(query_it->qclass), qtype_to_str(query_it->qtype), query_it->qname);
			}
		}
		
		fflush(qrlog_file);
	}
	else 							/* this is a response */
	{
		/* Check if the response originated from one of the IPs we're monitoring */
		if (!eemo_dnsqrlog_ipmatch(ip_info.ip_src))
		{
			return ERV_SKIPPED;
		}
		
		LL_FOREACH(dns_packet->questions, query_it)
		{
			/* Check if the query name matches one of the domains we're monitoring */
			if (!eemo_dnsqrlog_qnamematch(query_it->qname))
			{
				continue;
			}
		
			if (qrlog_file)
			{
				fprintf(qrlog_file, "%lu, Q(R), %s, %s, %s, %s, %s\n", now, ip_info.ip_dst, qclass_to_str(query_it->qclass), qtype_to_str(query_it->qtype), query_it->qname, rcode_to_str(dns_packet->rcode));
			}
			
			/* Log the response */
			LL_FOREACH(dns_packet->answers, answ_it)
			{
				if (qrlog_file)
				{
					fprintf(qrlog_file, "%lu, R(ANS), %s, %s, %s, %s\n", now, ip_info.ip_dst, qclass_to_str(answ_it->class), qtype_to_str(answ_it->type), answ_it->rdata_txt);
				}
			}
			
			LL_FOREACH(dns_packet->authorities, answ_it)
			{
				if (qrlog_file)
				{
					fprintf(qrlog_file, "%lu, R(AUT), %s, %s, %s, %s\n", now, ip_info.ip_dst, qclass_to_str(answ_it->class), qtype_to_str(answ_it->type), answ_it->rdata_txt);
				}
			}
			
			LL_FOREACH(dns_packet->additionals, answ_it)
			{
				if (qrlog_file)
				{
					fprintf(qrlog_file, "%lu, R(ADD), %s, %s, %s, %s\n", now, ip_info.ip_dst, qclass_to_str(answ_it->class), qtype_to_str(answ_it->type), answ_it->rdata_txt);
				}
			}
		}
		
		fflush(qrlog_file);
	}

	return ERV_HANDLED;
}

