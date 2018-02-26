/*
 * Copyright (c) 2010-2016 SURFnet bv
 * Copyright (c) 2015-2016 Roland van Rijswijk-Deij
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
 * The Extensible IP Monitor (EEMO)
 * DNS packet parsing
 */

#include "config.h"
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <ctype.h>
#include "dns_parser.h"
#include "eemo_log.h"
#include "ip_metadata.h"
#include "eemo_config.h"

/*#define DNS_PARSE_DEBUG*/  /* define to enable extensive debug logging of DNS parsing */
#undef DNS_PARSE_DEBUG

#ifdef DNS_PARSE_DEBUG
	#define PARSE_MSG(...) eemo_log(EEMO_LOG_DEBUG  , __FILE__, __LINE__, __VA_ARGS__);
#else // DNS_PARSE_DEBUG
	#define PARSE_MSG(...)
#endif // !DNS_PARSE_DEBUG

#pragma pack(push, 1)
/* DNS query packet header */
typedef struct
{
	u_short	dns_qid;	/* query ID */
	u_short dns_flags;	/* query flags */
	u_short dns_qdcount;	/* number of queries in packet */
	u_short	dns_ancount;	/* number of answers in packet */
	u_short	dns_nscount;	/* number of authority answers in packet */
	u_short	dns_arcount;	/* number of additional records in packet */
}
eemo_hdr_dns;
#pragma pack(pop)

/* Maximum number of pointers in a DNS name */
#define MAX_DNS_NAME_PTR	256

/* Log DNS parsing errors? */
static int	log_dns_parse_err	= 1;

/* Free up the RDATA belonging to an RR */
void eemo_free_dns_rr_rdata(eemo_dns_rr* rr)
{
	if (rr->rdata_txt != NULL)
	{
		free(rr->rdata_txt);
	}
	
	if (rr->rdata == NULL)
	{
		/* No data needs to be freed */
	}

	switch(rr->type)
	{
	case DNS_QTYPE_A:
		/* RDATA is a simple pointer to an unsigned integer */
		free(rr->rdata);
		break;
	case DNS_QTYPE_AAAA:
		/* RDATA is a simple pointer to an array */
		free(rr->rdata);
		break;
	case DNS_QTYPE_CNAME:
		/* RDATA is a simple pointer to a string */
		free(rr->rdata);
		break;
	case DNS_QTYPE_NS:
		/* RDATA is a simple pointer to a string */
		free(rr->rdata);
		break;
	case DNS_QTYPE_TXT:
		/* RDATA is a linked list of txt_rdata structures */
		{
			txt_rdata* txt_it = NULL;
			txt_rdata* txt_tmp = NULL;
			txt_rdata* txt_list = (txt_rdata*) rr->rdata;

			LL_FOREACH_SAFE(txt_list, txt_it, txt_tmp)
			{
				free(txt_it->string);

				LL_DELETE(txt_list, txt_it);

				free(txt_it);
			}
		}
		break;
	eemo_md_lookup_as_and_prefix_v4((struct in_addr*) &addr, &dns_packet->edns0_client_subnet_as_short, &dns_packet->edns0_client_subnet_as_full, &dns_packet->edns0_client_subnet_prefix);
											eemo_md_lookup_geoip_v4((struct in_addr*) &addr, &dns_packet->edns0_client_subnet_geo_ip);
										}
										else
										{
											eemo_md_lookup_as_and_prefix_v6((struct in6_addr*) &addr, &dns_packet->edns0_client_subnet_as_short, &dns_packet->edns0_client_subnet_as_full, &dns_packet->edns0_client_subnet_prefix);
											eemo_md_lookup_geoip_v6((struct in6_addr*) &addr, &dns_packet->edns0_client_subnet_geo_ip);
										}

										dns_packet->has_edns0_client_subnet = 1;
									}
								}
							}
						}
						else if (opt_code > 65000)
						{
							dns_packet->has_edns0_exp_opt = 1;

							/* Skip over the option data */
							rdata_ofs += opt_len;
							rdata_len_rem -= opt_len;
						}
						else
						{
							if (log_dns_parse_err) WARNING_MSG("Unrecognised EDNS0 option %u", opt_code);

							/* Skip over the option data */
							rdata_ofs += opt_len;
							rdata_len_rem -= opt_len;
						}
					}

					if (rdata_len_rem != 0)
					{
						/* EDNS0 OPT RDATA was malformed! */
						if (log_dns_parse_err) WARNING_MSG("Malformed EDNS0 OPT RDATA field");
					}
				}

				PARSE_MSG("EDNS0 data present, version %d, maximum response size %u, DO=%u", dns_packet->edns0_version, dns_packet->edns0_max_size, dns_packet->edns0_do);
			}

			if (dns_packet->has_edns0_client_subnet)
			{
				PARSE_MSG("EDNS0 client subnet option scoped to %s/%u (%s,%s,%s,%s)", dns_packet->edns0_client_subnet_ip, dns_packet->qr_flag ? dns_packet->edns0_client_subnet_res_scope : dns_packet->edns0_client_subnet_src_scope, dns_packet->edns0_client_subnet_as_short, dns_packet->edns0_client_subnet_as_full, dns_packet->edns0_client_subnet_prefix, dns_packet->edns0_client_subnet_geo_ip);
			}
		}

		/* Skip over RDATA */
		*offset += rdata_len;

		/* Append to list of answers */
		LL_APPEND(*rr_list, new_rr);
	}

	return ERV_OK;
}

/* Parse a DNS packet */
eemo_rv eemo_parse_dns_packet(const eemo_packet_buf* packet, eemo_dns_packet* dns_packet, unsigned long parser_flags, unsigned short udp_len, int is_fragmented)
{
	eemo_hdr_dns	hdr;
	unsigned long	ofs	= sizeof(eemo_hdr_dns);
	eemo_rv		rv	= ERV_OK;

	/* Initialise parsed packet data */
	dns_packet->is_valid 				= 0;
	dns_packet->is_partial				= 1;
	dns_packet->questions 				= NULL;
	dns_packet->answers 				= NULL;
	dns_packet->authorities				= NULL;
	dns_packet->additionals				= NULL;
	dns_packet->udp_len				= udp_len;
	dns_packet->is_fragmented			= is_fragmented;
	dns_packet->has_edns0				= 0;
	dns_packet->edns0_version			= 0;
	dns_packet->edns0_max_size			= 0;
	dns_packet->edns0_do				= 0;
	dns_packet->has_edns0_client_subnet		= 0;
	dns_packet->edns0_client_subnet_src_scope	= 0;
	dns_packet->edns0_client_subnet_res_scope	= 0;
	memset(dns_packet->edns0_client_subnet_ip, 0, sizeof(dns_packet->edns0_client_subnet_ip));
	dns_packet->has_edns0_exp_opt			= 0;
	dns_packet->edns0_client_subnet_as_short	= NULL;
	dns_packet->edns0_client_subnet_as_full		= NULL;
	dns_packet->edns0_client_subnet_prefix		= NULL;
	dns_packet->edns0_client_subnet_geo_ip		= NULL;

	/* Check if we need to parse at all */
	if (parser_flags == PARSE_NONE)
	{
		return ERV_OK;
	}

	/* Check parameters */
	if ((packet == NULL) || (dns_packet == NULL))
	{
		return ERV_PARAM_INVALID;
	}

	/* Check input data */
	if (packet->len < sizeof(eemo_hdr_dns))
	{
		/* Packet is malformed */
		return ERV_MALFORMED;
	}

	/* Retrieve the header */
	memcpy(&hdr, packet->data, sizeof(hdr));
	eemo_dns_hdr_ntoh(&hdr);

	PARSE_MSG("Parsing DNS packet with:");
	PARSE_MSG("%d questions (QDCOUNT)", hdr.dns_qdcount);
	PARSE_MSG("%d answers (ANCOUNT)", hdr.dns_ancount);
	PARSE_MSG("%d authorities (NSCOUNT)", hdr.dns_nscount);
	PARSE_MSG("%d additionals (ARCOUNT)", hdr.dns_arcount);

	/* Copy the query ID, flags, OPCODE and RCODE */
	dns_packet->query_id 	= hdr.dns_qid;
	dns_packet->qr_flag 	= FLAG_SET(hdr.dns_flags, DNS_QRFLAG);
	dns_packet->aa_flag	= FLAG_SET(hdr.dns_flags, DNS_AAFLAG);
	dns_packet->tc_flag 	= FLAG_SET(hdr.dns_flags, DNS_TCFLAG);
	dns_packet->ra_flag 	= FLAG_SET(hdr.dns_flags, DNS_RAFLAG);
	dns_packet->rd_flag	= FLAG_SET(hdr.dns_flags, DNS_RDFLAG);
	dns_packet->ad_flag	= FLAG_SET(hdr.dns_flags, DNS_ADFLAG);
	dns_packet->cd_flag	= FLAG_SET(hdr.dns_flags, DNS_CDFLAG);
	dns_packet->opcode	= DNS_OPCODE(hdr.dns_flags);
	dns_packet->rcode	= DNS_RCODE(hdr.dns_flags);
	dns_packet->ans_count	= hdr.dns_ancount;
	dns_packet->aut_count	= hdr.dns_nscount;
	dns_packet->add_count	= hdr.dns_arcount;

	PARSE_MSG("Query ID: %d", dns_packet->query_id);
	PARSE_MSG("Flags:%s%s%s%s%s%s%s",
		dns_packet->qr_flag ? " QR" : "",
		dns_packet->aa_flag ? " AA" : "",
		dns_packet->tc_flag ? " TC" : "",
		dns_packet->ra_flag ? " RA" : "",
		dns_packet->rd_flag ? " RD" : "",
		dns_packet->ad_flag ? " AD" : "",
		dns_packet->cd_flag ? " CD" : "");
	PARSE_MSG("OPCODE: %d", dns_packet->opcode);
	PARSE_MSG("RCODE: %d", dns_packet->rcode);

	/* Check if it is a query or a response and if it needs to be parsed */
	if (!dns_packet->qr_flag && !FLAG_SET(parser_flags, PARSE_QUERY))
	{
		dns_packet->is_valid = 1;

		return ERV_OK;
	}
	else if (dns_packet->qr_flag && !FLAG_SET(parser_flags, PARSE_RESPONSE))
	{
		dns_packet->is_valid = 1;

		return ERV_OK;
	}

	/* Retrieve the queries from the packet */
	if ((rv = eemo_parse_dns_queries(packet, dns_packet, hdr.dns_qdcount, &ofs, parser_flags)) != ERV_OK)
	{
		if (rv == ERV_PARTIAL)
		{
			dns_packet->is_valid = 1;

			PARSE_MSG("DNS packet is valid and partial query data is present");
		}

		return rv;
	}

	/* Retrieve the answers from the packet */
	PARSE_MSG("Answers:");

	if ((rv = eemo_parse_dns_rrs(packet, dns_packet, &dns_packet->answers, hdr.dns_ancount, &ofs, parser_flags)) != ERV_OK)
	{
		if (rv == ERV_PARTIAL)
		{
			dns_packet->is_valid = 1;

			PARSE_MSG("DNS packet is valid and partial answer data is present");
		}

		return rv;
	}

	/* Retrieve the authorities from the packet */
	PARSE_MSG("Authorities:");

	if ((rv = eemo_parse_dns_rrs(packet, dns_packet, &dns_packet->authorities, hdr.dns_nscount, &ofs, parser_flags)) != ERV_OK)
	{
		if (rv == ERV_PARTIAL)
		{
			dns_packet->is_valid = 1;

			PARSE_MSG("DNS packet is valid and partial authority data is present");
		}

		return rv;
	}

	/* Retrieve the additionals from the packet */
	PARSE_MSG("Additional RRs:");

	if ((rv = eemo_parse_dns_rrs(packet, dns_packet, &dns_packet->additionals, hdr.dns_arcount, &ofs, parser_flags)) != ERV_OK)
	{
		if (rv == ERV_PARTIAL)
		{
			dns_packet->is_valid = 1;

			PARSE_MSG("DNS packet is valid and partial additional data is present");
		}

		return rv;
	}

	/* Set packet data to be valid */
	dns_packet->is_partial = 0;
	dns_packet->is_valid = 1;

	PARSE_MSG("DNS packet is valid and complete");

	return ERV_OK;
}

/* Free a DNS packet structure */
void eemo_free_dns_packet(eemo_dns_packet* dns_packet)
{
	eemo_dns_query* query_it = NULL;
	eemo_dns_query* query_tmp = NULL;

	/* Free query data */
	LL_FOREACH_SAFE(dns_packet->questions, query_it, query_tmp)
	{
		free(query_it->qname);

		LL_DELETE(dns_packet->questions, query_it);

		free(query_it);
	}

	eemo_free_dns_rr_list(&dns_packet->answers);
	eemo_free_dns_rr_list(&dns_packet->authorities);
	eemo_free_dns_rr_list(&dns_packet->additionals);

	dns_packet->is_valid = 0;

	free(dns_packet->edns0_client_subnet_as_short);
	free(dns_packet->edns0_client_subnet_as_full);
	free(dns_packet->edns0_client_subnet_prefix);
	free(dns_packet->edns0_client_subnet_geo_ip);
}

/* Initialise DNS parser module */
eemo_rv eemo_parse_dns_init(void)
{
	if (eemo_conf_get_bool("logging", "log_dns_parse_errors", &log_dns_parse_err, log_dns_parse_err) != ERV_OK)
	{
		ERROR_MSG("Failed to retrieve configuration setting for logging of DNS parse errors");

		return ERV_CONFIG_ERROR;
	}

	INFO_MSG("%s log DNS parsing errors", log_dns_parse_err ? "Will" : "Will not");

	INFO_MSG("DNS parsing module initialised");

	return ERV_OK;
}

/* Uninitialise DNS parser module */
eemo_rv eemo_parse_dns_finalize(void)
{
	INFO_MSG("DNS parser module uninitialised");

	return ERV_OK;
}

