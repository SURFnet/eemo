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
 * The Extensible IP Monitor (EEMO)
 * DNS packet parsing
 */

#include "config.h"
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <ctype.h>
#include "dns_parser.h"
#include "eemo_log.h"

/* #define DNS_PARSE_DEBUG */ /* define to enable extensive debug logging of DNS parsing */
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
	default:
		/* Assume that it is a simple copy of the RDATA byte string */
		free(rr->rdata);
		return;
	}
}

/* Free up an RR */
void eemo_free_dns_rr_list(eemo_dns_rr** rr_list)
{
	eemo_dns_rr* rr_it = NULL;
	eemo_dns_rr* rr_tmp = NULL;

	/* Check parameter */
	if (rr_list == NULL)
	{
		ERROR_MSG("Invalid parameter to eemo_free_dns_rr_list");
		
		return;
	}

	LL_FOREACH_SAFE(*rr_list, rr_it, rr_tmp)
	{
		LL_DELETE(*rr_list, rr_it);

		/* Free any memory used for RDATA */
		eemo_free_dns_rr_rdata(rr_it);

		free(rr_it->name);

		free(rr_it);
	}
}

/* Convert DNS packet header to host byte order */
void eemo_dns_hdr_ntoh(eemo_hdr_dns* hdr)
{
	hdr->dns_qid		= ntohs(hdr->dns_qid);
	hdr->dns_flags		= ntohs(hdr->dns_flags);
	hdr->dns_qdcount	= ntohs(hdr->dns_qdcount);
	hdr->dns_ancount	= ntohs(hdr->dns_ancount);
	hdr->dns_nscount	= ntohs(hdr->dns_nscount);
	hdr->dns_arcount	= ntohs(hdr->dns_arcount);
}

/* Uncompress a DNS name */
#define IS_POINTER		0xC0
#define PTR_HI_OCTET_MASK	0x3F

eemo_rv eemo_uncompress_dns_name(eemo_packet_buf* packet, unsigned long* offset, char** name, unsigned long parser_flags)
{
	unsigned char root_label_found = 0;
	unsigned char label_len = 0;
	unsigned char is_first_ptr = 1;
	unsigned short ofs = *offset;
	char name_buf[512] = { 0 };
	unsigned short len = 0;
	unsigned short ptr_ctr = 0;

	*name = NULL;

	while(!root_label_found && (ofs < packet->len) && (len < 512))
	{
		label_len = packet->data[ofs++];

		/* Check if we're dealing with a pointer */
		if (FLAG_SET(label_len, IS_POINTER))
		{
			/* Check if we can retrieve the second octet of the pointer without exceeding the buffer */
			if (ofs >= packet->len)
			{
				return ERV_MALFORMED;
			}

			/* Check if this is the first pointer */
			if (is_first_ptr)
			{
				/* Store the offset where the next record can be found */
				*offset = ofs + 1;

				is_first_ptr = 0;
			}

			/* Set the new offset based on the pointer */
			ofs = ((label_len & PTR_HI_OCTET_MASK) << 8) + packet->data[ofs];

			/* To prevent endless looping, count the number of pointers in this name */
			if (ptr_ctr++ >= MAX_DNS_NAME_PTR)
			{
				return ERV_DNS_NAME_LOOPS;
			}

			/* Continue parsing the name */
			continue;
		}

		/* Check for sane label length */
		if (label_len > 63)
		{
			ERROR_MSG("Invalid length field in QNAME (%d)", label_len);

			return ERV_MALFORMED;
		}

		/* Is this the root label? */
		if (label_len == 0)
		{
			/* Did we encounter a pointer in the label? */
			if (is_first_ptr)
			{
				/* Store the offset where the next record can be found */
				*offset = ofs;
			}

			root_label_found = 1;

			break;
		}

		/* Copy the label */
		if (FLAG_SET(parser_flags, PARSE_CANONICALIZE_NAME))
		{
			do
			{
				name_buf[len++] = tolower(packet->data[ofs++]);
			}
			while ((--label_len > 0) && (ofs < packet->len) && (len < 512));
		}
		else
		{
			do
			{
				name_buf[len++] = packet->data[ofs++];
			}
			while ((--label_len > 0) && (ofs < packet->len) && (len < 512));
		}

		/* Emit separating dot */
		if (len < 512)
		{
			name_buf[len++] = '.';
		}
	}

	if (root_label_found)
	{
		*name = strdup(name_buf);
	}

	if (root_label_found)
	{
		return ERV_OK;
	}
	else
	{
		return (len < 512) ? ERV_PARTIAL : ERV_MALFORMED;
	}
}

/* Parse the queries in a DNS packet */
eemo_rv eemo_parse_dns_queries(eemo_packet_buf* packet, eemo_dns_packet* dns_packet, unsigned short qdcount, unsigned long* offset, unsigned long parser_flags)
{
	int i = 0;
	eemo_rv rv = ERV_OK;

	for (i = 0; i < qdcount; i++)
	{
		eemo_dns_query* new_query = (eemo_dns_query*) malloc(sizeof(eemo_dns_query));

		if (new_query == NULL)
		{
			return ERV_MEMORY;
		}

		if ((rv = eemo_uncompress_dns_name(packet, offset, &new_query->qname, parser_flags)) != ERV_OK)
		{
			free(new_query);

			return rv;
		}

		PARSE_MSG("Query name: %s", new_query->qname);

		/* Check if there is enough space left for the query type and class */
		if ((*offset + 4) > packet->len)
		{
			free(new_query);

			return ERV_PARTIAL;
		}

		new_query->qtype = ntohs(*((unsigned short*) &packet->data[*offset]));
		*offset += 2;
		
		new_query->qclass = ntohs(*((unsigned short*) &packet->data[*offset]));
		*offset += 2;

		PARSE_MSG("Query type %d, query class %d", new_query->qtype, new_query->qclass);

		/* Append to list of questions */
		LL_APPEND(dns_packet->questions, new_query);
	}

	return ERV_OK;
}

/* Convert RDATA to a string */
char* eemo_rdata_to_string(eemo_dns_rr* rr)
{
	char* rv = NULL;

	if (rr->rdata == NULL)
	{
		PARSE_MSG("(null) RDATA");
		return rv;
	}

	switch(rr->type)
	{
	case DNS_QTYPE_A:
		rv = (char*) malloc(16 * sizeof(char)); /* 4x 3 digits + 3x '.' + \0 */

		if (rv != NULL)
		{
			snprintf(rv, 16, "%d.%d.%d.%d",
				(*((unsigned int*) rr->rdata) & 0xff000000) >> 24,
				(*((unsigned int*) rr->rdata) & 0x00ff0000) >> 16,
				(*((unsigned int*) rr->rdata) & 0x0000ff00) >> 8,
				(*((unsigned int*) rr->rdata) & 0x000000ff));
		}
		break;
	case DNS_QTYPE_AAAA:
		rv = (char*) malloc(40 * sizeof(char)); /* 8x 4 characters + 7x ':" + \0 */

		if (rv != NULL)
		{
			snprintf(rv, 40, "%x:%x:%x:%x:%x:%x:%x:%x",
				((unsigned short*) rr->rdata)[0],
				((unsigned short*) rr->rdata)[1],
				((unsigned short*) rr->rdata)[2],
				((unsigned short*) rr->rdata)[3],
				((unsigned short*) rr->rdata)[4],
				((unsigned short*) rr->rdata)[5],
				((unsigned short*) rr->rdata)[6],
				((unsigned short*) rr->rdata)[7]);
		}
		break;
	case DNS_QTYPE_CNAME:
		rv = strdup((char*) rr->rdata);
		break;
	case DNS_QTYPE_NS:
		rv = strdup((char*) rr->rdata);
		break;
	case DNS_QTYPE_OPT:
		{
			rv = (char*) malloc(256*sizeof(char));

			snprintf(rv, 256, "EDNS version %d, advertised buffer size %d bytes, extended RCODE %d, %d bytes RDATA", EDNS0_VERSION(rr), EDNS0_BUFSIZE(rr), EDNS0_EXT_RCODE(rr), rr->rdata_len);
		}
		break;
	case DNS_QTYPE_TXT:
		{
			txt_rdata* txt_it = NULL;
			txt_rdata* txt_list = (txt_rdata*) rr->rdata;

			LL_FOREACH(txt_list, txt_it)
			{
				if (rv != NULL)
				{
					size_t cur_len = strlen(rv);

					rv = (char*) realloc(rv, (cur_len + strlen(txt_it->string) + 2) * sizeof(char));
					
					sprintf(rv, "%s\n%s", rv, txt_it->string);
				}
				else
				{
					rv = strdup(txt_it->string);
				}
			}
		}
		break;
	case DNS_QTYPE_AFSDB:
	case DNS_QTYPE_APL:
	case DNS_QTYPE_CERT:
	case DNS_QTYPE_DHCID:
	case DNS_QTYPE_DLV:
	case DNS_QTYPE_DNAME:
	case DNS_QTYPE_DNSKEY:
	case DNS_QTYPE_DS:
	case DNS_QTYPE_HIP:
	case DNS_QTYPE_IPSECKEY:
	case DNS_QTYPE_KEY:
	case DNS_QTYPE_KX:
	case DNS_QTYPE_LOC:
	case DNS_QTYPE_MX:
	case DNS_QTYPE_NAPTR:
	case DNS_QTYPE_NSEC:
	case DNS_QTYPE_NSEC3:
	case DNS_QTYPE_NSEC3PARAM:
	case DNS_QTYPE_PTR:
	case DNS_QTYPE_RRSIG:
	case DNS_QTYPE_RP:
	case DNS_QTYPE_SIG:
	case DNS_QTYPE_SOA:
	case DNS_QTYPE_SPF:
	case DNS_QTYPE_SRV:
	case DNS_QTYPE_SSHFP:
	case DNS_QTYPE_TA:
	case DNS_QTYPE_TKEY:
	case DNS_QTYPE_TSIG:
	default:
		rv = (char*) malloc(128 * sizeof(char));

		snprintf(rv, 128, "%d byte%s unparsed RDATA", rr->rdata_len, rr->rdata_len == 1 ? "" : "s");

		break;
	}

	return rv;
}

#ifdef DNS_PARSE_DEBUG
#define LOG_RDATA(rr) log_rdata(rr)

void log_rdata(eemo_dns_rr* rr)
{
	char* rdata_string = eemo_rdata_to_string(rr);

	if (rdata_string != NULL)
	{
		PARSE_MSG("RDATA value %s", rdata_string);

		free(rdata_string);
	}
	else
	{
		PARSE_MSG("No RDATA string value available");
	}
}
#else // DNS_PARSE_DEBUG
#define LOG_RDATA(rr)
#endif // !DNS_PARSE_DEBUG

/* Parse the RDATA for an A record */
eemo_rv eemo_parse_dns_rr_a(eemo_packet_buf* packet, eemo_dns_rr* rr, unsigned long* offset, unsigned short rdata_len, unsigned long parser_flags)
{
	unsigned int* a_data = NULL;

	/* Check the RDATA length */
	if (rdata_len != 4)
	{
		PARSE_MSG("Invalid A record RDATA, wrong size(%d)", rdata_len);
		
		return ERV_MALFORMED;
	}

	/* Reserve memory */
	a_data = (unsigned int*) malloc(sizeof(unsigned int));

	if (a_data != NULL)
	{
		*a_data = ntohl(*((unsigned int*) &packet->data[*offset]));
		rr->rdata = a_data;
	}

	return ERV_OK;
}

/* Parse the RDATA for a AAAA record */
eemo_rv eemo_parse_dns_rr_aaaa(eemo_packet_buf* packet, eemo_dns_rr* rr, unsigned long* offset, unsigned short rdata_len, unsigned long parser_flags)
{
	unsigned short* aaaa_data = NULL;

	/* Check RDATA length */
	if (rdata_len != 16)
	{
		PARSE_MSG("Invalid AAAA record RDATA, wrong size(%d)", rdata_len);

		return ERV_MALFORMED;
	}

	/* Reserve memory */
	aaaa_data = (unsigned short*) malloc(8 * sizeof(unsigned short));

	if (aaaa_data != NULL)
	{
		int i = 0;

		memcpy(aaaa_data, &packet->data[*offset], 16);

		for (i = 0; i < 8; i++)
		{
			aaaa_data[i] = ntohs(aaaa_data[i]);
		}

		rr->rdata = aaaa_data;
	}

	return ERV_OK;
}

/* Parse the RDATA for an NS record */
eemo_rv eemo_parse_dns_rr_ns(eemo_packet_buf* packet, eemo_dns_rr* rr, unsigned long* offset, unsigned short rdata_len, unsigned long parser_flags)
{
	char* ns_rdata = NULL;
	unsigned long ofs = *offset;
	eemo_rv rv = ERV_OK;

	/* The RDATA is a DNS name, uncompress it */
	if ((rv = eemo_uncompress_dns_name(packet, &ofs, &ns_rdata, parser_flags)) == ERV_OK)
	{
		rr->rdata = ns_rdata;
	}

	return rv;
}

/* Parse the RDATA for an CNAME record */
eemo_rv eemo_parse_dns_rr_cname(eemo_packet_buf* packet, eemo_dns_rr* rr, unsigned long* offset, unsigned short rdata_len, unsigned long parser_flags)
{
	char* cname_rdata = NULL;
	unsigned long ofs = *offset;
	eemo_rv rv = ERV_OK;

	/* The RDATA is a DNS name, uncompress it */
	if ((rv = eemo_uncompress_dns_name(packet, &ofs, &cname_rdata, parser_flags)) == ERV_OK)
	{
		rr->rdata = cname_rdata;
	}

	return rv;
}

/* Parse the RDATA for a TXT record */
eemo_rv eemo_parse_dns_rr_txt(eemo_packet_buf* packet, eemo_dns_rr* rr, unsigned long* offset, unsigned short rdata_len, unsigned long parser_flags)
{
	unsigned long ofs = 0;
	txt_rdata* txt_data = NULL;
	eemo_rv rv = ERV_OK;

	/* The RDATA field contains 1 or more character strings */
	while (ofs < rdata_len)
	{
		txt_rdata* new_txt_rdata = NULL;
		unsigned char str_len = packet->data[*offset + ofs++];

		/* Check if the string fits in the remaining space */
		if ((rdata_len - ofs) < str_len)
		{
			PARSE_MSG("Warning: invalid string in TXT RR");

			rv = ERV_MALFORMED;
			break;
		}

		new_txt_rdata = (txt_rdata*) malloc(sizeof(txt_rdata));

		if (new_txt_rdata != NULL)
		{
			new_txt_rdata->string = (char*) malloc((str_len + 1) * sizeof(char));

			if (new_txt_rdata->string != NULL)
			{
				bzero(new_txt_rdata->string, (str_len + 1) * sizeof(char));

				memcpy(new_txt_rdata->string, &packet->data[*offset + ofs], str_len);

				LL_APPEND(txt_data, new_txt_rdata);
			}
			else
			{
				free(new_txt_rdata);
			}
		}

		ofs += str_len;
	}

	rr->rdata = txt_data;

	return rv;
}

/* Don't parse the RDATA field, simply copy it */
eemo_rv eemo_copy_dns_rdata(eemo_packet_buf* packet, eemo_dns_rr* rr, unsigned long* offset, unsigned short rdata_len)
{
	unsigned char* rdata = (unsigned char*) malloc(rdata_len*sizeof(unsigned char));

	if (rdata != NULL)
	{
		memcpy(rdata, &packet->data[*offset], rdata_len);

		rr->rdata_len = rdata_len;
		rr->rdata = rdata;

		return ERV_OK;
	}
	else
	{
		return ERV_MEMORY;
	}
}

/* Parse the RDATA field of a resource record */
eemo_rv eemo_parse_dns_rdata(eemo_packet_buf* packet, eemo_dns_rr* rr, unsigned long* offset, unsigned short rdata_len, unsigned int parser_flags)
{
	eemo_rv rv = ERV_OK;

	/* Reset the RDATA field */
	rr->rdata = NULL;
	rr->rdata_len = 0;

	/* Parse the RDATA based on the RR type */
	switch(rr->type)
	{
	case DNS_QTYPE_A:
		rv = eemo_parse_dns_rr_a(packet, rr, offset, rdata_len, parser_flags);
		break;
	case DNS_QTYPE_AAAA:
		rv = eemo_parse_dns_rr_aaaa(packet, rr, offset, rdata_len, parser_flags);
		break;
	case DNS_QTYPE_CNAME:
		rv = eemo_parse_dns_rr_cname(packet, rr, offset, rdata_len, parser_flags);
		break;
	case DNS_QTYPE_NS:
		rv = eemo_parse_dns_rr_ns(packet, rr, offset, rdata_len, parser_flags);
		break;
	case DNS_QTYPE_TXT:
		rv = eemo_parse_dns_rr_txt(packet, rr, offset, rdata_len, parser_flags);
		break;
	case DNS_QTYPE_OPT:
		/* Will be parsed lower down */
		rv = eemo_copy_dns_rdata(packet, rr, offset, rdata_len);
		break;
	default:
		PARSE_MSG("Unsupported or unparsed RR type %d", rr->type);
		rv = eemo_copy_dns_rdata(packet, rr, offset, rdata_len);
		break;
	}
	
	if (FLAG_SET(parser_flags, PARSE_RDATA_TO_STR))
	{
		rr->rdata_txt = eemo_rdata_to_string(rr);
	}

	LOG_RDATA(rr);

	return rv;
}

/* Parse the resource records in a DNS packet */
eemo_rv eemo_parse_dns_rrs(eemo_packet_buf* packet, eemo_dns_packet* dns_packet, eemo_dns_rr** rr_list, unsigned short count, unsigned long* offset, unsigned int parser_flags)
{
	int i = 0;
	eemo_rv rv = ERV_OK;

	/* Check parameters */
	if (rr_list == NULL)
	{
		return ERV_PARAM_INVALID;
	}

	for (i = 0; i < count; i++)
	{
		eemo_dns_rr* new_rr = (eemo_dns_rr*) malloc(sizeof(eemo_dns_rr));
		memset(new_rr, 0, sizeof(eemo_dns_rr));
		unsigned short rdata_len = 0;

		if (new_rr == NULL)
		{
			return ERV_MEMORY;
		}

		/* Retrieve the name for the RR */
		if ((rv = eemo_uncompress_dns_name(packet, offset, &new_rr->name, parser_flags)) != ERV_OK)
		{
			free(new_rr);

			return rv;
		}

		/* Retrieve the answer type, class, time-to-live and the size of the RDATA */
		if ((*offset + 10) > packet->len)
		{
			free(new_rr->name);
			free(new_rr);

			return ERV_PARTIAL;
		}

		new_rr->type = ntohs(*((unsigned short*) &packet->data[*offset]));
		*offset += 2;
		new_rr->class = ntohs(*((unsigned short*) &packet->data[*offset]));
		*offset += 2;
		new_rr->ttl = ntohl(*((int*) &packet->data[*offset]));
		*offset += 4;
		rdata_len = ntohs(*((unsigned short*) &packet->data[*offset]));
		*offset += 2;

		PARSE_MSG("RR for name: %s", new_rr->name);
		PARSE_MSG("RR type:%d class:%d TTL:%d RDATA length: %d octets", new_rr->type, new_rr->class, new_rr->ttl, rdata_len);

		/* Check if all RDATA is (potentially) there */
		if ((*offset + rdata_len) > packet->len)
		{
			free(new_rr->name);
			free(new_rr);

			return ERV_PARTIAL;
		}

		/* Parse the RDATA */
		if ((rv = eemo_parse_dns_rdata(packet, new_rr, offset, rdata_len, parser_flags)) != ERV_OK)
		{
			eemo_free_dns_rr_rdata(new_rr);
			free(new_rr->name);
			free(new_rr);

			PARSE_MSG("Parsing of RDATA failed, aborting parsing");

			return rv;
		}
		else
		{
			/* Check if it was an EDNS0 OPT RR */
			if (new_rr->type == DNS_QTYPE_OPT)
			{
				if (dns_packet->has_edns0)
				{
					/* Hmm... this is fishy! */
					WARNING_MSG("Multiple EDNS0 OPT RRs found in packet, retaining options from the last one");
				}

				/* The packet has an EDNS0 OPT RR */
				dns_packet->has_edns0		= 1;

				dns_packet->edns0_version	= EDNS0_VERSION(new_rr);
				dns_packet->edns0_max_size 	= EDNS0_BUFSIZE(new_rr);
				dns_packet->edns0_do		= EDNS0_DO_SET(new_rr);

				/* Check if there are EDNS0 options present */
				if (new_rr->rdata_len > 0)
				{
					unsigned short	rdata_ofs	= 0;
					unsigned short	rdata_len_rem	= new_rr->rdata_len;
					unsigned char*	rdata		= (unsigned char*) new_rr->rdata;

					/* There are options, parse them */
					while (rdata_len_rem >= 4)
					{
						unsigned short	opt_code	= 0;
						unsigned short	opt_len		= 0;
						
						opt_code = ntohs(*((unsigned short*) &rdata[rdata_ofs]));
						rdata_ofs += 2;

						opt_len = ntohs(*((unsigned short*) &rdata[rdata_ofs]));
						rdata_ofs += 2;

						rdata_len_rem -= 4;
						
						/* Check if there is enough RDATA remaining */
						if (rdata_len_rem < opt_len)
						{
							WARNING_MSG("Malformed EDNS0 OPT RDATA field; less RDATA remaining then the length specified in the option field");

							break;
						}

						/* Check if we know the option type, and if so, parse it */
						if (opt_code == EDNS0_OPT_CLIENT_SUBNET)
						{
							/* Check the length of the available data */
							if (opt_len >= 4)
							{
								unsigned short	addr_family	= 0;
								unsigned char	source_scope	= 0;
								unsigned char	resp_scope	= 0;
								unsigned char	addrlen		= 0;
								unsigned short	addrbytes	= 0;

								addr_family = ntohs(*((unsigned short*) &rdata[rdata_ofs]));
								rdata_ofs += 2;

								source_scope = rdata[rdata_ofs];
								rdata_ofs++;

								resp_scope = rdata[rdata_ofs];
								rdata_ofs++;

								rdata_len_rem -= 4;
								opt_len -= 4;

								dns_packet->edns0_client_subnet_src_scope = source_scope;
								dns_packet->edns0_client_subnet_res_scope = resp_scope;

								if (dns_packet->qr_flag)
								{
									addrlen = resp_scope;
								}
								else
								{
									addrlen = source_scope;

									if (resp_scope != 0)
									{
										WARNING_MSG("EDNS0 client subnet response scope is not set to 0 in query (set to %u)", resp_scope);
									}
								}

								switch(addr_family)
								{
								case 1:	/* AF_INET */
									if (addrlen > 32)
									{
										WARNING_MSG("EDNS0 client subnet scope exceeds limit for IPv4 (%u)", addrlen);
										addrlen = 32;
									}
									addr_family = AF_INET;
									break;
								case 2: /* AF_INET6 */
									if (addrlen > 128)
									{
										WARNING_MSG("EDNS0 client subnet scope exceeds limit for IPv6 (%u)", addrlen);
										addrlen = 128;
									}
									addr_family = AF_INET6;
									break;
								default:
									WARNING_MSG("Unknown EDNS0 client subnet address family %u", addr_family);
									break;
								}

								/* Nasty but effective... */
								addrbytes = (addrlen + 7) / 8;

								if (opt_len != addrbytes)
								{
									WARNING_MSG("Malformed EDNS0 client subnet partial IP, expected %u bytes, got %u bytes", addrbytes, opt_len);

									rdata_ofs += opt_len;
									rdata_len_rem -= opt_len;
								}
								else
								{
									unsigned char	addr[16]	= { 0 };
									int		i		= 0;

									for (i = 0; i < addrbytes; i++)
									{
										addr[i] = rdata[rdata_ofs];
										rdata_ofs++;
										rdata_len_rem--;
									}

									/* Convert to string */
									if (inet_ntop(addr_family, addr, dns_packet->edns0_client_subnet_ip, INET6_ADDRSTRLEN) == NULL)
									{
										WARNING_MSG("Failed to convert EDNS0 client subnet partial IP to string");
									}
									else
									{
										dns_packet->has_edns0_client_subnet = 1;
									}
								}
							}
						}
						else if (opt_code > 65000)
						{
							dns_packet->has_edns0_exp_opt = 1;
						}
						else
						{
							WARNING_MSG("Unrecognised EDNS0 option %u", opt_code);

							/* Skip over the option data */
							rdata_ofs += opt_len;
							rdata_len_rem -= opt_len;
						}
					}

					if (rdata_len_rem != 0)
					{
						/* EDNS0 OPT RDATA was malformed! */
						WARNING_MSG("Malformed EDNS0 OPT RDATA field");
					}
				}
			}

			PARSE_MSG("EDNS0 data present, version %d, maximum response size %u, DO=%u", dns_packet->edns0_version, dns_packet->edns0_max_size, dns_packet->edns0_do);

			if (dns_packet->has_edns0_client_subnet)
			{
				PARSE_MSG("EDNS0 client subnet option scoped to %s/%u", dns_packet->edns0_client_subnet_ip, dns_packet->qr_flag ? dns_packet->edns0_client_subnet_res_scope : dns_packet->edns0_client_subnet_src_scope);
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
eemo_rv eemo_parse_dns_packet(eemo_packet_buf* packet, eemo_dns_packet* dns_packet, unsigned long parser_flags, unsigned short udp_len, int is_fragmented)
{
	eemo_hdr_dns* hdr = NULL;
	unsigned long ofs = sizeof(eemo_hdr_dns);
	eemo_rv rv = ERV_OK;

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
	hdr = (eemo_hdr_dns*) packet->data;
	eemo_dns_hdr_ntoh(hdr);

	PARSE_MSG("Parsing DNS packet with:");
	PARSE_MSG("%d questions (QDCOUNT)", hdr->dns_qdcount);
	PARSE_MSG("%d answers (ANCOUNT)", hdr->dns_ancount);
	PARSE_MSG("%d authorities (NSCOUNT)", hdr->dns_nscount);
	PARSE_MSG("%d additionals (ARCOUNT)", hdr->dns_arcount);

	/* Copy the query ID, flags, OPCODE and RCODE */
	dns_packet->query_id 	= hdr->dns_qid;
	dns_packet->qr_flag 	= FLAG_SET(hdr->dns_flags, DNS_QRFLAG);
	dns_packet->aa_flag	= FLAG_SET(hdr->dns_flags, DNS_AAFLAG);
	dns_packet->tc_flag 	= FLAG_SET(hdr->dns_flags, DNS_TCFLAG);
	dns_packet->ra_flag 	= FLAG_SET(hdr->dns_flags, DNS_RAFLAG);
	dns_packet->rd_flag	= FLAG_SET(hdr->dns_flags, DNS_RDFLAG);
	dns_packet->opcode	= DNS_OPCODE(hdr->dns_flags);
	dns_packet->rcode	= DNS_RCODE(hdr->dns_flags);
	dns_packet->ans_count	= hdr->dns_ancount;
	dns_packet->aut_count	= hdr->dns_nscount;
	dns_packet->add_count	= hdr->dns_arcount;

	PARSE_MSG("Query ID: %d", dns_packet->query_id);
	PARSE_MSG("Flags:%s%s%s%s%s",
		dns_packet->qr_flag ? " QR" : "",
		dns_packet->aa_flag ? " AA" : "",
		dns_packet->tc_flag ? " TC" : "",
		dns_packet->ra_flag ? " RA" : "",
		dns_packet->rd_flag ? " RD" : "");
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
	if ((rv = eemo_parse_dns_queries(packet, dns_packet, hdr->dns_qdcount, &ofs, parser_flags)) != ERV_OK)
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

	if ((rv = eemo_parse_dns_rrs(packet, dns_packet, &dns_packet->answers, hdr->dns_ancount, &ofs, parser_flags)) != ERV_OK)
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

	if ((rv = eemo_parse_dns_rrs(packet, dns_packet, &dns_packet->authorities, hdr->dns_nscount, &ofs, parser_flags)) != ERV_OK)
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

	if ((rv = eemo_parse_dns_rrs(packet, dns_packet, &dns_packet->additionals, hdr->dns_arcount, &ofs, parser_flags)) != ERV_OK)
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
}

