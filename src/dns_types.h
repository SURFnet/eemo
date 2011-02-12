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
 * The Extensible IP Monitor (EEMO)
 * DNS types
 */

#ifndef _EEMO_DNS_TYPES_H
#define _EEMO_DNS_TYPES_H

#include "config.h"

/* DNS port */
#define DNS_PORT	53

/* DNS flags */
#define DNS_QRFLAG	0x8000
#define DNS_AAFLAG	0x0400
#define DNS_TCFLAG	0x0200
#define DNS_RDFLAG	0x0100
#define DNS_RAFLAG	0x0080
#define DNS_OPCODE(flags) ((flags & 0x7800) >> 11)
#define DNS_RCODE(flags) (flags & 0x000f)

/* Standard query types */
#define DNS_QTYPE_UNSPECIFIED	0		/* matches any query */
#define DNS_QTYPE_A		1		/* A record (IPv4 address) */
#define DNS_QTYPE_AAAA		28		/* AAAA record (IPv6 address) */
#define DNS_QTYPE_AFSDB		18		/* Andrew Filesystem DB */
#define DNS_QTYPE_APL		42		/* Address Prefix List */
#define DNS_QTYPE_CERT		37		/* Digital certificate (PKIX, SPKI, PGP) */
#define DNS_QTYPE_CNAME		5		/* Canonical name */
#define DNS_QTYPE_DHCID		49		/* DHCP ID */
#define DNS_QTYPE_DLV		32769		/* DNSSEC Look-a-side Validation */
#define DNS_QTYPE_DNAME		39		/* Delegation name */
#define DNS_QTYPE_DNSKEY	48		/* DNSKEY record */
#define DNS_QTYPE_DS		43		/* Delegation signer */
#define DNS_QTYPE_HIP		55		/* Host Identity Protocol */
#define DNS_QTYPE_IPSECKEY	45		/* IPsec key */
#define DNS_QTYPE_KEY		25		/* Key for TSIG or SIG(0) */
#define DNS_QTYPE_KX		36		/* Key exchanger */
#define DNS_QTYPE_LOC		29		/* Location record */
#define DNS_QTYPE_MX		15		/* Mail eXchange */
#define DNS_QTYPE_NAPTR		35		/* Naming Authority Pointer */
#define DNS_QTYPE_NS		2		/* Name Server record */
#define DNS_QTYPE_NSEC		47		/* Next Secure record */
#define DNS_QTYPE_NSEC3		50		/* Next Secure version 3 */
#define DNS_QTYPE_NSEC3PARAM	51		/* NSEC3 parameters */
#define DNS_QTYPE_PTR		12		/* Pointer record */
#define DNS_QTYPE_RRSIG		46		/* RR signature */
#define DNS_QTYPE_RP		17		/* Responsible Person */
#define DNS_QTYPE_SIG		24		/* Signature for TSIG or SIG(0) */
#define DNS_QTYPE_SOA		6		/* Start Of Authority */
#define DNS_QTYPE_SPF		99		/* Sender Policy Framework */
#define DNS_QTYPE_SRV		33		/* Generic Server record */
#define DNS_QTYPE_SSHFP		44		/* SSH fingerprint */
#define DNS_QTYPE_TA		32768		/* Trusted Authority */
#define DNS_QTYPE_TKEY		249		/* Trusted Key secret */
#define DNS_QTYPE_TSIG		250		/* Transaction Signature */
#define DNS_QTYPE_TXT		16		/* Text Record */

/* Special query types */
#define DNS_QTYPE_ANY		255		/* Any record type */
#define DNS_QTYPE_AXFR		252		/* Transfer */
#define DNS_QTYPE_IXFR		251		/* Incremental Transfer */
#define DNS_QTYPE_OPT		41		/* Options for EDNS */

/* Standard query classes */
#define DNS_QCLASS_UNSPECIFIED	0		/* Matches any class */
#define DNS_QCLASS_IN		1		/* Internet */
#define DNS_QCLASS_CS		2		/* CSNET class, obsolete */
#define DNS_QCLASS_CH		3		/* Chaos */
#define DNS_QCLASS_HS		4		/* Hesiod */

/* Special query classes */
#define DNS_QCLASS_ANY		255		/* Any class */

#endif /* !_EEMO_DNS_TYPES_H */

