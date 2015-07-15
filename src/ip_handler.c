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
 * IP packet handling
 */

#include "config.h"
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "eemo.h"
#include "utlist.h"
#include "eemo_handlefactory.h"
#include "eemo_log.h"
#include "ip_handler.h"
#include "ether_handler.h"
#include "ip_metadata.h"
#include "eemo_config.h"
#include "ip_reassemble.h"

/* The handles for the IPv4 and IPv6 Ethernet handlers */
static unsigned long	ip4handler_handle	= 0;
static unsigned long	ip6handler_handle	= 0;

/* The linked list of IP packet handlers */
static eemo_ip_handler*	ip_handlers 		= NULL;

/* Metadata handling configuration */
static int		md_lookup_src		= 1;	/* Perform metadata lookup for source IP? */
static int		md_lookup_dst		= 1;	/* Perform metadata lookup for destination IP? */

/* Handle an IPv4 packet */
eemo_rv eemo_handle_ipv4_packet(const eemo_packet_buf* packet, eemo_ether_packet_info ether_info)
{
	u_char			version		= 0;
	eemo_ip_packet_info	ip_info;
	u_short			offset		= 0;
	eemo_ip_handler*	handler_it	= NULL;
	eemo_rv			rv		= ERV_SKIPPED;
	u_short			ip_proto	= 0;
	eemo_packet_buf		ip_data		= { NULL, 0 };
	/*u_short			ip4_len		= 0;*/	/* TODO: we'll need this for reassembly */
	u_short			ip4_id		= 0;
	u_short			ip4_ofs		= 0;
	int			release_ra	= 0;

	/* Clear ip_info structure */
	memset(&ip_info, 0, sizeof(ip_info));

	/* Copy timestamp */
	memcpy(&ip_info.ts, &ether_info.ts, sizeof(struct timeval));

	/* Packets smaller than 1 byte are malformed... */
	if (packet->len < 1)
	{
		/* Packet is malformed */
		return ERV_MALFORMED;
	}

	/* Check the version number */
	version = (packet->data[0] & 0xF0) >> 4;

	if (version == IP_TYPE_V4)
	{
		eemo_hdr_ipv4* hdr = NULL;

		/* Check minimum length */
		if (packet->len < sizeof(eemo_hdr_ipv4))
		{
			/* Packet is malformed */
			return ERV_MALFORMED;
		}

		/* Take the header from the packet */
		hdr = (eemo_hdr_ipv4*) packet->data;

		/* Convert to host byte order */
		/*ip4_len	= ntohs(hdr->ip4_len);*/	/* TODO: we'll need this for reassembly */
		ip4_id	= ntohs(hdr->ip4_id);
		ip4_ofs	= ntohs(hdr->ip4_ofs);

		/*
		 * FIXME: if we are every going to do anything with the IPv4 checksum
		 *        field, it should be converted to host byte order first
		 */

		/* Check header length */
		if (IP_HDRLEN(hdr->ip4_ver_hl) < 5)
		{
			ERROR_MSG("Malformed IPv4 packet (header length %d < 5)", IP_HDRLEN(hdr->ip4_ver_hl));

			return ERV_MALFORMED;
		}
		else if (IP_HDRLEN(hdr->ip4_ver_hl) > 5)
		{
			DEBUG_MSG("IPv4 packet with options (header length %d words)", IP_HDRLEN(hdr->ip4_ver_hl));
		}

		/* Copy relevant information to the ip_info structure */
		ip_info.fragment_ofs 	= (ip4_ofs & IPV4_FRAGMASK) * 8;
		ip_info.is_fragment 	= (ip_info.fragment_ofs > 0) || FLAG_SET(ip4_ofs, IPV4_MOREFRAG);
		ip_info.more_frags 	= FLAG_SET(ip4_ofs, IPV4_MOREFRAG);
		ip_info.ip_type 	= IP_TYPE_V4;
		ip_info.ip_id		= ip4_id;
		ip_info.ttl		= hdr->ip4_ttl;

		if (inet_ntop(AF_INET, hdr->ip4_src, ip_info.ip_src, INET6_ADDRSTRLEN) == NULL)
		{
			DEBUG_MSG("Failed to convert source IPv4 address to string representation");
		}

		if (inet_ntop(AF_INET, hdr->ip4_dst, ip_info.ip_dst, INET6_ADDRSTRLEN) == NULL)
		{
			DEBUG_MSG("Failed to convert destination IPv4 address to string representation");
		}
		memcpy(&ip_info.src_addr.v4, hdr->ip4_src, 4);
		memcpy(&ip_info.dst_addr.v4, hdr->ip4_dst, 4);

		/* Determine the offset */
		offset = IP_HDRLEN(hdr->ip4_ver_hl) << 2;

		/* Determine the IP protocol */
		ip_proto = hdr->ip4_proto;

		/* Take IP data */
		eemo_pbuf_shrink(&ip_data, packet, offset);

		/* If this is a fragment, try to reassemble it */
		if (ip_info.is_fragment)
		{
			eemo_rv	ra_rv	= eemo_reasm_v4_fragment((struct in_addr*) &ip_info.src_addr.v4, (struct in_addr*) &ip_info.dst_addr.v4, ip_proto, ip_info.ip_id, ip_info.fragment_ofs, &ip_data, !FLAG_SET(ip4_ofs, IPV4_MOREFRAG), &ip_data);

			switch(ra_rv)
			{
			case ERV_NEED_MORE_FRAGS:
				return ERV_HANDLED;
			case ERV_REASM_DISABLED:
				break;
			case ERV_REASM_FAILED:
				return ERV_SKIPPED;
			case ERV_OK:
				release_ra = 1; /* need to release the reassembled packet after processing */
				ip_info.is_reassembled = 1;
				break;
			default:
				ERROR_MSG("Unexpected return value 0x%08X from IP reassembly module", ra_rv);
				return ERV_SKIPPED;
			}
		}

		/* Perform IP-to-AS and Geo IP lookup */
		if (md_lookup_src)
		{
			eemo_md_lookup_as_v4((struct in_addr*) &ip_info.src_addr.v4, &ip_info.src_as_short, &ip_info.src_as_full);
			eemo_md_lookup_geoip_v4((struct in_addr*) &ip_info.src_addr.v4, &ip_info.src_geo_ip);
		}

		if (md_lookup_dst)
		{
			eemo_md_lookup_as_v4((struct in_addr*) &ip_info.dst_addr.v4, &ip_info.dst_as_short, &ip_info.dst_as_full);
			eemo_md_lookup_geoip_v4((struct in_addr*) &ip_info.dst_addr.v4, &ip_info.dst_geo_ip);
		}
	}
	else
	{
		/* Eek! Unknown IP version number */
		return ERV_MALFORMED;
	}

	/* See if there are handlers for this type of packet */
	LL_FOREACH(ip_handlers, handler_it)
	{
		eemo_rv handler_rv = ERV_SKIPPED;

		if ((handler_it->handler_fn != NULL) && (handler_it->which_ip_proto == ip_proto))
		{
			handler_rv = (handler_it->handler_fn)(&ip_data, ip_info);
		}

		if (rv != ERV_HANDLED)
		{
			rv = handler_rv;
		}
	}

	/* Clean up */
	free(ip_info.src_as_short);
	free(ip_info.src_as_full);
	free(ip_info.src_geo_ip);
	free(ip_info.dst_as_short);
	free(ip_info.dst_as_full);
	free(ip_info.dst_geo_ip);

	if (release_ra)
	{
		eemo_reasm_v4_free((struct in_addr*) &ip_info.src_addr.v4, (struct in_addr*) &ip_info.dst_addr.v4, ip_proto, ip_info.ip_id);
	}

	return rv;
}

/* Handle an IPv6 packet */
eemo_rv eemo_handle_ipv6_packet(const eemo_packet_buf* packet, eemo_ether_packet_info ether_info)
{
	u_char			version		= 0;
	eemo_ip_packet_info	ip_info;
	u_short			offset		= 0;
	eemo_ip_handler*	handler_it	= NULL;
	eemo_rv			rv		= ERV_SKIPPED;
	u_short			ip_proto	= 0;
	eemo_packet_buf		ip_data		= { NULL, 0 };
	int			release_ra	= 0;
	/*u_short			ip6_len		= 0;*/	/* TODO: we'll need this for reassembly */

	/* Clear ip_info structure */
	memset(&ip_info, 0, sizeof(ip_info));	

	/* Copy timestamp */
	memcpy(&ip_info.ts, &ether_info.ts, sizeof(struct timeval));

	/* Packets smaller than 1 byte are malformed... */
	if (packet->len < 1)
	{
		/* Packet is malformed */
		return ERV_MALFORMED;
	}

	/* Check the version number */
	version = (packet->data[0] & 0xF0) >> 4;

	if (version == IP_TYPE_V6)
	{
		eemo_hdr_ipv6*	hdr		= NULL;
		int		skip_ext_hdr	= 1;

		/* Check minimum length */
		if (packet->len < sizeof(eemo_hdr_ipv6))
		{
			/* Packet is malformed */
			return ERV_MALFORMED;
		}

		/* Take the header from the packet */
		hdr = (eemo_hdr_ipv6*) packet->data;

		/* Copy binary source and destination address in network byte order */
		memcpy(ip_info.src_addr.v6, hdr->ip6_src, 8 * sizeof(u_short));
		memcpy(ip_info.dst_addr.v6, hdr->ip6_dst, 8 * sizeof(u_short));

		/* Convert to host byte order */
		/*ip6_len	= ntohs(hdr->ip6_len);*/ /* TODO: we'll need this for reassembly */

		/* Copy relevant information to the ip_info structure */
		ip_info.fragment_ofs	= 0; /* currently not supported */
		ip_info.is_fragment	= 0; /* currently not supported */
		ip_info.more_frags 	= 0; /* currently not supported */
		ip_info.ip_type		= IP_TYPE_V6;

		if (inet_ntop(AF_INET6, hdr->ip6_src, ip_info.ip_src, INET6_ADDRSTRLEN) == NULL)
		{
			DEBUG_MSG("Failed to convert source IPv6 address to string representation");
		}

		if (inet_ntop(AF_INET6, hdr->ip6_dst, ip_info.ip_dst, INET6_ADDRSTRLEN) == NULL)
		{
			DEBUG_MSG("Failed to convert destination IPv6 address to string representation");
		}

		ip_info.ttl		= hdr->ip6_hop_lmt;

		/* Determine the offset */
		offset = sizeof(eemo_hdr_ipv6);

		/* Determine the IP protocol */
		ip_proto = hdr->ip6_next_hdr;

		/* Take IP data */
		eemo_pbuf_shrink(&ip_data, packet, offset);

		/* Skip over extension headers so we get to the "meat" of the packet */
		while (skip_ext_hdr && (ip_data.len > 0))
		{
			if (ip_proto == IPV6_NH_ROUTING)
			{
				DEBUG_MSG("Skipping IPv6 routing extension header");
			}
			else if (ip_proto == IPV6_NH_ESP)
			{
				DEBUG_MSG("IPv6 IPsec packet, cannot handle encrypted traffic, skipping whole packet");

				return ERV_SKIPPED;
			}
			else if (ip_proto == IPV6_NH_AH)
			{
				DEBUG_MSG("IPv6 IPsec packet, cannot handle encrypted traffic, skipping whole packet");

				return ERV_SKIPPED;
			}
			else if (ip_proto == IPV6_NH_OPTIONS)
			{
				DEBUG_MSG("Skipping IPv6 options extension header");
			}
			else if (ip_proto == IPV6_NH_MOBILITY)
			{
				DEBUG_MSG("Skipping IPv6 mobility extension header");
			}
			else if (ip_proto == IPV6_NH_HIP)
			{
				DEBUG_MSG("Skipping IPv6 host-identification-protocol extension header");
			}
			else if (ip_proto == IPV6_NH_SHIM6)
			{
				DEBUG_MSG("Skipping IPv6 SHIM6 extension header");
			}
			else if (ip_proto == IPV6_NH_EXP1)
			{
				DEBUG_MSG("Skipping IPv6 experimental extension header (253)");
			}
			else if (ip_proto == IPV6_NH_EXP2)
			{
				DEBUG_MSG("Skipping IPv6 experimental extension header (254)");
			}
			else
			{
				skip_ext_hdr = 0;
			}

			if (skip_ext_hdr)
			{
				eemo_hdr_ipv6_generic_ext*	ext_h	= (eemo_hdr_ipv6_generic_ext*) &ip_data.data[0];

				ip_proto = ext_h->ip6_next_hdr;

				eemo_pbuf_shrink(&ip_data, &ip_data, (ext_h->ip6_hdr_len + 1) * 8);
			}
		}

		if (ip_proto == IPV6_NH_FRAG)
		{
			/* This is a fragment */
			eemo_rv			ra_rv		= 0;
			eemo_hdr_ipv6_frag_ext*	frag_hdr	= (eemo_hdr_ipv6_frag_ext*) &ip_data.data[0];
			u_short			ip_ofs		= 0;
			u_char			is_last		= 0;

			if (ip_data.len < sizeof(eemo_hdr_ipv6_frag_ext))
			{
				ERROR_MSG("Invalid fragment extension header in IPv6 packet");

				return ERV_SKIPPED;
			}

			ip_ofs		= IPV6_FRAG_OFS(ntohs(frag_hdr->ip6_ofs));
			is_last		= IPV6_FRAG_IS_LAST(ntohs(frag_hdr->ip6_ofs));
			ip_info.ip6_id	= ntohl(frag_hdr->ip6_id);

			/* Remove fragment extension header */
			eemo_pbuf_shrink(&ip_data, &ip_data, sizeof(eemo_hdr_ipv6_frag_ext));

			ra_rv = eemo_reasm_v6_fragment((const struct in6_addr*) &ip_info.src_addr.v6, (const struct in6_addr*) &ip_info.dst_addr.v6, ip_info.ip6_id, ip_ofs, &ip_data, is_last, &ip_data);

			switch(ra_rv)
			{
			case ERV_NEED_MORE_FRAGS:
				return ERV_HANDLED;
			case ERV_REASM_DISABLED:
				break;
			case ERV_REASM_FAILED:
				return ERV_SKIPPED;
			case ERV_OK:
				release_ra = 1; /* need to release the reassembled packet after processing */
				ip_info.is_reassembled = 1;
				break;
			default:
				ERROR_MSG("Unexpected return value 0x%08X from IP reassembly module", ra_rv);
				return ERV_SKIPPED;
			}

			ip_proto = frag_hdr->ip6_next_hdr;
		}

		/* Perform IP-to-AS and Geo IP lookup */
		if (md_lookup_src)
		{
			eemo_md_lookup_as_v6((struct in6_addr*) &ip_info.src_addr.v6, &ip_info.src_as_short, &ip_info.src_as_full);
			eemo_md_lookup_geoip_v6((struct in6_addr*) &ip_info.src_addr.v6, &ip_info.src_geo_ip);
		}

		if (md_lookup_dst)
		{
			eemo_md_lookup_as_v6((struct in6_addr*) &ip_info.dst_addr.v6, &ip_info.dst_as_short, &ip_info.dst_as_full);
			eemo_md_lookup_geoip_v6((struct in6_addr*) &ip_info.dst_addr.v6, &ip_info.dst_geo_ip);
		}
	}
	else
	{
		/* Eek! Unknown IP version number */
		return ERV_MALFORMED;
	}

	/* See if there are handlers for this type of packet */
	LL_FOREACH(ip_handlers, handler_it)
	{
		eemo_rv handler_rv = ERV_SKIPPED;

		if ((handler_it->handler_fn != NULL) && (handler_it->which_ip_proto == ip_proto))
		{
			handler_rv = (handler_it->handler_fn)(&ip_data, ip_info);
		}

		if (rv != ERV_HANDLED)
		{
			rv = handler_rv;
		}
	}

	/* Clean up */
	free(ip_info.src_as_short);
	free(ip_info.src_as_full);
	free(ip_info.src_geo_ip);
	free(ip_info.dst_as_short);
	free(ip_info.dst_as_full);
	free(ip_info.dst_geo_ip);

	if (release_ra)
	{
		eemo_reasm_v6_free((const struct in6_addr*) &ip_info.src_addr.v6, (const struct in6_addr*) &ip_info.dst_addr.v6, ip_info.ip6_id);
	}

	return rv;
}

/* Register an IP handler */
eemo_rv eemo_reg_ip_handler(u_short which_ip_proto, eemo_ip_handler_fn handler_fn, unsigned long* handle)
{
	eemo_ip_handler* new_handler = NULL;

	/* Check parameters */
	if ((handler_fn == NULL) || (handle == NULL))
	{
		return ERV_PARAM_INVALID;
	}

	/* Create a new handler entry */
	new_handler = (eemo_ip_handler*) malloc(sizeof(eemo_ip_handler));

	if (new_handler == NULL)
	{
		/* Not enough memory */
		return ERV_MEMORY;
	}

	new_handler->which_ip_proto = which_ip_proto;
	new_handler->handler_fn = handler_fn;
	new_handler->handle = eemo_get_new_handle();

	/* Register the new handler */
	LL_APPEND(ip_handlers, new_handler);

	*handle = new_handler->handle;

	DEBUG_MSG("Registered IP handle with handle 0x%08X and handler function at 0x%08X", *handle, handler_fn);

	return ERV_OK;
}

/* Unregister an IP handler */
eemo_rv eemo_unreg_ip_handler(unsigned long handle)
{
	eemo_ip_handler* to_delete = NULL;

	LL_SEARCH_SCALAR(ip_handlers, to_delete, handle, handle);

	if (to_delete != NULL)
	{
		LL_DELETE(ip_handlers, to_delete);

		DEBUG_MSG("Unregistered IP handler with handle 0x%08X and handler function at 0x%08X", handle, to_delete->handler_fn);

		free(to_delete);

		eemo_recycle_handle(handle);

		return ERV_OK;
	}
	else
	{
		return ERV_NOT_FOUND;
	}
}

/* Initialise IP handling */
eemo_rv eemo_init_ip_handler(void)
{
	eemo_rv rv = ERV_OK;
	ip_handlers = NULL;

	/* Register IPv4 packet handler */
	rv = eemo_reg_ether_handler(ETHER_IPV4, &eemo_handle_ipv4_packet, &ip4handler_handle);

	if (rv != ERV_OK)
	{
		return rv;
	}

	/* Register IPv6 packet handler */
	rv = eemo_reg_ether_handler(ETHER_IPV6, &eemo_handle_ipv6_packet, &ip6handler_handle);

	if (rv != ERV_OK)
	{
		eemo_unreg_ether_handler(ip4handler_handle);
	}

	/* Retrieve metadata handling configuration */
	if (eemo_conf_get_bool("metadata", "lookup_src_ip", &md_lookup_src, 1) != ERV_OK)
	{
		ERROR_MSG("Failed to retrieve metadata configuration setting (source lookup)");
	}

	if (eemo_conf_get_bool("metadata", "lookup_dst_ip", &md_lookup_dst, 1) != ERV_OK)
	{
		ERROR_MSG("Failed to retrieve metadata configuration setting (source lookup)");
	}

	INFO_MSG("Will %slook up metadata for source IPs", md_lookup_src ? "" : "not ");
	INFO_MSG("Will %slook up metadata for destination IPs", md_lookup_dst ? "" : "not ");

	INFO_MSG("Initialised IP handling");

	return rv;
}

/* Clean up */
void eemo_ip_handler_cleanup(void)
{
	eemo_ip_handler* handler_it;
	eemo_ip_handler* handler_tmp;

	/* Clean up the list of IP packet handlers */
	LL_FOREACH_SAFE(ip_handlers, handler_it, handler_tmp)
	{
		LL_DELETE(ip_handlers, handler_it);
		
		free(handler_it);
	}

	/* Unregister the Ethernet handler for IPv4 and IPv6 packets */
	eemo_unreg_ether_handler(ip4handler_handle);
	eemo_unreg_ether_handler(ip6handler_handle);

	INFO_MSG("Uninitialised IP handling");
}

