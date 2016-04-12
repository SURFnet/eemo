/*
 * Copyright (c) 2010-2016 SURFnet bv
 * Copyright (c) 2016 Roland van Rijswijk-Deij
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
 * IP reassembly
 */

#include "config.h"
#include "ip_reassemble.h"
#include "eemo.h"
#include "eemo_packet.h"
#include "eemo_log.h"
#include "eemo_config.h"
#include <pcap.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

/* Set this define to provide extra debug logging about reassembly */
/*#define FRAG_DBG*/
#undef FRAG_DBG 

#ifdef FRAG_DBG
#define FRAG_MSG(...) DEBUG_MSG(__VA_ARGS__)
#else
#define FRAG_MSG(...)
#endif

/* Reassembly identification of an IPv4 packet */
typedef struct
{
	int		af;
	struct in_addr	src;
	struct in_addr	dst;
	u_char		proto;
	u_short		id;
}
ip4_reasm_id;

/* Reassembly identification of an IPv6 packet */
typedef struct
{
	int		af;
	struct in6_addr	src;
	struct in6_addr	dst;
	u_int		id;
}
ip6_reasm_id;

/* Generic reassembly identification structure */
typedef struct
{
	int		af;
}
generic_reasm_id;

/* Abstract reassembly identification type */
typedef union
{
	ip4_reasm_id		ip4_id;
	ip6_reasm_id		ip6_id;
	generic_reasm_id	gen_id;
}
ip_reasm_id;

/* Reassembly buffer type */
typedef struct
{
	ip_reasm_id	id;
	time_t		first_frag_arr;		/* arrival time of first fragment, needed to time reassembly */
	int		in_use;			/* is the buffer in use? */
	int		reassembled;		/* set to true if reassembly is complete */
	u_char		buffer[65536];
	u_short		first_hole;		/* pointer to the first hole descriptor */
	u_short		frag_count;		/* total number of fragments that make up the packet */
	int		pkt_len;		/* the expected reassembled length; set to -1 if unknown */
}
ip_reasm_buf;

/* Hole descriptor */
#define HD_NULL		0xffff

#pragma pack(push,1)
typedef struct
{
	u_short	hd_first;	/* Offset of first octet */
	u_short	hd_last;	/* Offset of last octet */
	u_short	hd_next;	/* Offset of next hole descriptor */
}
hole_desc;
#pragma pack(pop)

/* Module variables */
static ip_reasm_buf*	ra_buffers	= NULL;
static int		ra_buf_count	= -1;
static int		ra_timeout	= -1;
static int		ra_enabled	= 1;
static int		ra_log		= 1;

/* Initialise reassembly module */
eemo_rv eemo_reasm_init(void)
{
	int	i	= 0;

	if (eemo_conf_get_bool("ip", "reassemble", &ra_enabled, 1) != ERV_OK)
	{
		ERROR_MSG("Failed to retrieve configuration setting for IP reassembly");

		return ERV_CONFIG_ERROR;
	}

	if (!ra_enabled)
	{
		INFO_MSG("IP reassembly is disabled");

		return ERV_OK;
	}

	if ((eemo_conf_get_int("ip", "reassembly_timeout", &ra_timeout, 30) != ERV_OK) || (ra_timeout <= 0))
	{
		ERROR_MSG("Failed to retrieve configuration setting for IP reassembly timeout");

		return ERV_CONFIG_ERROR;
	}

	if (ra_timeout < 30)
	{
		WARNING_MSG("IP reassembly timeout is set to a value below that of most operating systems (%ds < 30s)", ra_timeout);
	}

	if ((eemo_conf_get_int("ip", "reassembly_buffers", &ra_buf_count, 1000) != ERV_OK) || (ra_buf_count <= 0))
	{
		ERROR_MSG("Failed to retrieve number of IP reassembly buffers from the configuration");

		return ERV_CONFIG_ERROR;
	}

	if (eemo_conf_get_bool("ip", "reassemble_log", &ra_log, 1) != ERV_OK)
	{
		ERROR_MSG("Failed to retrieve reassembly log setting from the configuration");

		return ERV_CONFIG_ERROR;
	}

	/* Allocate and clear reassembly buffers */
	ra_buffers = (ip_reasm_buf*) malloc(ra_buf_count * sizeof(ip_reasm_buf));

	for (i = 0; i < ra_buf_count; i++)
	{
		memset(&ra_buffers[i], 0, sizeof(ip_reasm_buf));
		ra_buffers[i].pkt_len = -1;
	}

	INFO_MSG("Initialised %d IP reassembly buffers", ra_buf_count);

	return ERV_OK;
}

/* Uninitialise reassembly module */
eemo_rv eemo_reasm_finalize(void)
{
	if (ra_enabled)
	{
		int	i		= 0;
		int	in_use_ct	= 0;
		int	reass_ct	= 0;

		for (i = 0; i < ra_buf_count; i++)
		{
			if (ra_buffers[i].in_use)
			{
				if (!ra_buffers[i].reassembled)
				{
					in_use_ct++;
				}
				else
				{
					reass_ct++;
				}
			}
		}

		if (in_use_ct > 0)
		{
			WARNING_MSG("%d reassembly buffers with partially reassembled packets still in use on exit", in_use_ct);
		}

		if (reass_ct > 0)
		{
			WARNING_MSG("%d reassembly buffers with fully reassembled packets still in use on exit", reass_ct);
		}

		/* Clean up */
		free(ra_buffers);
	}

	INFO_MSG("Finalised IP reassembly module");

	return ERV_OK;
}

/* Get a string representation of the source IP address in a reassembly ID */
static const char* eemo_reasm_int_get_src_str(const ip_reasm_id* id)
{
	assert(id != NULL);

	/* WARNING! It is not safe to call this function from multiple threads concurrently */
	static char		ip_str[INET6_ADDRSTRLEN]	= { 0 };
	const generic_reasm_id*	gen_id				= &id->gen_id;
	const ip4_reasm_id*	ip4_id				= &id->ip4_id;
	const ip6_reasm_id*	ip6_id				= &id->ip6_id;

	if (gen_id->af == AF_INET)
	{
		if (inet_ntop(AF_INET, &ip4_id->src, ip_str, INET6_ADDRSTRLEN) == NULL)
		{
			WARNING_MSG("Failed to convert IPv4 source address from reassembly ID to string");

			return NULL;
		}
	}
	else if (gen_id->af == AF_INET6)
	{
		if (inet_ntop(AF_INET6, &ip6_id->src, ip_str, INET6_ADDRSTRLEN) == NULL)
		{
			WARNING_MSG("Failed to convert IPv6 source address from reassembly ID to string");

			return NULL;
		}
	}
	else
	{
		ERROR_MSG("Reassembly ID with unknown address family %d", gen_id->af);

		return NULL;
	}

	return &ip_str[0];
}

/* Get a string representation of the destination IP address in a reassembly ID */
static const char* eemo_reasm_int_get_dst_str(const ip_reasm_id* id)
{
	assert(id != NULL);

	/* WARNING! It is not safe to call this function from multiple threads concurrently */
	static char		ip_str[INET6_ADDRSTRLEN]	= { 0 };
	const generic_reasm_id*	gen_id				= &id->gen_id;
	const ip4_reasm_id*	ip4_id				= &id->ip4_id;
	const ip6_reasm_id*	ip6_id				= &id->ip6_id;

	if (gen_id->af == AF_INET)
	{
		if (inet_ntop(AF_INET, &ip4_id->dst, ip_str, INET6_ADDRSTRLEN) == NULL)
		{
			WARNING_MSG("Failed to convert IPv4 destination address from reassembly ID to string");

			return NULL;
		}
	}
	else if (gen_id->af == AF_INET6)
	{
		if (inet_ntop(AF_INET6, &ip6_id->dst, ip_str, INET6_ADDRSTRLEN) == NULL)
		{
			WARNING_MSG("Failed to convert IPv6 destination address from reassembly ID to string");

			return NULL;
		}
	}
	else
	{
		ERROR_MSG("Reassembly ID with unknown address family %d", gen_id->af);

		return NULL;
	}

	return &ip_str[0];
}

/* Find a reassembly buffer for the packet with the specified ID or allocate an empty one */
static ip_reasm_buf* eemo_reasm_int_find_buf(const ip_reasm_id* id)
{
	assert(id != NULL);

	int			i		= 0;
	ip_reasm_buf*		rv		= NULL;
	time_t			now		= time(NULL);
	ip_reasm_buf*		empty		= NULL;
	ip_reasm_buf*		prunable	= NULL;
	ip_reasm_buf*		oldest		= NULL;
	generic_reasm_id*	gen_id		= (generic_reasm_id*) id;

	/* Try to find the reassembly buffer first */
	for (i = 0; i < ra_buf_count; i++)
	{
		if (ra_buffers[i].in_use && (memcmp(&ra_buffers[i].id, id, (gen_id->af == AF_INET) ? sizeof(ip4_reasm_id) : sizeof(ip6_reasm_id)) == 0))
		{
			rv = &ra_buffers[i];

			/* Found it, check for reassembly timeout */
			if (((now - rv->first_frag_arr) > ra_timeout) && !rv->reassembled)
			{
				if (ra_log) WARNING_MSG("Fragment reassembly timeout occurred, assuming new packet (src %s, dst %s)", eemo_reasm_int_get_src_str(id), eemo_reasm_int_get_dst_str(id));

				rv->first_frag_arr	= now;
				rv->in_use 		= 1;
				rv->reassembled 	= 0;
				rv->first_hole		= HD_NULL;
				rv->frag_count		= 0;
				memset(rv->buffer, 0, 65536 * sizeof(u_char));

			}

			FRAG_MSG("Found matching fragment reassembly buffer for packet with src %s and dst %s", eemo_reasm_int_get_src_str(id), eemo_reasm_int_get_dst_str(id));

			return rv;
		}

		/* 
		 * Record the first empty, first prunable and oldest buffer, in case we 
		 * cannot find a buffer for this packet ID 
		 */
		if ((empty == NULL) && !ra_buffers[i].in_use)
		{
			empty = &ra_buffers[i];
		}

		if ((prunable == NULL) && ((now - ra_buffers[i].first_frag_arr) > ra_timeout))
		{
			prunable = &ra_buffers[i];
		}

		if ((oldest == NULL) || (ra_buffers[i].first_frag_arr < oldest->first_frag_arr))
		{
			oldest = &ra_buffers[i];
		}
	}

	/* No reassembly buffer found, this is the first fragment to arrive */
	if (empty != NULL)
	{
		rv = empty;
	}
	else if (prunable != NULL)
	{
		rv = prunable;
	}
	else
	{
		/* 
		 * This is problematic, we ran out of buffers and are sacrificing the
		 * oldest packet being reassembled under the assumption that that one
		 * will time out first.
		 */
		rv = oldest;

		if (ra_log) WARNING_MSG("Ran out of reassembly buffers, discarding partially reassembled packet of age %ds with src %s and dst %s", (int) (now - oldest->first_frag_arr), eemo_reasm_int_get_src_str(&oldest->id), eemo_reasm_int_get_dst_str(&oldest->id));
	}

	/* Clean up the new buffer */
	memcpy(&rv->id, id, sizeof(ip_reasm_id));
	rv->first_frag_arr	= now;
	rv->in_use 		= 1;
	rv->reassembled 	= 0;
	rv->first_hole		= HD_NULL;
	rv->frag_count		= 0;
	rv->pkt_len		= -1;

	/* This may not be efficient but it is more secure */
	memset(rv->buffer, 0, 65536 * sizeof(u_char));

	FRAG_MSG("Returning blank reassembly buffer for packet with src %s and dst %s", eemo_reasm_int_get_src_str(id), eemo_reasm_int_get_dst_str(id));

	return rv;
}

/* Process a single fragment */
static eemo_rv eemo_reasm_int_process_fragment(const ip_reasm_id* id, const eemo_packet_buf* fragment, u_short ofs, const int is_last, eemo_packet_buf* pkt)
{
	assert(id != NULL);
	assert(fragment != NULL);
	assert(pkt != NULL);

	ip_reasm_buf*	buf		= NULL;
	hole_desc*	hd		= NULL;
	hole_desc	hd_found	= { 0, 0, 0 };

	FRAG_MSG("Processing fragment with src %s, dst %s", eemo_reasm_int_get_src_str(id), eemo_reasm_int_get_dst_str(id));

	/* Find a buffer for the fragment */
	if ((buf = eemo_reasm_int_find_buf(id)) == NULL)
	{
		if (ra_log) ERROR_MSG("Could not find a reassembly buffer for fragment with src %s and dst %s", eemo_reasm_int_get_src_str(id), eemo_reasm_int_get_dst_str(id));

		return ERV_REASM_FAILED;
	}

	/* Check the sanity of the fragment */
	if ((fragment->len + ofs) > 65536)
	{
		if (ra_log) ERROR_MSG("Fragment with src %s and dst %s has offset %u and length %u, which would exceed the maximum allowed packet length!", eemo_reasm_int_get_src_str(id), eemo_reasm_int_get_dst_str(id), ofs, fragment->len);

		buf->in_use = 0;

		return ERV_REASM_FAILED;
	}

	/* Check if we already know the length of the whole reassembled packet and if this fragment is within that size */
	if ((buf->pkt_len > 0) && ((fragment->len + ofs) > buf->pkt_len))
	{
		if (ra_log) ERROR_MSG("Fragment with src %s and dst %s has offset %u and length %u, which exceeds the expected length %d", eemo_reasm_int_get_src_str(id), eemo_reasm_int_get_dst_str(id), ofs, fragment->len, buf->pkt_len);

		/* Return the buffer */
		buf->in_use = 0;

		return ERV_REASM_FAILED;
	}

	/* Is this the first fragment to arrive? */
	if (buf->first_hole == HD_NULL)
	{
		FRAG_MSG("First fragment with offset %u and length %u", ofs, fragment->len);

		if (ofs == 0)
		{
			FRAG_MSG("First fragment is start of packet");

			if (is_last)
			{
				if (ra_log) ERROR_MSG("First fragment is also the last fragment; packet should not be reassembled");

				buf->in_use = 0;

				return ERV_REASM_FAILED;
			}

			/* Copy the data in */
			memcpy(&buf->buffer[0], fragment->data, fragment->len);

			/* Create first hole descriptor after the fragment */
			hd = (hole_desc*) &buf->buffer[fragment->len];

			hd->hd_first = fragment->len;
			hd->hd_last = HD_NULL;
			hd->hd_next = HD_NULL;

			FRAG_MSG("Added hole f=%u l=%u n=%u", hd->hd_first, hd->hd_last, hd->hd_next);

			buf->first_hole = fragment->len;
		}
		else
		{
			FRAG_MSG("First fragment is somewhere in the packet, creating new holes");

			hd = (hole_desc*) &buf->buffer[0];

			hd->hd_first = 0;
			hd->hd_last = (ofs - 1);
			hd->hd_next = is_last ? HD_NULL : (ofs + fragment->len);

			/* Check if the hole is 8 octets or more */
			if (hd->hd_last + 1 - hd->hd_first < 8)
			{
				ERROR_MSG("Fragment reassembly starting with hole of less than 8 octets; packet should not be reassembled");

				buf->in_use = 0;

				return ERV_REASM_FAILED;
			}

			FRAG_MSG("Added hole f=%u l=%u n=%u", hd->hd_first, hd->hd_last, hd->hd_next);

			/* Copy the fragment data in */
			memcpy(&buf->buffer[ofs], fragment->data, fragment->len);

			if (!is_last)
			{
				hd = (hole_desc*) &buf->buffer[ofs + fragment->len];
				
				hd->hd_first = ofs + fragment->len;
				hd->hd_last = HD_NULL;
				hd->hd_next = HD_NULL;

				FRAG_MSG("Added hole f=%u l=%u n=%u", hd->hd_first, hd->hd_last, hd->hd_next);
			}

			buf->first_hole = 0;
		}
	}
	else
	{
		hole_desc*	hd_prev		= NULL;

		/* Iterate over the holes that we have to see where the packet fits */
		hd = (hole_desc*) &buf->buffer[buf->first_hole];

		while (hd != NULL)
		{
			if (ofs > hd->hd_last)
			{
				if (hd->hd_next != HD_NULL)
				{
					hd_prev = hd;
					hd = (hole_desc*) &buf->buffer[hd->hd_next];

					continue;
				}

				hd = NULL;
			}
			else if (((ofs + fragment->len - 1) > hd->hd_last) || (ofs < hd->hd_first))
			{
				/* Overlapping fragment! */
				if (ra_log) ERROR_MSG("Overlapping fragment in packet with src %s and dst %s", eemo_reasm_int_get_src_str(id), eemo_reasm_int_get_dst_str(id));

				buf->in_use = 0;

				return ERV_REASM_FAILED;
			}

			break;
		}

		if (hd == NULL)
		{
			if (ra_log) ERROR_MSG("Found a fragment with src %s and dst %s but no hole to put it in", eemo_reasm_int_get_src_str(id), eemo_reasm_int_get_dst_str(id));

			buf->in_use = 0;

			return ERV_REASM_FAILED;
		}

		FRAG_MSG("Found matching hole f=%u l=%u n=%u for fragment at ofs=%u with len=%u", hd->hd_first, hd->hd_last, hd->hd_next, ofs, fragment->len);

		memcpy(&hd_found, hd, sizeof(hole_desc));

		if (ofs > hd_found.hd_first)
		{
			/* Create a new hole */
			hole_desc*	new_hd	= (hole_desc*) &buf->buffer[hd_found.hd_first];

			new_hd->hd_first	= hd_found.hd_first;
			new_hd->hd_last		= ofs - 1;
			new_hd->hd_next		= hd_found.hd_next;

			/* Check if the hole is more than 8 octets */
			if (new_hd->hd_last + 1 - new_hd->hd_first < 8)
			{
				ERROR_MSG("Fragment would create a new hole of less than 8 octets; stopping reassembly");

				buf->in_use = 0;

				return ERV_REASM_FAILED;
			}

			FRAG_MSG("Added hole f=%u l=%u n=%u", new_hd->hd_first, new_hd->hd_last, new_hd->hd_next);

			hd_prev = new_hd;
		}
		else
		{
			/* Remove the hole */
			if (hd_prev != NULL)
			{
				hd_prev->hd_next = hd_found.hd_next;
			}
			else
			{
				buf->first_hole = hd_found.hd_next;
			}
		}

		if (((ofs + fragment->len - 1) < hd_found.hd_last) && !is_last)
		{
			/* Create a new hole */
			hole_desc*	new_hd	= (hole_desc*) &buf->buffer[ofs + fragment->len];

			new_hd->hd_first	= ofs + fragment->len;
			new_hd->hd_last		= hd_found.hd_last;
			new_hd->hd_next		= hd_found.hd_next;

			/* Check if the hole is more than 8 octets */
			if (new_hd->hd_last + 1 - new_hd->hd_first < 8)
			{
				ERROR_MSG("Fragment would resize existing hole to less than 8 octets; stopping reassembly");

				buf->in_use = 0;

				return ERV_REASM_FAILED;
			}

			FRAG_MSG("Added hole f=%u l=%u n=%u", new_hd->hd_first, new_hd->hd_last, new_hd->hd_next);

			if (hd_prev != NULL)
			{
				hd_prev->hd_next = new_hd->hd_first;

				FRAG_MSG("Chained new hole to previous hole at %u", hd_prev->hd_first);
			}
			else
			{
				buf->first_hole = new_hd->hd_first;

				FRAG_MSG("New hole is first hole");
			}
		}

		/* Copy data in last (overwrites old hole descriptors!) */
		memcpy(&buf->buffer[ofs], fragment->data, fragment->len);

		/* Check if the hole descriptor list is now empty */
		buf->reassembled = (buf->first_hole == HD_NULL);
	}

	/* Is this the last fragment of the packet? Then we can calculate the total reassembled length */
	if (is_last)
	{
		buf->pkt_len = ofs + fragment->len;

		FRAG_MSG("Total packet length for packet with src %s and dst %s is %u octets", eemo_reasm_int_get_src_str(id), eemo_reasm_int_get_dst_str(id), buf->pkt_len);
	}

	/* Did reassembly complete? */
	if (buf->reassembled)
	{
		FRAG_MSG("Reassembly of packet with src %s and dst %s of %u octets completed", eemo_reasm_int_get_src_str(id), eemo_reasm_int_get_dst_str(id), buf->pkt_len);

		/* Make the reassembled packet available */
		pkt->data = &buf->buffer[0];
		pkt->len = buf->pkt_len;

		return ERV_OK;
	}

	return ERV_NEED_MORE_FRAGS;
}

/*
 * Process an IPv4 fragment; will return ERV_NEED_MORE_FRAGS if more
 * fragments are needed to reasmemble the packet, and ERV_OK if a full
 * packet was reassembled (in which case <pkt> contains the packet
 * data. Caller must release reasmembled packets with the appropriate
 * call below!
 */
eemo_rv eemo_reasm_v4_fragment(const struct in_addr* src, const struct in_addr* dst, const u_char ip_proto, const u_short ip_id, const u_short ip_ofs, const eemo_packet_buf* fragment, const int is_last, eemo_packet_buf* pkt)
{
	assert(src != NULL);
	assert(dst != NULL);
	assert(fragment != NULL);
	assert(pkt != NULL);

	ip4_reasm_id	id4;
	ip_reasm_id*	id	= (ip_reasm_id*) &id4;

	if (!ra_enabled) return ERV_REASM_DISABLED;	/* Exit early */

	/* Assemble fragment identifier */
	memset(&id4, 0, sizeof(ip4_reasm_id));
	memcpy(&id4.src, src, sizeof(struct in_addr));
	memcpy(&id4.dst, dst, sizeof(struct in_addr));
	id4.proto	= ip_proto;
	id4.id		= ip_id;
	id4.af		= AF_INET;

	FRAG_MSG("Processing IPv4 fragment with src %s, dst %s, proto=%u and ID=%u", eemo_reasm_int_get_src_str(id), eemo_reasm_int_get_dst_str(id), ip_proto, ip_id);

	return eemo_reasm_int_process_fragment(id, fragment, ip_ofs, is_last, pkt);
}

/* Process an IPv6 fragment; semantics of parameters same as for IPv4 */
eemo_rv eemo_reasm_v6_fragment(const struct in6_addr* src, const struct in6_addr* dst, const u_int ip_id, const u_short ip_ofs, const eemo_packet_buf* fragment, const int is_last, eemo_packet_buf* pkt)
{
	assert(src != NULL);
	assert(dst != NULL);
	assert(fragment != NULL);
	assert(pkt != NULL);

	ip6_reasm_id	id6;
	ip_reasm_id*	id	= (ip_reasm_id*) &id6;

	if (!ra_enabled) return ERV_REASM_DISABLED;	/* Exit early */

	/* Assemble fragment identifier */
	memset(&id6, 0, sizeof(ip6_reasm_id));
	memcpy(&id6.src, src, sizeof(struct in6_addr));
	memcpy(&id6.dst, dst, sizeof(struct in6_addr));
	id6.id		= ip_id;
	id6.af		= AF_INET6;

	FRAG_MSG("Processing IPv6 fragment with src %s, dst %s and ID=%u", eemo_reasm_int_get_src_str(id), eemo_reasm_int_get_dst_str(id), ip_id);

	return eemo_reasm_int_process_fragment(id, fragment, ip_ofs, is_last, pkt);
}

/* Discard a reassembled IPv4 packet */
void eemo_reasm_v4_free(const struct in_addr* src, const struct in_addr* dst, const u_char ip_proto, const u_short ip_id)
{
	assert(src != NULL);
	assert(dst != NULL);

	ip4_reasm_id	id4;
	ip_reasm_id*	id	= (ip_reasm_id*) &id4;
	ip_reasm_buf*	buf	= NULL;

	if (!ra_enabled) return;	/* Exit early */

	/* Assemble fragment identifier */
	memset(&id4, 0, sizeof(ip4_reasm_id));
	memcpy(&id4.src, src, sizeof(struct in_addr));
	memcpy(&id4.dst, dst, sizeof(struct in_addr));
	id4.proto	= ip_proto;
	id4.id		= ip_id;
	id4.af		= AF_INET;

	FRAG_MSG("Releasing IPv4 fragment with src %s, dst %s, proto=%u and ID=%u", eemo_reasm_int_get_src_str(id), eemo_reasm_int_get_dst_str(id), ip_proto, ip_id);

	if ((buf = eemo_reasm_int_find_buf(id)) == NULL)
	{
		if (ra_log) ERROR_MSG("Could not find a reassembly buffer for fragment with src %s and dst %s", eemo_reasm_int_get_src_str(id), eemo_reasm_int_get_dst_str(id));

		return;
	}

	if (!buf->reassembled)
	{
		if (ra_log) WARNING_MSG("Releasing packet that was not fully reassembled");
	}

	buf->in_use = 0;
}

/* Discard a reassembled IPv6 packet */
void eemo_reasm_v6_free(const struct in6_addr* src, const struct in6_addr* dst, const u_int ip_id)
{
	assert(src != NULL);
	assert(dst != NULL);

	ip6_reasm_id	id6;
	ip_reasm_id*	id	= (ip_reasm_id*) &id6;
	ip_reasm_buf*	buf	= NULL;

	if (!ra_enabled) return;	/* Exit early */

	FRAG_MSG("Releasing reassembled IPv6 fragment");
	
	/* Assemble fragment identifier */
	memset(&id6, 0, sizeof(ip6_reasm_id));
	memcpy(&id6.src, src, sizeof(struct in6_addr));
	memcpy(&id6.dst, dst, sizeof(struct in6_addr));
	id6.id		= ip_id;
	id6.af		= AF_INET6;

	FRAG_MSG("Releasing IPv6 fragment with src %s, dst %s and ID=%u", eemo_reasm_int_get_src_str(id), eemo_reasm_int_get_dst_str(id), ip_id);

	if ((buf = eemo_reasm_int_find_buf(id)) == NULL)
	{
		if (ra_log) ERROR_MSG("Could not find a reassembly buffer for fragment with src %s and dst %s", eemo_reasm_int_get_src_str(id), eemo_reasm_int_get_dst_str(id));

		return;
	}

	if (!buf->reassembled)
	{
		if (ra_log) WARNING_MSG("Releasing packet that was not fully reassembled");
	}

	buf->in_use = 0;
}

