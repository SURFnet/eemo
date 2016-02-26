/*
 * Copyright (c) 2015 SURFnet bv
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
 * CIDR block based IP matching
 */

#include "config.h"
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <assert.h>
#include "utlist.h"
#include "cidrmatch.h"
#include "eemo_log.h"

typedef struct v4_cidr_ent
{
	u_int			v4_partial;
	u_int			v4_mask;
	char*			desc;
	struct v4_cidr_ent*	next;
}
v4_cidr_ent;

typedef struct v6_cidr_ent
{
	u_short			v6_partial[8];
	u_short			v6_mask[8];
	char*			desc;
	struct v6_cidr_ent*	next;
}
v6_cidr_ent;

static v4_cidr_ent*	v4_blocks	= NULL;
static v6_cidr_ent*	v6_blocks	= NULL;

/* Initialise the CIDR matching module */
eemo_rv eemo_cm_init(void)
{
	v4_blocks = NULL;
	v6_blocks = NULL;

	return ERV_OK;
}

/* Uninitialise the CIDR matching module */
eemo_rv eemo_cm_finalize(void)
{
	v4_cidr_ent*	v4_it	= NULL;
	v4_cidr_ent*	v4_tmp	= NULL;
	v6_cidr_ent*	v6_it	= NULL;
	v6_cidr_ent*	v6_tmp	= NULL;

	LL_FOREACH_SAFE(v4_blocks, v4_it, v4_tmp)
	{
		free(v4_it->desc);
		free(v4_it);
	}

	v4_blocks = NULL;

	LL_FOREACH_SAFE(v6_blocks, v6_it, v6_tmp)
	{
		free(v6_it->desc);
		free(v6_it);
	}

	v6_blocks = NULL;

	return ERV_OK;
}

/* Add a block for matching */
eemo_rv eemo_cm_add_block(const char* block_str, const char* block_desc)
{
	assert(block_str != NULL);

	int	mask		= -1;
	char*	block_dup	= strdup(block_str);

	if ((strchr(block_dup, '/') == NULL) || (strchr(block_dup, '/') != strrchr(block_dup, '/')))
	{
		free(block_dup);
		return ERV_CIDR_FORMERR;
	}

	/* Retrieve CIDR mask */
	mask = atoi(strchr(block_dup, '/') + 1);

	if (mask < 0)
	{
		free(block_dup);
		return ERV_CIDR_FORMERR;
	}

	/* Strip off CIDR mask */
	*(strchr(block_dup, '/')) = '\0';

	if (strchr(block_dup, ':') != NULL)
	{
		/* IPv6 CIDR block */
		v6_cidr_ent*	new_ent		= NULL;
		struct in6_addr	addr;
		size_t		mask_ofs	= 0;

		if (mask > 128)
		{
			free(block_dup);
			return ERV_CIDR_FORMERR;
		}

		if (inet_pton(AF_INET6, block_dup, &addr) != 1)
		{
			free(block_dup);
			return ERV_CIDR_FORMERR;
		}

		new_ent = (v6_cidr_ent*) malloc(sizeof(v6_cidr_ent));
		memset(new_ent, 0, sizeof(v6_cidr_ent));

		if (block_desc != NULL) new_ent->desc = strdup(block_desc);

		while (mask >= 16)
		{
			new_ent->v6_mask[mask_ofs++] = 0xffff;
			mask -= 16;
		}

		while (mask > 0)
		{
			new_ent->v6_mask[mask_ofs] >>= 1;
			new_ent->v6_mask[mask_ofs] |= 0x8000;
			mask--;
		}

		new_ent->v6_mask[mask_ofs] = htons(new_ent->v6_mask[mask_ofs]);

		/* Copy in partial address */
		memcpy(new_ent->v6_partial, &addr, sizeof(struct in6_addr));

		LL_APPEND(v6_blocks, new_ent);
	}
	else if (strchr(block_dup, '.') != NULL)
	{
		/* IPv4 CIDR block */
		v4_cidr_ent*	new_ent		= NULL;
		struct in_addr	addr;

		if (mask > 32)
		{
			free(block_dup);
			return ERV_CIDR_FORMERR;
		}

		if (inet_pton(AF_INET, block_dup, &addr) != 1)
		{
			free(block_dup);
			return ERV_CIDR_FORMERR;
		}

		new_ent = (v4_cidr_ent*) malloc(sizeof(v4_cidr_ent));
		memset(new_ent, 0, sizeof(v4_cidr_ent));

		if (block_desc != NULL) new_ent->desc = strdup(block_desc);

		while (mask > 0)
		{
			new_ent->v4_mask >>= 1;
			new_ent->v4_mask |= 0x80000000;
			mask--;
		}

		new_ent->v4_mask = htonl(new_ent->v4_mask);

		/* Copy in partial address */
		memcpy(&new_ent->v4_partial, &addr, sizeof(struct in_addr));

		LL_APPEND(v4_blocks, new_ent);
	}
	else
	{
		free(block_dup);
		return ERV_CIDR_FORMERR;
	}

	free(block_dup);

	return ERV_OK;
}

/* Match an IPv4 address (input address should be in network byte order!) */
eemo_rv eemo_cm_match_v4(const u_int v4addr, const char** block_desc)
{
	u_int		match_addr	= 0;
	v4_cidr_ent*	v4_it		= NULL;

	LL_FOREACH(v4_blocks, v4_it)
	{
		match_addr = v4addr & v4_it->v4_mask;

		if (match_addr == v4_it->v4_partial)
		{
			/* Match! */
			if (block_desc != NULL)
			{
				*block_desc = v4_it->desc;
			}

			return ERV_OK;
		}
	}

	return ERV_CIDR_NOMATCH;
}

/* Match an IPv6 address (input address should be in network byte order!) */
eemo_rv eemo_cm_match_v6(const u_short v6addr[8], const char** block_desc)
{
	u_short		match_addr[8]	= { 0 };
	v6_cidr_ent*	v6_it		= NULL;
	int		mask_ofs	= 0;

	LL_FOREACH(v6_blocks, v6_it)
	{
		for (mask_ofs = 0; mask_ofs < 8; mask_ofs++)
		{
			match_addr[mask_ofs] = v6addr[mask_ofs] & v6_it->v6_mask[mask_ofs];
		}

		if (memcmp(match_addr, v6_it->v6_partial, 8 * sizeof(u_short)) == 0)
		{
			/* Match! */
			if (block_desc != NULL)
			{
				*block_desc = v6_it->desc;
			}

			return ERV_OK;
		}
	}

	return ERV_CIDR_NOMATCH;
}

