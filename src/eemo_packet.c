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
 * Packet buffer handling functions
 */

#include "config.h"
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "eemo_packet.h"

/* Create a new packet structure */
eemo_packet_buf* eemo_pbuf_new(u_char* data, u_short len)
{
	eemo_packet_buf* rv = (eemo_packet_buf*) malloc(sizeof(eemo_packet_buf));

	if (rv == NULL)
	{
		/* Not enough memory! */
		return NULL;
	}

	rv->len = len;
	rv->data = (u_char*) malloc(len*sizeof(u_char));

	if (rv->data == NULL)
	{
		/* Not enough memory! */
		free(rv);

		return NULL;
	}

	memcpy(rv->data, data, len);

	return rv;
}

/* Fill packet buf from existing with offset */
void eemo_pbuf_shrink(eemo_packet_buf* dst, const eemo_packet_buf* src, const size_t ofs)
{
	assert(dst != NULL);
	assert(src != NULL);

	if (ofs >= dst->len)
	{
		dst->data = NULL;
		dst->len = 0;
	}
	else
	{
		dst->data = &src->data[ofs];
		dst->len = src->len - ofs;
	}
}

/* Free up a packet structure */
void eemo_pbuf_free(eemo_packet_buf* pbuf)
{
	if (pbuf != NULL)
	{
		if (pbuf->data != NULL)
		{
			free(pbuf->data);
			pbuf->data = NULL;
		}

		free(pbuf);
	}
}

/* Clone a packet structure */
eemo_packet_buf* eemo_pbuf_clone(eemo_packet_buf* pbuf)
{
	return eemo_pbuf_new(pbuf->data, pbuf->len);
}

