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
 * The Extensible Ethernet Monitor Sensor Multiplexer (EEMO)
 * Protocol command transfer
 */

#include "config.h"
#include "eemo.h"
#include "eemo_api.h"
#include "eemo_mux_cmdxfer.h"
#include "eemo_tlscomm.h"
#include "eemo_mux_proto.h"
#include <openssl/ssl.h>
#include <stdint.h>
#include <assert.h>
#include "endian_compat.h"

/* Define this to log information about recv/xmit of commands */
/*#define DBG_CMDXFER*/
#undef DBG_CMDXFER

#ifdef DBG_CMDXFER
	#define DBGCMD(...)	DEBUG_MSG(__VA_ARGS__)
#else
	#define DBGCMD(...)
#endif /* DBG_CMDXFER */

/* Receive a command */
eemo_rv eemo_cx_recv(SSL* socket, eemo_mux_cmd* recv_cmd)
{
	eemo_rv	rv	= ERV_OK;

	assert(recv_cmd != NULL);

	recv_cmd->cmd_data = NULL;

	if ((rv = tls_sock_read_ushort(socket, &recv_cmd->cmd_id)) != ERV_OK)
	{
		DBGCMD("tls_sock_read_ushort failed (0x%08x)", rv);

		return rv;
	}

	if ((rv = tls_sock_read_uint(socket, &recv_cmd->cmd_len)) != ERV_OK)
	{
		DBGCMD("tls_sock_read_uint failed (0x%08x)", rv);

		return rv;
	}

	if (recv_cmd->cmd_len > 0)
	{
		recv_cmd->cmd_data = (uint8_t*) malloc(recv_cmd->cmd_len * sizeof(uint8_t));

		if ((rv = tls_sock_read_bytes(socket, recv_cmd->cmd_data, recv_cmd->cmd_len)) != ERV_OK)
		{
			DBGCMD("tls_sock_read_bytes(..., %u) failed (0x%08x)", recv_cmd->cmd_len, rv);

			free(recv_cmd->cmd_data);
			
			recv_cmd->cmd_data = NULL;
			recv_cmd->cmd_len = 0;

			return rv;
		}
	}

	DBGCMD("rx cmd=%u len=%u", recv_cmd->cmd_id, recv_cmd->cmd_len);

	return ERV_OK;
}

/* Send a command */
eemo_rv eemo_cx_send(SSL* socket, const uint16_t cmd_id, const uint32_t cmd_len, const uint8_t* cmd_data)
{
	assert((cmd_len == 0) || (cmd_data != NULL));

	eemo_rv	rv	= ERV_OK;

	if ((rv = tls_sock_write_ushort(socket, cmd_id)) != ERV_OK)
	{
		DBGCMD("tls_sock_write_ushort failed (0x%08x)", rv);

		return rv;
	}

	if ((rv = tls_sock_write_uint(socket, cmd_len)) != ERV_OK)
	{
		DBGCMD("tls_sock_write_uint failed (0x%08x)", rv);

		return rv;
	}

	if (cmd_len > 0)
	{
		if ((rv = tls_sock_write_bytes(socket, cmd_data, cmd_len)) != ERV_OK)
		{
			DBGCMD("tls_sock_write_bytes(..., %u) failed (0x%08x)", cmd_len, rv);

			return rv;
		}
	}

	DBGCMD("tx cmd=%u len=%u", cmd_id, cmd_len);

	return ERV_OK;
}

/* Clean up a command data structure */
void eemo_cx_cmd_free(eemo_mux_cmd* recv_cmd)
{
	assert(recv_cmd != NULL);

	if (recv_cmd->cmd_data != NULL) free(recv_cmd->cmd_data);
	recv_cmd->cmd_len = 0;
	recv_cmd->cmd_data = NULL;
}

/* Create a new packet */
eemo_mux_pkt* eemo_cx_new_packet(const struct timeval ts, uint8_t* data, const uint32_t len, uint8_t* tofree)
{
	pthread_mutexattr_t	pkt_mutex_attr;
	eemo_mux_pkt*		new_pkt	= (eemo_mux_pkt*) malloc(sizeof(eemo_mux_pkt));

	pthread_mutexattr_init(&pkt_mutex_attr);

	pthread_mutexattr_settype(&pkt_mutex_attr, PTHREAD_MUTEX_RECURSIVE);

	if (pthread_mutex_init(&new_pkt->pkt_refmutex, &pkt_mutex_attr) != 0)
	{
		ERROR_MSG("Failed to initialise reference counting mutex");

		free(new_pkt);

		return NULL;
	}

	pthread_mutexattr_destroy(&pkt_mutex_attr);

	memset(new_pkt, 0, sizeof(eemo_mux_pkt));

	memcpy(&new_pkt->pkt_ts, &ts, sizeof(struct timeval));

	new_pkt->pkt_len 	= len;
	new_pkt->pkt_data 	= data;
	new_pkt->pkt_tofree	= tofree;

	new_pkt->pkt_refctr = 1;

	return new_pkt;
}

void eemo_cx_int_buf_append_ushort(const uint16_t value, uint8_t* buf, size_t* bufptr)
{
	uint16_t	netval	= htons(value);

	memcpy(&buf[*bufptr], &netval, sizeof(uint16_t));
	*bufptr += sizeof(uint16_t);
}

void eemo_cx_int_buf_append_uint(const uint32_t value, uint8_t* buf, size_t* bufptr)
{
	uint32_t	netval	= htonl(value);

	memcpy(&buf[*bufptr], &netval, sizeof(uint32_t));
	*bufptr += sizeof(uint32_t);
}

void eemo_cx_int_buf_append_uint64(const uint64_t value, uint8_t* buf, size_t* bufptr)
{
	uint64_t	netval	= htobe64(value);

	memcpy(&buf[*bufptr], &netval, sizeof(uint64_t));
	*bufptr += sizeof(uint64_t);
}

void eemo_cx_int_buf_append_bytes(const uint8_t* bytes, const size_t len, uint8_t* buf, size_t* bufptr)
{
	memcpy(&buf[*bufptr], bytes, len);
	*bufptr += len;
}

/* Serialize a captured packet and its metadata and transmit it */
eemo_rv eemo_cx_send_pkt(SSL* socket, const eemo_mux_pkt* pkt, const int is_client, uint8_t* sndbuf, const size_t sndbuf_sz, size_t* sndbuf_ptr, const int is_last)
{
	assert(socket != NULL);
	assert(pkt != NULL);
	assert(sndbuf != NULL);
	assert(sndbuf_ptr != NULL);
	assert(sndbuf_sz > 0);

	size_t		buf_req_sz	= 2 +				/* command ID */
					  4 +				/* command length */
					  2 * sizeof(uint64_t) +	/* timestamp */
					  pkt->pkt_len;			/* datagram */
	eemo_rv		rv		= ERV_OK;
	uint32_t	cmd_len		= (2 * sizeof(uint64_t)) + pkt->pkt_len;

	/* Check if it will fit in the buffer */
	if ((*sndbuf_ptr + buf_req_sz) > sndbuf_sz)
	{
		/* Send off the current buffer content and clear the buffer */
		if ((rv = tls_sock_write_bytes(socket, sndbuf, *sndbuf_ptr)) != ERV_OK)
		{
			DEBUG_MSG("tls_sock_write_bytes failed (0x%08x)", rv);

			return rv;
		}

		*sndbuf_ptr = 0;

		assert(sndbuf_sz >= buf_req_sz);
	}

	/* Append the packet to the send buffer */

	/* Command ID */
	eemo_cx_int_buf_append_ushort(is_client ? MUX_CLIENT_DATA : SENSOR_DATA, sndbuf, sndbuf_ptr);

	/* Command length */
	eemo_cx_int_buf_append_uint(cmd_len, sndbuf, sndbuf_ptr);

	/* Packet timestamp */
	eemo_cx_int_buf_append_uint64(pkt->pkt_ts.tv_sec, sndbuf, sndbuf_ptr);
	eemo_cx_int_buf_append_uint64(pkt->pkt_ts.tv_usec, sndbuf, sndbuf_ptr);

	/* Packet data */
	eemo_cx_int_buf_append_bytes(pkt->pkt_data, pkt->pkt_len, sndbuf, sndbuf_ptr);

	/* If this is the last packet, flush the send buffer */
	if (is_last)
	{
		if ((rv = tls_sock_write_bytes(socket, sndbuf, *sndbuf_ptr)) != ERV_OK)
		{
			DEBUG_MSG("tls_sock_write_bytes failed (0x%08x)", rv);

			return rv;
		}

		*sndbuf_ptr = 0;
	}

	return ERV_OK;
}

/* Deserialize a captured packet and its metadata */
eemo_mux_pkt* eemo_cx_deserialize_pkt(eemo_mux_cmd* pkt_cmd)
{
	assert(pkt_cmd != NULL);

	struct timeval	ts	= { 0, 0 };
	uint32_t	pkt_len	= pkt_cmd->cmd_len - (2 * sizeof(uint64_t));
	uint8_t*	tofree	= pkt_cmd->cmd_data;

	if (pkt_cmd->cmd_len < (2 * sizeof(uint64_t)))
	{
		return NULL;
	}

	/* Retrieve timestamp and convert to host byte order */
	ts.tv_sec	= (time_t) 	be64toh(*((uint64_t*) &pkt_cmd->cmd_data[0]));
	ts.tv_usec	= (suseconds_t)	be64toh(*((uint64_t*) &pkt_cmd->cmd_data[sizeof(uint64_t)]));

	pkt_cmd->cmd_data = NULL;

	return eemo_cx_new_packet(ts, &tofree[2 * sizeof(uint64_t)], pkt_len, tofree);
}

/* Create a new packet from a captured packet by copy */
eemo_mux_pkt* eemo_cx_pkt_from_capture(struct timeval ts, const uint8_t* pkt_data, const uint32_t pkt_len)
{
	assert((pkt_data != NULL) || (pkt_len == 0));

	uint8_t*	tofree	= (uint8_t*) malloc(pkt_len * sizeof(uint8_t));

	memcpy(tofree, pkt_data, pkt_len);

	return eemo_cx_new_packet(ts, tofree, pkt_len, tofree);
}

/* Create a shallow copy of a packet (increases the reference counter) */
eemo_mux_pkt* eemo_cx_pkt_copy(eemo_mux_pkt* pkt)
{
	if (pkt != NULL)
	{
		pthread_mutex_lock(&pkt->pkt_refmutex);

		pkt->pkt_refctr++;

		pthread_mutex_unlock(&pkt->pkt_refmutex);
	}

	return pkt;
}

/* Release the reference to a packet (frees storage when the reference counter reaches zero) */
void eemo_cx_pkt_free(eemo_mux_pkt* pkt)
{
	if (pkt == NULL)
	{
		return;
	}

	pthread_mutex_lock(&pkt->pkt_refmutex);

	if (--pkt->pkt_refctr == 0)
	{
		pthread_mutex_t	dest_mutex;

		memcpy(&dest_mutex, &pkt->pkt_refmutex, sizeof(pthread_mutex_t));

		free(pkt->pkt_tofree);
		free(pkt);

		pthread_mutex_unlock(&dest_mutex);
		pthread_mutex_destroy(&dest_mutex);
	}
	else
	{
		pthread_mutex_unlock(&pkt->pkt_refmutex);
	}
}

