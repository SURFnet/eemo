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

	free(recv_cmd->cmd_data);
	recv_cmd->cmd_len = 0;
	recv_cmd->cmd_data = NULL;
}

/* Create a new packet */
eemo_mux_pkt* eemo_cx_new_packet(const struct timeval ts, const uint8_t* data, const uint32_t len)
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

	new_pkt->pkt_len = len;
	new_pkt->pkt_data = (uint8_t*) malloc(len * sizeof(uint8_t));
	memcpy(new_pkt->pkt_data, data, len);

	new_pkt->pkt_refctr = 1;

	return new_pkt;
}

static eemo_rv eemo_cx_send_pkt_int(SSL* socket, const uint16_t cmd_id, struct timeval ts, const uint8_t* pkt_data, const uint32_t pkt_len)
{
	assert((pkt_len == 0) || (pkt_data != NULL));

	/* Convert timestamp to network byte order */
	uint64_t	ts_sec	= htobe64(ts.tv_sec);
	uint64_t	ts_usec	= htobe64(ts.tv_usec);
	uint32_t	cmd_len	= (2 * sizeof(uint64_t)) + pkt_len;
	eemo_rv		rv	= ERV_OK;

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

	/* Transmit timestamp */
	if (((rv = tls_sock_write_bytes(socket, (const uint8_t*) &ts_sec, sizeof(uint64_t))) != ERV_OK) ||
	    ((rv = tls_sock_write_bytes(socket, (const uint8_t*) &ts_usec, sizeof(uint64_t))) != ERV_OK))
	{
		DBGCMD("tls_sock_write_bytes failed (0x%08x)", rv);

		return rv;
	}

	/* Transmit data if applicable */
	if (pkt_len > 0)
	{
		if ((rv = tls_sock_write_bytes(socket, pkt_data, pkt_len)) != ERV_OK)
		{
			DBGCMD("tls_sock_write_bytes failed (0x%08x)", rv);

			return rv;
		}
	}

	DBGCMD("tx cmd=%u len=%u", cmd_id, pkt_len + (2 * sizeof(uint64_t)));

	return ERV_OK;
}

/* Serialize a captured packet and its metadata and transmit it */
eemo_rv eemo_cx_send_pkt_sensor(SSL* socket, struct timeval ts, const uint8_t* pkt_data, const uint32_t pkt_len)
{
	return eemo_cx_send_pkt_int(socket, SENSOR_DATA, ts, pkt_data, pkt_len);
}

eemo_rv eemo_cx_send_pkt_client(SSL* socket, const eemo_mux_pkt* pkt)
{
	return eemo_cx_send_pkt_int(socket, MUX_CLIENT_DATA, pkt->pkt_ts, pkt->pkt_data, pkt->pkt_len);
}

/* Deserialize a captured packet and its metadata */
eemo_mux_pkt* eemo_cx_deserialize_pkt(eemo_mux_cmd* pkt_cmd)
{
	assert(pkt_cmd != NULL);

	struct timeval	ts	= { 0, 0 };
	uint32_t	pkt_len	= pkt_cmd->cmd_len - (2 * sizeof(uint64_t));

	if (pkt_cmd->cmd_len < (2 * sizeof(uint64_t)))
	{
		return NULL;
	}

	/* Retrieve timestamp and convert to host byte order */
	ts.tv_sec	= (time_t) 	be64toh(*((uint64_t*) &pkt_cmd->cmd_data[0]));
	ts.tv_usec	= (suseconds_t)	be64toh(*((uint64_t*) &pkt_cmd->cmd_data[sizeof(uint64_t)]));

	return eemo_cx_new_packet(ts, &pkt_cmd->cmd_data[2 * sizeof(uint64_t)], pkt_len);
}

/* Create a shallow copy of a packet (increases the reference counter) */
eemo_mux_pkt* eemo_cx_pkt_copy(eemo_mux_pkt* pkt)
{
	if (pkt != NULL)
	{
		pkt->pkt_refctr++;
	}

	return pkt;
}

/* Clone a packet (creates a deep copy) */
eemo_mux_pkt* eemo_cx_pkt_clone(const eemo_mux_pkt* pkt)
{
	eemo_mux_pkt*	clone	= (eemo_mux_pkt*) malloc(sizeof(eemo_mux_pkt));

	memset(clone, 0, sizeof(eemo_mux_pkt));

	memcpy(&clone->pkt_ts, &pkt->pkt_ts, sizeof(struct timeval));

	clone->pkt_len = pkt->pkt_len;
	clone->pkt_data = (uint8_t*) malloc(clone->pkt_len * sizeof(uint8_t));
	memcpy(clone->pkt_data, pkt->pkt_data, pkt->pkt_len);

	clone->pkt_refctr = 1;

	return clone;
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
		pthread_mutex_unlock(&pkt->pkt_refmutex);
		pthread_mutex_destroy(&pkt->pkt_refmutex);

		free(pkt->pkt_data);
		free(pkt);
	}
	else
	{
		pthread_mutex_unlock(&pkt->pkt_refmutex);
	}
}

