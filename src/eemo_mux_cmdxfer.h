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

#ifndef _EEMO_MUX_CMDXFER_H
#define _EEMO_MUX_CMDXFER_H

#include "config.h"
#include "eemo.h"
#include "eemo_api.h"
#include <openssl/ssl.h>
#include <stdint.h>
#include <time.h>
#include <sys/time.h>
#include <pthread.h>

/* Command data structure */
typedef struct
{
	uint16_t	cmd_id;
	uint32_t	cmd_len;
	uint8_t*	cmd_data;
}
eemo_mux_cmd;

/* Packet information */
typedef struct
{
	struct timeval	pkt_ts;
	uint8_t*	pkt_data;
	uint32_t	pkt_len;
	int32_t		pkt_refctr;
	pthread_mutex_t	pkt_refmutex;
	uint8_t*	pkt_tofree;
}
eemo_mux_pkt;

/* Receive a command */
eemo_rv eemo_cx_recv(SSL* socket, eemo_mux_cmd* recv_cmd);

/* Send a command */
eemo_rv eemo_cx_send(SSL* socket, const uint16_t cmd_id, const uint32_t cmd_len, const uint8_t* cmd_data);

/* Clean up a command data structure */
void eemo_cx_cmd_free(eemo_mux_cmd* recv_cmd);

/* Serialize a captured packet and its metadata and transmit it */
eemo_rv eemo_cx_send_pkt_sensor(SSL* socket, struct timeval ts, const uint8_t* pkt_data, const uint32_t pkt_len);

eemo_rv eemo_cx_send_pkt_client(SSL* socket, const eemo_mux_pkt* pkt);

/* Deserialize a captured packet and its metadata */
eemo_mux_pkt* eemo_cx_deserialize_pkt(eemo_mux_cmd* pkt_cmd);

/* Create a shallow copy of a packet (increases the reference counter) */
eemo_mux_pkt* eemo_cx_pkt_copy(eemo_mux_pkt* pkt);

/* Release the reference to a packet (frees storage when the reference counter reaches zero) */
void eemo_cx_pkt_free(eemo_mux_pkt* pkt);

#endif /* !_EEMO_MUX_CMDXFER_H */

