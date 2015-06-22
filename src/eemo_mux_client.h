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
 * Client handling and queueing
 */

#ifndef _EEMO_MUX_CLIENT_H
#define _EEMO_MUX_CLIENT_H

#include "config.h"
#include "eemo.h"
#include "eemo_api.h"
#include "eemo_mux_cmdxfer.h"
#include <pthread.h>
#include <openssl/ssl.h>

/* Queue item */
typedef struct cq_entry
{
	eemo_mux_pkt*		cq_pkt;
	struct cq_entry*	next;
	struct cq_entry*	prev;
}
cq_entry;

/* Client queue */
typedef struct client_queue
{
	SSL*		tls;		/* TLS connection */
	cq_entry*	q_head;		/* The head of the queue */
	cq_entry*	q_tail;		/* The tail of the queue */
	size_t		q_len;		/* The length of the queue */
	size_t		q_maxlen;	/* The maximum queue length */
	pthread_mutex_t	q_mutex;	/* Queue access mutex */
	pthread_cond_t	q_signal;	/* Queue signal */
	pthread_t	client_thread;	/* The client thread */
	int		client_run;	/* Should the client thread be running? */
	int		client_state;	/* Is the client connection OK? */
	int		q_overflow;	/* Is the packet queue overflowing? */
}
client_queue;

/* Create a new client handler */
client_queue* eemo_cq_new(SSL* tls, const size_t maxlen);

/* Enqueue a new packet for the client */
eemo_rv eemo_cq_enqueue(client_queue* q, eemo_mux_pkt* pkt);

/* Finalise the client */
void eemo_cq_stop(client_queue* q);

#endif /* !_EEMO_MUX_CLIENT_H */

