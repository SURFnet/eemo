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
 * Client handling and queueing
 */

#include "config.h"
#include "eemo.h"
#include "eemo_api.h"
#include "eemo_mux_cmdxfer.h"
#include "eemo_mux_queue.h"
#include <pthread.h>
#include <openssl/ssl.h>
#include <assert.h>

/* Client thread procedure */
static void* eemo_q_int_threadproc(void* params)
{
	assert(params != NULL);

	mux_queue*	q		= (mux_queue*) params;
	q_entry*	sendq		= NULL;
	q_entry*	sendq_it	= NULL;
	q_entry*	cleanup		= NULL;

	DEBUG_MSG("Entering queue queue thread procedure (0x%08x)", (unsigned int) pthread_self());

	while (q->queue_run && q->queue_state)
	{
		sendq = NULL;

		/* Wait for new data to send to the queue */
		pthread_mutex_lock(&q->q_mutex);

		while((q->q_len == 0) && (q->queue_run))
		{
			pthread_cond_wait(&q->q_signal, &q->q_mutex);
		}

		/* First, check if we should exit */
		if (!q->queue_run)
		{
			pthread_mutex_unlock(&q->q_mutex);

			break;
		}

		/* Dequeue all items to the local send queue */
		sendq = q->q_head;

		q->q_head = NULL;
		q->q_tail = NULL;
		q->q_len = 0;

		pthread_mutex_unlock(&q->q_mutex);

		/* Now try to send the items in the queue */
		sendq_it = sendq;

		while (sendq_it != NULL)
		{
			if (q->queue_state && (eemo_cx_send_pkt(q->tls, sendq_it->q_pkt, q->is_client) != ERV_OK))
			{
				ERROR_MSG("Failed to send queued packet to the queue (0x%08x)", (unsigned int) pthread_self());

				q->queue_state = 0;
			}

			/* Release queued packet */
			eemo_cx_pkt_free(sendq_it->q_pkt);

			cleanup = sendq_it;
			sendq_it = sendq_it->next;
			free(cleanup);
		}
	}

	if (q->queue_state == 0)
	{
		ERROR_MSG("Client thread 0x%08x exiting because of an error", (unsigned int) pthread_self());
	}

	DEBUG_MSG("Leaving queue queue thread procedure (0x%08x)", (unsigned int) pthread_self());

	return NULL;
}

/* Create a new queue handler */
mux_queue* eemo_q_new(SSL* tls, const size_t maxlen, const int is_client)
{
	assert(tls != NULL);

	pthread_attr_t	ct_attr;
	mux_queue*	new_queue	= (mux_queue*) malloc(sizeof(mux_queue));

	memset(new_queue, 0, sizeof(mux_queue));

	new_queue->q_maxlen = maxlen;

	if (pthread_mutex_init(&new_queue->q_mutex, NULL) != 0)
	{
		ERROR_MSG("Failed to initialise queue queue mutex");

		free(new_queue);

		return NULL;
	}

	if (pthread_cond_init(&new_queue->q_signal, NULL) != 0)
	{
		ERROR_MSG("Failed to initialise queue condition signal");

		pthread_mutex_destroy(&new_queue->q_mutex);

		free(new_queue);

		return NULL;
	}

	new_queue->queue_run = 1;
	new_queue->queue_state = 1;
	new_queue->q_overflow = 0;
	new_queue->tls = tls;
	new_queue->is_client = is_client;
	
	/* Launch queue thread */
	pthread_attr_init(&ct_attr);

	pthread_attr_setdetachstate(&ct_attr, PTHREAD_CREATE_JOINABLE);

	if (pthread_create(&new_queue->queue_thread, &ct_attr, eemo_q_int_threadproc, (void*) new_queue) != 0)
	{
		ERROR_MSG("Failed to launch new queue thread");

		pthread_attr_destroy(&ct_attr);
		pthread_cond_destroy(&new_queue->q_signal);
		pthread_mutex_destroy(&new_queue->q_mutex);

		free(new_queue);

		return NULL;
	}

	pthread_attr_destroy(&ct_attr);

	return new_queue;
}

/* Enqueue a new packet for the queue */
eemo_rv eemo_q_enqueue(mux_queue* q, eemo_mux_pkt* pkt)
{
	assert((q != NULL) && (pkt != NULL));

	q_entry*	new_entry	= NULL;
	eemo_rv		rv		= ERV_OK;

	if (!q->queue_state)
	{
		return ERV_CLIENT_ERROR;
	}

	pthread_mutex_lock(&q->q_mutex);

	/* Check if the queue is overflowing */
	if (q->q_len == q->q_maxlen)
	{
		q_entry*	dequeue	= NULL;

		if (!q->q_overflow)
		{
			q->q_overflow = 1;

			rv = ERV_QUEUE_OVERFLOW;
		}

		/* Dequeue the head element */
		dequeue = q->q_head;

		if (dequeue != NULL)
		{
			q->q_head = q->q_head->next;
			q->q_head->prev = NULL;

			eemo_cx_pkt_free(dequeue->q_pkt);

			free(dequeue);
		}
		else
		{
			ERROR_MSG("Cannot dequeue element, queue length has reached the maximum value but there appears to be nothing in the queue! This is bad... giving up.");

			assert(dequeue != NULL);
		}

		q->q_len--;
	}
	else if ((q->q_overflow) && (q->q_len < q->q_maxlen))
	{
		q->q_overflow = 0;

		rv = ERV_QUEUE_OK;
	}

	/* Append the entry to the queue */
	new_entry = (q_entry*) malloc(sizeof(q_entry));

	memset(new_entry, 0, sizeof(q_entry));

	new_entry->q_pkt = eemo_cx_pkt_copy(pkt);
	new_entry->next = NULL;
	new_entry->prev = NULL;

	if (q->q_head == NULL)
	{
		q->q_head = new_entry;
	}

	if (q->q_tail == NULL)
	{
		q->q_tail = new_entry;
	}
	else
	{
		new_entry->prev = q->q_tail;
		q->q_tail->next = new_entry;
		q->q_tail = new_entry;
	}

	q->q_len++;

	/* Signal the queue thread */
	pthread_cond_signal(&q->q_signal);

	pthread_mutex_unlock(&q->q_mutex);

	return rv;
}

/* Finalise the queue */
void eemo_q_stop(mux_queue* q)
{
	q_entry*	q_it	= NULL;
	q_entry*	q_tmp	= NULL;

	assert(q != NULL);

	/* Lock the queue queue */
	pthread_mutex_lock(&q->q_mutex);

	/* Tell the thread it should exit */
	q->queue_run = 0;

	pthread_cond_signal(&q->q_signal);

	/* Unlock the queue queue */
	pthread_mutex_unlock(&q->q_mutex);

	/* Wait for the thread to exit */
	pthread_join(q->queue_thread, NULL);

	/* Clean up */
	pthread_mutex_destroy(&q->q_mutex);
	pthread_cond_destroy(&q->q_signal);

	q_it = q->q_head;

	while (q_it != NULL)
	{
		q_tmp = q_it;
		q_it = q_it->next;
		eemo_cx_pkt_free(q_tmp->q_pkt);
		free(q_tmp);
	}

	free(q);
}

