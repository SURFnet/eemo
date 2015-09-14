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
 * Raw packet handling
 */

#include "config.h"
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "eemo.h"
#include "eemo_log.h"
#include "raw_handler.h"
#include "eemo_handlefactory.h"
#include "utlist.h"

/* The linked list of raw packet handlers */
static eemo_raw_handler* raw_handlers = NULL;

/* Register a raw packet handler */
eemo_rv eemo_reg_raw_handler(eemo_raw_handler_fn handler_fn, unsigned long* handle)
{
	eemo_raw_handler* new_handler = NULL;

	/* Check parameters */
	if ((handler_fn == NULL) || (handle == NULL))
	{
		return ERV_PARAM_INVALID;
	}

	/* Create a new handler entry */
	new_handler = (eemo_raw_handler*) malloc(sizeof(eemo_raw_handler));

	if (new_handler == NULL)
	{
		/* Not enough memory */
		return ERV_MEMORY;
	}

	new_handler->handler_fn = handler_fn;
	new_handler->handle = eemo_get_new_handle();

	/* Register the new handler */
	LL_APPEND(raw_handlers, new_handler);

	*handle = new_handler->handle;

	DEBUG_MSG("Registered raw packet handler with handle 0x%08X and handler function at 0x%08X", *handle, handler_fn);

	return ERV_OK;
}

/* Unregister a raw handler */
eemo_rv eemo_unreg_raw_handler(unsigned long handle)
{
	eemo_raw_handler* to_delete = NULL;

	LL_SEARCH_SCALAR(raw_handlers, to_delete, handle, handle);

	if (to_delete != NULL)
	{
		LL_DELETE(raw_handlers, to_delete);

		DEBUG_MSG("Unregistered raw handler with handle 0x%08X and handler function at 0x%08X", handle, to_delete->handler_fn);

		free(to_delete);
		
		eemo_recycle_handle(handle);

		return ERV_OK;
	}
	else
	{
		return ERV_NOT_FOUND;
	}
}

/* Handle a raw packet */
eemo_rv eemo_handle_raw_packet(const eemo_packet_buf* packet, struct timeval ts)
{
	eemo_raw_handler*	handler_it	= NULL;
	eemo_rv			rv		= ERV_OK;

	/* Handle the packet */
	LL_FOREACH(raw_handlers, handler_it)
	{
		eemo_rv handler_rv = ERV_SKIPPED;

		if (handler_it->handler_fn != NULL)
		{
			handler_rv = (handler_it->handler_fn)(packet, ts);
		}

		if (rv != ERV_HANDLED)
		{
			rv = handler_rv;
		}
	}

	return rv;
}

/* Initialise raw packet handling */
eemo_rv eemo_init_raw_handler(void)
{
	raw_handlers = NULL;

	INFO_MSG("Initialised raw packet handling");

	return ERV_OK;
}

/* Clean up */
void eemo_raw_handler_cleanup(void)
{
	eemo_raw_handler*	handler_it	= NULL;
	eemo_raw_handler*	handler_tmp	= NULL;

	/* Clean up the list of raw packet handlers */
	LL_FOREACH_SAFE(raw_handlers, handler_it, handler_tmp)
	{
		LL_DELETE(raw_handlers, handler_it);

		free(handler_it);
	}

	INFO_MSG("Uninitialised raw packet handling");
}

