/* $Id$ */

/*
 * Copyright (c) 2010-2012 SURFnet bv
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
 * Handle factory for handles used to identify handlers
 */

#include "config.h"
#include <stdlib.h>
#include "eemo_log.h"
#include "eemo_handlefactory.h"

/* The handle registry */
unsigned char handle_used[EEMO_MAX_HANDLERS] = { 0 };

/* Get a fresh handle */
unsigned long eemo_get_new_handle(void)
{
	unsigned long handle = 0;

	for (handle = 0; handle < EEMO_MAX_HANDLERS; handle++)
	{
		if (!handle_used[handle])
		{
			handle_used[handle] = 1;

			return handle;
		}
	}

	ERROR_MSG("FATAL: eemo has run out of handles, consider recompiling with EEMO_MAX_HANDLERS set to a higher value in eemo_handlefactory.h, now exiting");

	exit(1);
}

/* Recycle a handle when it is no longer used */
void eemo_recycle_handle(unsigned long handle)
{
	handle_used[handle] = 0;
}

