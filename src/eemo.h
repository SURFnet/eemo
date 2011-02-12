/* $Id$ */

/*
 * Copyright (c) 2010-2011 SURFnet bv
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
 * General include file
 */

#ifndef _EEMO_H
#define _EEMO_H

#include "config.h"

#define FLAG_SET(flags, flag) ((flags & flag) == flag)

/* Type for function return values */
typedef unsigned long eemo_rv;

/* Function return values */

/* Success */
#define ERV_OK			0x00000000

/* Processing results */
#define ERV_HANDLED		0x00001000	/* The packet was handled by the module */
#define ERV_SKIPPED		0x00001001	/* The packet was not handled by the module */
#define ERV_MALFORMED		0x80001000	/* The packet was recognised but is malformed */

/* Error messages */
#define ERV_GENERAL_ERROR	0x80000000	/* An undefined error occurred */
#define ERV_MEMORY		0x80000001	/* An error occurred while allocating memory */
#define ERV_NO_PROMISC		0x80000002	/* Failed to set the interface in promiscuous mode */
#define ERV_ETH_NOT_EXIST	0x80000003	/* The specified Ethernet interface does not exist */
#define ERV_HANDLER_EXISTS	0x80000004	/* A handler for the specified type already exists */
#define ERV_NO_HANDLER		0x80000005	/* No handler exists for the specified type */
#define ERV_NO_ACCESS		0x80000006	/* The capture interface could not be accessed */
#define ERV_INVALID_FILTER	0x80000007	/* Invalid packet filter specified */
#define ERV_CAPTURE_ERROR	0x80000008	/* Error capturing packets */

#endif /* !_EEMO_H */

