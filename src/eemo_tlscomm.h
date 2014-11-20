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
 * Generic TLS communication functions
 */

#ifndef _EEMO_TLSCOMM_H
#define _EEMO_TLSCOMM_H

#include "config.h"
#include "eemo.h"
#include "eemo_api.h"
#include <stdint.h>

/* Receive a specified number of bytes from a socket via TLS */
int tls_sock_read_bytes(SSL* tls, unsigned char* data, const size_t len);

/* Receive an unsigned short value via TLS */
int tls_sock_read_ushort(SSL* tls, uint16_t* value);

/* Receive an unsigned int value via TLS */
int tls_sock_read_uint(SSL* tls, uint32_t* value);

/* Send the specified number of bytes to a socket using TLS */
int tls_sock_write_bytes(SSL* tls, unsigned char* data, const size_t len);

/* Send an unsigned short value via TLS */
int tls_sock_write_ushort(SSL* tls, uint16_t value);

/* Send an unsigned int value via TLS */
int tls_sock_write_uint(SSL* tls, uint32_t value);

#endif /* !_EEMO_TLSCOMM_H */

