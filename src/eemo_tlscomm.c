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

#include "config.h"
#include "eemo.h"
#include "eemo_api.h"
#include "eemo_log.h"
#include <openssl/ssl.h>
#include <openssl/err.h>

/* Receive a specified number of bytes from a socket via TLS */
int tls_sock_read_bytes(SSL* tls, unsigned char* data, const size_t len)
{
	size_t	total_read	= 0;
	int		num_read	= 0;
	
	while (total_read < len)
	{
		num_read = SSL_read(tls, &data[total_read], len - total_read);
		
		if (num_read <= 0)
		{
			if (SSL_get_error(tls, num_read) == SSL_ERROR_ZERO_RETURN)
			{
				return 1;
			}
			
			return -1;
		}
		
		total_read += num_read;
	}
	
	return 0;
}

/* Receive an unsigned short value via TLS */
int tls_sock_read_ushort(SSL* tls, uint16_t* value)
{
	int rv = 0;
	
	*value = 0;
	
	if ((rv = tls_sock_read_bytes(tls, (unsigned char*) value, sizeof(unsigned short))) != 0)
	{
		return rv;
	}
	
	*value = ntohs(*value);
	
	return 0;
}

/* Receive an unsigned int value via TLS */
int tls_sock_read_uint(SSL* tls, uint32_t* value)
{
	int rv = 0;
	
	*value = 0;
	
	if ((rv = tls_sock_read_bytes(tls, (unsigned char*) value, sizeof(uint32_t))) != 0)
	{
		return rv;
	}
	
	*value = ntohl(*value);
	
	return 0;
}

/* Send the specified number of bytes to a socket using TLS */
int tls_sock_write_bytes(SSL* tls, const uint8_t* data, const size_t len)
{
	int num_written = SSL_write(tls, data, len);
	
	if (num_written <= 0)
	{
		if (SSL_get_error(tls, num_written) == SSL_ERROR_ZERO_RETURN)
		{
			return 1;
		}
		
		return -1;
	}
	
	if (num_written != len)
	{
		WARNING_MSG("TLS write %zd bytes supplied, %d bytes actually sent", len, num_written);
	}
	
	return 0;
}

/* Send an unsigned short value via TLS */
int tls_sock_write_ushort(SSL* tls, const uint16_t value)
{
	uint16_t send_value = htons(value);
	
	return tls_sock_write_bytes(tls, (unsigned char*) &send_value, sizeof(uint16_t));
}

/* Send an unsigned int value via TLS */
int tls_sock_write_uint(SSL* tls, const uint32_t value)
{
	uint32_t send_value = htonl(value);
	
	return tls_sock_write_bytes(tls, (unsigned char*) &send_value, sizeof(uint32_t));
}
