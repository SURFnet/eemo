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
 * The Extensible Ethernet Monitor (EEMO)
 * TLS convenience functions
 */

#include "config.h"
#include "eemo.h"
#include "eemo_tlsutil.h"
#include "eemo_log.h"
#include <openssl/ssl.h>
#include <openssl/err.h>

static const char* STR_SSL_ERROR_NONE				= "SSL_ERROR_NONE";
static const char* STR_SSL_ERROR_ZERO_RETURN		= "SSL_ERROR_ZERO_RETURN";
static const char* STR_SSL_ERROR_WANT_READ			= "SSL_ERROR_WANT_READ";
static const char* STR_SSL_ERROR_WANT_WRITE			= "SSL_ERROR_WANT_WRITE";
static const char* STR_SSL_ERROR_WANT_CONNECT		= "SSL_ERROR_WANT_CONNECT";
static const char* STR_SSL_ERROR_WANT_ACCEPT		= "SSL_ERROR_WANT_ACCEPT";
static const char* STR_SSL_ERROR_WANT_X509_LOOKUP	= "SSL_ERROR_WANT_X509_LOOKUP";
static const char* STR_SSL_ERROR_SYSCALL			= "SSL_ERROR_SYSCALL";
static const char* STR_SSL_ERROR_SSL				= "SSL_ERROR_SSL";
static const char* STR_UNKNOWN						= "UNKNOWN";

const char* eemo_tls_get_err(SSL* tls, int err)
{
	const char* 	rv			= NULL;
	char			buf[512]	= { 0 };
	unsigned long	e			= 0;
		
	switch(SSL_get_error(tls, err))
	{
	case SSL_ERROR_NONE:
		rv = STR_SSL_ERROR_NONE;
		break;
	case SSL_ERROR_ZERO_RETURN:
		rv = STR_SSL_ERROR_ZERO_RETURN;
		break;
	case SSL_ERROR_WANT_READ:
		rv = STR_SSL_ERROR_WANT_READ;
		break;
	case SSL_ERROR_WANT_WRITE:
		rv = STR_SSL_ERROR_WANT_WRITE;
		break;
	case SSL_ERROR_WANT_CONNECT:
		rv = STR_SSL_ERROR_WANT_CONNECT;
		break;
	case SSL_ERROR_WANT_ACCEPT:
		rv = STR_SSL_ERROR_WANT_ACCEPT;
		break;
	case SSL_ERROR_WANT_X509_LOOKUP:
		rv = STR_SSL_ERROR_WANT_X509_LOOKUP;
		break;
	case SSL_ERROR_SYSCALL:
		rv = STR_SSL_ERROR_SYSCALL;
		break;
	case SSL_ERROR_SSL:
		rv = STR_SSL_ERROR_SSL;
		break;
	default:
		rv = STR_UNKNOWN;
		break;
	}
	
	/* Log OpenSSL error stack */
	while ((e = ERR_get_error()) != 0)
	{
		ERR_error_string_n(e, buf, 512);
		
		ERROR_MSG("TLS error: %s", buf);
	}
	
	return rv;
}
