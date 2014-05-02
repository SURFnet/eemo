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
 * Main sensor code
 */

#include "config.h"
#include "eemo.h"
#include "eemo_api.h"
#include "eemo_sensor_sensor.h"
#include "eemo_config.h"
#include "eemo_tlsutil.h"
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <signal.h>
#include <stdlib.h>
#include <openssl/ssl.h>
#include <arpa/inet.h>
#include <netinet/in.h>

/* Connection to the multiplexer */
SSL_CTX*	tls_ctx		= NULL;
SSL*		tls			= NULL;
int			mux_socket	= -1;

int eemo_sensor_connect_mux(void)
{
	char*				mux_hostname	= NULL;	
	int					mux_port		= -1;
	struct addrinfo* 	mux_addrs		= NULL;
	struct addrinfo*	addr_it			= NULL;
	struct addrinfo 	hints;
	char 				port_str[16];
	
	/* Retrieve mux information from the configuration */
	if ((eemo_conf_get_string("sensor", "mux_host", &mux_hostname, NULL) != ERV_OK) || (mux_hostname == NULL))
	{
		ERROR_MSG("No multiplexer host configured, giving up");
		
		return -2;
	}
	
	if ((eemo_conf_get_int("sensor", "mux_port", &mux_port, 6969) != ERV_OK) || (mux_port < 1))
	{
		ERROR_MSG("Incorrect multiplexer port (%d) configured, giving up", mux_port);
		
		free(mux_hostname);
		
		return -2;
	}

	/* Resolve the address of the multiplexer */
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = 0;
	hints.ai_protocol = 0;

	snprintf(port_str, 16, "%d", mux_port);

	if (getaddrinfo(mux_hostname, port_str, &hints, &mux_addrs) != 0)
	{
		ERROR_MSG("Unable to resolve host %s", mux_hostname);
		
		free(mux_hostname);
		
		return -1;
	}

	/* Attempt to connect to one of the addresses that was found */
	addr_it = mux_addrs;
	mux_socket = -1;

	while(addr_it != NULL)
	{
		if ((addr_it->ai_family == AF_INET) || (addr_it->ai_family == AF_INET6))
		{
			struct timeval socket_timeout = { 1, 0}; /* socket time-out is 1 second */

			INFO_MSG("Attempting to connect to %s:%d over IPv%d", 
				mux_hostname, mux_port,
				addr_it->ai_family == AF_INET ? 4 : 6);

			mux_socket = socket(addr_it->ai_family, SOCK_STREAM, 0);

			if (mux_socket == -1)
			{
				ERROR_MSG("Failed to open a new socket");
				
				free(mux_hostname);
				
				return -1;
			}

			/* Set socket time-out value for both sending as well as receiving */
			if (setsockopt(mux_socket, SOL_SOCKET, SO_RCVTIMEO, (char*) &socket_timeout, sizeof(socket_timeout)) != 0)
			{
				ERROR_MSG("Failed to set receive time-out on sensor socket");
			}

			if (setsockopt(mux_socket, SOL_SOCKET, SO_SNDTIMEO, (char*) &socket_timeout, sizeof(socket_timeout)) != 0)
			{
				ERROR_MSG("Failed to set send time-out on sensor socket");
			}

			/* Attempt to connect the socket */
			if (connect(mux_socket, addr_it->ai_addr, addr_it->ai_addrlen) != 0)
			{
				ERROR_MSG("Failed to connect to %s:%d (%s)", mux_hostname, mux_port, strerror(errno));
				close(mux_socket);
				addr_it = addr_it->ai_next;
				continue;
			}

			INFO_MSG("Established a connection to %s:%d", mux_hostname, mux_port);
			
			break;
		}

		addr_it = addr_it->ai_next;
	}

	freeaddrinfo(mux_addrs);
	free(mux_hostname);
	
	if (mux_socket != -1)
	{
		char* 	cert_file	= NULL;
		char* 	key_file	= NULL;
		int		err			= -1;
		
		/* Set up new TLS context */
		tls_ctx = SSL_CTX_new(TLSv1_client_method());
	
		if (tls_ctx == NULL)
		{
			ERROR_MSG("Failed to setup up TLS v1 on the client socket");
			
			close(mux_socket);
			
			return -1;
		}
		
		/* Load the certificate and private key */
		if ((eemo_conf_get_string("sensor", "sensor_cert", &cert_file, NULL) != ERV_OK) || (cert_file == NULL))
		{
			ERROR_MSG("No TLS server certificate configured");
			
			SSL_CTX_free(tls_ctx);
			tls_ctx = NULL;
			close(mux_socket);
			
			mux_socket = -1;
			
			return -1;
		}
		
		if ((eemo_conf_get_string("sensor", "sensor_key", &key_file, NULL) != ERV_OK) || (key_file == NULL))
		{
			ERROR_MSG("No TLS key configured");
			
			SSL_CTX_free(tls_ctx);
			tls_ctx = NULL;
			free(cert_file);
			close(mux_socket);
			
			mux_socket = -1;
			
			return -1;
		}
		
		if ((SSL_CTX_use_certificate_file(tls_ctx, cert_file, SSL_FILETYPE_PEM) != 1) &&
			(SSL_CTX_use_certificate_file(tls_ctx, cert_file, SSL_FILETYPE_ASN1) != 1))
		{
			ERROR_MSG("Failed to load TLS certificate from %s", cert_file);
			
			SSL_CTX_free(tls_ctx);
			tls_ctx = NULL;
			free(cert_file);
			free(key_file);
			close(mux_socket);
			
			mux_socket = -1;
			
			return -1;
		}
		
		INFO_MSG("Loaded TLS certificate");
		
		if ((SSL_CTX_use_PrivateKey_file(tls_ctx, key_file, SSL_FILETYPE_PEM) != 1) &&
			(SSL_CTX_use_PrivateKey_file(tls_ctx, key_file, SSL_FILETYPE_ASN1) != 1))
		{
			ERROR_MSG("Failed to load TLS key from %s", key_file);
			
			SSL_CTX_free(tls_ctx);
			tls_ctx = NULL;
			free(cert_file);
			free(key_file);
			close(mux_socket);
			
			mux_socket = -1;
			
			return -1;
		}
		
		INFO_MSG("Loaded TLS key");
		
		free(cert_file);
		free(key_file);
		
		/* Set TLS options */
		if (SSL_CTX_set_cipher_list(tls_ctx, "HIGH:!DSS:!aNULL@STRENGTH'") != 1)
		{
			ERROR_MSG("Failed to select safe TLS ciphers, giving up");
			
			SSL_CTX_free(tls_ctx);
			close(mux_socket);
			
			mux_socket = -1;
			
			return -1;
		}
		
		/* Perform TLS handshake */
		tls = SSL_new(tls_ctx);
		
		if ((tls == NULL) || (SSL_set_fd(tls, mux_socket) != 1))
		{
			SSL_free(tls);
			SSL_CTX_free(tls_ctx);
			tls_ctx = NULL;
			tls = NULL;
			
			ERROR_MSG("Failed to establish new TLS context");
			
			close(mux_socket);
			
			mux_socket = -1;
			
			return -1;
		}
		
		if ((err = SSL_connect(tls)) != 1)
		{
			ERROR_MSG("TLS handshake failed (%s)", eemo_tls_get_err(tls, err));
			
			SSL_shutdown(tls);
			SSL_free(tls);
			SSL_CTX_free(tls_ctx);
			tls = NULL;
			tls_ctx = NULL;
			
			close(mux_socket);
			
			mux_socket = -1;
		}
		
		INFO_MSG("Successfully connected to the multiplexer");
		
		return 0;
	}
	else
	{	
		ERROR_MSG("Failed to connect to the multiplexer on any address");
		
		return -1;
	}
}

void eemo_sensor_disconnect_mux(void)
{
	if (tls != NULL)
	{
		SSL_shutdown(tls);
		SSL_free(tls);
		tls = NULL;
	}
	
	if (tls_ctx != NULL)
	{
		SSL_CTX_free(tls_ctx);
		tls_ctx = NULL;
	}
	
	if (mux_socket >= 0)
	{
		close(mux_socket);
		
		mux_socket = -1;
		
		INFO_MSG("Disconnected from the multiplexer");
	}
}

/* Run the sensor */
void eemo_sensor_run(void)
{
	/* Attempt to establish an initial connection to the multiplexer */
	if (eemo_sensor_connect_mux() == -2)
	{
		ERROR_MSG("Fatal error, giving up");
		
		return;
	}
	
	/* Disconnect from the multiplexer */
	eemo_sensor_disconnect_mux();
}
