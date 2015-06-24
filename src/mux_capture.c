/*
 * Copyright (c) 2010-2015 SURFnet bv
 * Copyright (c) 2014-2015 Roland van Rijswijk-Deij
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
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHMUX
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/*
 * The Extensible Ethernet Monitor (EEMO)
 * Handling capture feed(s) from a multiplexer
 */

#include "config.h"
#include "eemo.h"
#include "eemo_log.h"
#include "eemo_config.h"
#include "mux_capture.h"
#include "eemo_mux_proto.h"
#include "eemo_mux_cmdxfer.h"
#include <stdlib.h>
#include <string.h>
#include "utlist.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include "eemo_tlsutil.h"
#include "eemo_tlscomm.h"
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/conf.h>
#include "mt_openssl.h"

typedef struct feed_spec
{
	char*			feed_guid;
	struct feed_spec*	next;
}
feed_spec;

/* Configuration */
static char*				mux_host	= NULL;
static int				mux_port	= -1;
static feed_spec*			feeds		= NULL;

/* State */
static int				should_run	= 1;

/* Connection to the multiplexer */
static SSL_CTX*				tls_ctx		= NULL;

/* Packet handler function */
static eemo_mux_capture_handle_pkt_fn	handler		= NULL;

/* Counters */
static unsigned long long		pkt_count	= 0;
static unsigned long long		pkt_handled	= 0;
static unsigned long long		bytes_recv	= 0;

/* Interval between logging of statistics */
static int capture_stats_interval = 0;

/* Last time statistics were logged */
static time_t last_capture_stats = 0;

/* Signal handler for exit signal */
static void stop_signal_handler(int signum)
{
	INFO_MSG("Received request to exit");

	should_run = 0;
}

/* Initialise direct capturing */
eemo_rv eemo_mux_capture_init(eemo_mux_capture_handle_pkt_fn handler_fn)
{
	assert(handler_fn != NULL);

	char*	client_cert	= NULL;
	char*	client_key	= NULL;
	char*	cert_dir	= NULL;
	char**	feeds_conf	= NULL;
	int	feeds_conf_ct	= 0;
	int	i		= 0;

	/* Initialise OpenSSL */
	SSL_library_init();
	SSL_load_error_strings();

	if (eemo_mt_openssl_init() != ERV_OK)
	{
		ERROR_MSG("Failed to initialise multi-threaded use of OpenSSL");

		return ERV_GENERAL_ERROR;
	}

	last_capture_stats = time(NULL);

	/* Retrieve configuration */
	eemo_conf_get_int("capture", "stats_interval", &capture_stats_interval, 0);

	if (capture_stats_interval > 0)
	{
		INFO_MSG("Emitting capture statistics every %ds", capture_stats_interval);
	}

	/* Retrieve configuration */
	if ((eemo_conf_get_string("capture", "mux", &mux_host, NULL) != ERV_OK) || (mux_host == NULL))
	{
		ERROR_MSG("Failed to retrieve the host name of the multiplexer from the configuration, giving up");

		return ERV_CONFIG_ERROR;
	}

	if ((eemo_conf_get_int("capture", "mux_port", &mux_port, -1) != ERV_OK) || (mux_port < 1))
	{
		ERROR_MSG("Failed to retrieve the multiplexer port number from the configuration, giving up");

		free(mux_host);

		return ERV_CONFIG_ERROR;
	}

	if ((eemo_conf_get_string("capture", "client_cert", &client_cert, NULL) != ERV_OK) || (client_cert == NULL))
	{
		ERROR_MSG("Failed to retrieve the path for the client certificate from the configuration, giving up");

		free(mux_host);

		return ERV_CONFIG_ERROR;
	}

	if ((eemo_conf_get_string("capture", "client_key", &client_key, NULL) != ERV_OK) || (client_key == NULL))
	{
		ERROR_MSG("Failed to retrieve the path for the client certificate private key from the configuration, giving up");

		free(mux_host);
		free(client_cert);

		return ERV_CONFIG_ERROR;
	}

	if ((eemo_conf_get_string("capture", "cert_dir", &cert_dir, NULL) != ERV_OK) || (cert_dir == NULL))
	{
		ERROR_MSG("Failed to retrieve the path to valid multiplexer certificates from the configuration, giving up");

		free(mux_host);
		free(client_cert);
		free(client_key);

		return ERV_CONFIG_ERROR;
	}

	if ((eemo_conf_get_string_array("capture", "mux_feeds", &feeds_conf, &feeds_conf_ct) != ERV_OK) || (feeds_conf == NULL) || (feeds_conf_ct <= 0))
	{
		ERROR_MSG("Failed to retrieve feeds to request from the multiplexer from the configuration, giving up");

		free(mux_host);
		free(client_cert);
		free(client_key);
		free(cert_dir);

		return ERV_CONFIG_ERROR;
	}

	/* Set up new TLS context */
	tls_ctx = SSL_CTX_new(TLSv1_2_client_method());
	
	if (tls_ctx == NULL)
	{
		ERROR_MSG("Failed to setup up TLS 1.2 context");

		free(client_cert);
		free(client_key);
		free(cert_dir);
			
		return ERV_TLS_ERROR;
	}
		
	/* Load the certificate and private key */
	if ((SSL_CTX_use_certificate_file(tls_ctx, client_cert, SSL_FILETYPE_PEM) != 1) &&
	    (SSL_CTX_use_certificate_file(tls_ctx, client_cert, SSL_FILETYPE_ASN1) != 1))
	{
		ERROR_MSG("Failed to load TLS certificate from %s", client_cert);
			
		SSL_CTX_free(tls_ctx);
		tls_ctx = NULL;

		free(client_cert);
		free(client_key);
		free(cert_dir);
			
		return ERV_TLS_ERROR;
	}
		
	INFO_MSG("Loaded TLS certificate");

	free(client_cert);
		
	if ((SSL_CTX_use_PrivateKey_file(tls_ctx, client_key, SSL_FILETYPE_PEM) != 1) &&
	    (SSL_CTX_use_PrivateKey_file(tls_ctx, client_key, SSL_FILETYPE_ASN1) != 1))
	{
		ERROR_MSG("Failed to load TLS key from %s", client_key);
			
		SSL_CTX_free(tls_ctx);
		tls_ctx = NULL;
			
		free(client_key);
		free(cert_dir);
			
		return ERV_TLS_ERROR;
	}
		
	INFO_MSG("Loaded TLS key");
	
	free(client_key);
		
	/* Set TLS options */
	if (SSL_CTX_set_cipher_list(tls_ctx, EEMO_MUX_CIPHERSUITES) != 1)
	{
		ERROR_MSG("Failed to select safe TLS ciphers, giving up");
			
		SSL_CTX_free(tls_ctx);
		tls_ctx = NULL;

		free(cert_dir);
			
		return ERV_TLS_ERROR;
	}

	INFO_MSG("Checking for valid mux server certificates in %s", cert_dir);
			
	SSL_CTX_load_verify_locations(tls_ctx, NULL, cert_dir);
			
	free(cert_dir);

	SSL_CTX_set_verify(tls_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
	
	for (i = 0; i < feeds_conf_ct; i++)
	{
		feed_spec*	new_feed	= (feed_spec*) malloc(sizeof(feed_spec));

		new_feed->feed_guid = strdup(feeds_conf[i]);

		LL_APPEND(feeds, new_feed);
	}

	eemo_conf_free_string_array(feeds_conf, feeds_conf_ct);

	handler = handler_fn;

	return ERV_OK;
}

/* Uninitialise direct capturing */
eemo_rv eemo_mux_capture_finalize(void)
{
	feed_spec*	feed_it		= NULL;
	feed_spec*	feed_tmp	= NULL;

	handler = NULL;

	/* Clean up */
	SSL_CTX_free(tls_ctx);
	tls_ctx = NULL;

	free(mux_host);

	LL_FOREACH_SAFE(feeds, feed_it, feed_tmp)
	{
		free(feed_it->feed_guid);
		free(feed_it);
	}

	eemo_mt_openssl_finalize();

	ERR_free_strings();

	return ERV_OK;
}

/* Run the direct capture */
void eemo_mux_capture_run(void)
{
	SSL*	tls				= NULL;
	int	mux_socket			= -1;
	char	mux_ip_str[INET6_ADDRSTRLEN]	= { 0 };
	int	backoff_wait			= 1;

	/* Register the signal handler for termination */
	signal(SIGINT, stop_signal_handler);
	signal(SIGHUP, stop_signal_handler);
	signal(SIGTERM, stop_signal_handler);

	while (should_run)
	{
		/* Attempt to connect to the multiplexer */
		while (should_run)
		{
			struct addrinfo* 	mux_addrs	= NULL;
			struct addrinfo*	addr_it		= NULL;
			struct addrinfo 	hints;
			char 			port_str[16]	= { 0 };
			eemo_mux_cmd		cmd		= { 0, 0, NULL };
			int			subs_count	= 0;
			feed_spec*		feed_it		= NULL;
	
			/* Resolve the address of the multiplexer */
			hints.ai_family = AF_UNSPEC;
			hints.ai_socktype = SOCK_STREAM;
			hints.ai_flags = 0;
			hints.ai_protocol = 0;

			snprintf(port_str, 16, "%d", mux_port);

			if (getaddrinfo(mux_host, port_str, &hints, &mux_addrs) != 0)
			{
				ERROR_MSG("Unable to resolve host %s", mux_host);

				ERROR_MSG("Backing off for %ds", backoff_wait);

				sleep(backoff_wait);

				if (backoff_wait < 512) backoff_wait *= 2;
		
				continue;
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
						mux_host, mux_port,
						addr_it->ai_family == AF_INET ? 4 : 6);
		
					mux_socket = socket(addr_it->ai_family, SOCK_STREAM, 0);
		
					if (mux_socket == -1)
					{
						ERROR_MSG("Failed to open a new socket");
		
						continue;
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
						ERROR_MSG("Failed to connect to %s:%d (%s)", mux_host, mux_port, strerror(errno));
		
						close(mux_socket);
						
						mux_socket = -1;
						
						addr_it = addr_it->ai_next;
						
						continue;
					}
		
					INFO_MSG("Established a connection to %s:%d", mux_host, mux_port);
		
					/* 
					 * Save address; we need this later to filter out communication between the sensor
					 * and the multiplexer
					 */
					if (addr_it->ai_family == AF_INET)
					{
						struct sockaddr_in*	addr	= (struct sockaddr_in*) addr_it->ai_addr;
		
						if (inet_ntop(AF_INET, &addr->sin_addr, mux_ip_str, INET6_ADDRSTRLEN) == NULL)
						{
							WARNING_MSG("Failed to convert mux server address to string");
						}
					}
					else
					{
						struct sockaddr_in6*	addr	= (struct sockaddr_in6*) addr_it->ai_addr;
		
						if (inet_ntop(AF_INET6, &addr->sin6_addr, mux_ip_str, INET6_ADDRSTRLEN) == NULL)
						{
							WARNING_MSG("Failed to convert mux server address to string");
						}
					}
					
					break;
				}
		
				addr_it = addr_it->ai_next;
			}
		
			freeaddrinfo(mux_addrs);
			
			if (mux_socket >= 0)
			{
				int		err		= -1;
				
				/* Perform TLS handshake */
				tls = SSL_new(tls_ctx);
				
				if ((tls == NULL) || (SSL_set_fd(tls, mux_socket) != 1))
				{
					if (tls != NULL) SSL_free(tls);
					tls = NULL;
					
					ERROR_MSG("Failed to establish new TLS connection");
					
					close(mux_socket);
					
					mux_socket = -1;
					
					ERROR_MSG("Backing off for %ds", backoff_wait);
		
					sleep(backoff_wait);
		
					if (backoff_wait < 512) backoff_wait *= 2;
		
					continue;
				}
				
				if ((err = SSL_connect(tls)) != 1)
				{
					ERROR_MSG("TLS handshake failed (%s)", eemo_tls_get_err(tls, err));
				
					goto errorcond;
				}
				
				INFO_MSG("Successfully connected to the multiplexer");
			}
			else
			{
				ERROR_MSG("Failed to open a connection to the multiplexer");

				ERROR_MSG("Backing off for %ds", backoff_wait);
		
				sleep(backoff_wait);
		
				if (backoff_wait < 512) backoff_wait *= 2;
		
				continue;
			}
			
			/* Connected; now do the protocol negotiation and register for data feeds */
			if (eemo_cx_send(tls, MUX_CLIENT_GET_PROTO_VERSION, 0, NULL) != ERV_OK)
			{
				ERROR_MSG("Failed to request protocol version from the multiplexer");

				goto errorcond;
			}

			if (eemo_cx_recv(tls, &cmd) != ERV_OK)
			{
				ERROR_MSG("Failed to receive response to request for protocol version from the multiplexer");

				eemo_cx_cmd_free(&cmd);

				goto errorcond;
			}

			if ((cmd.cmd_id != MUX_CLIENT_GET_PROTO_VERSION) || (cmd.cmd_len != sizeof(uint16_t)))
			{
				ERROR_MSG("Invalid response from multiplexer to protocol version request");

				eemo_cx_cmd_free(&cmd);

				goto errorcond;
			}

			if (ntohs(*((uint16_t*) cmd.cmd_data)) != MUX_CLIENT_PROTO_VERSION)
			{
				ERROR_MSG("Multiplexer protocol version mismatch (mux = %u, client = %u)", ntohs(*((uint16_t*) cmd.cmd_data)), MUX_CLIENT_PROTO_VERSION);

				eemo_cx_cmd_free(&cmd);

				goto errorcond;
			}

			eemo_cx_cmd_free(&cmd);

			/* Now subscribe to all the feeds */
			LL_FOREACH(feeds, feed_it)
			{
				if (eemo_cx_send(tls, MUX_CLIENT_SUBSCRIBE, (strlen(feed_it->feed_guid) + 1), (const uint8_t*) feed_it->feed_guid) != ERV_OK)
				{
					ERROR_MSG("Failed to send feed request for feed %s", feed_it->feed_guid);

					goto errorcond;
				}

				INFO_MSG("Registered for feed %s", feed_it->feed_guid);

				subs_count++;
			}

			if (subs_count == 0)
			{
				WARNING_MSG("There are no feed subscriptions");
			}
			else
			{
				INFO_MSG("Successfully registered for %d feed%s", subs_count, subs_count > 1 ? "s" : "");
			}

			/* Successfully registered, leave the loop */
			backoff_wait = 1;
			break;

			/* Nasty, but makes the code a whole lot more readable :-S */
errorcond:
			SSL_shutdown(tls);
			SSL_free(tls);
			tls = NULL;
			close(mux_socket);
			mux_socket = -1;

			ERROR_MSG("Backing off for %ds", backoff_wait);

			sleep(backoff_wait);

			if (backoff_wait < 512) backoff_wait *= 2;
		}

		if (!should_run) break;

		while (should_run)
		{
			/* Wait for packets from the multiplexer or for a feed shutdown */
			fd_set		select_socks;
			struct timeval	timeout		= { 1, 0 };
			int		rv		= 0;

			FD_ZERO(&select_socks);
			FD_SET(mux_socket, &select_socks);

			rv = select(mux_socket + 1 /* max_fd */, &select_socks, NULL, NULL, &timeout);

			if (rv < 0)
			{
				switch(errno)
				{
				case EINTR:
					continue;
				default:
					ERROR_MSG("Call to select(...) returned an unexpected error, giving up");
					should_run = 0;
					break;
				}
			}

			if (FD_ISSET(mux_socket, &select_socks))
			{
				eemo_mux_cmd	cmd	= { 0, 0, NULL };
				eemo_mux_pkt*	pkt	= NULL;
				eemo_packet_buf	pktbuf	= { NULL, 0 };

				/* The multiplexer did something */
				if (eemo_cx_recv(tls, &cmd) != ERV_OK)
				{
					INFO_MSG("Disconnected from the multiplexer");

					break;
				}

				if (cmd.cmd_id != MUX_CLIENT_DATA)
				{
					ERROR_MSG("Unrecognised command with id 0x%x from the multiplexer", cmd.cmd_id);

					eemo_cx_cmd_free(&cmd);

					continue;
				}

				if ((pkt = eemo_cx_deserialize_pkt(&cmd)) == NULL)
				{
					ERROR_MSG("Failed to deserialize packet received from the multiplexer");

					eemo_cx_cmd_free(&cmd);

					continue;
				}

				pktbuf.data = pkt->pkt_data;
				pktbuf.len = pkt->pkt_len;

				/* Process the packet */
				pkt_count++;
				bytes_recv += pkt->pkt_len;

				if ((handler)(&pktbuf, pkt->pkt_ts) == ERV_HANDLED) pkt_handled++;

				/* Check if we need to emit statistics */
				if (capture_stats_interval > 0)
				{
					if ((time(NULL) - last_capture_stats) >= capture_stats_interval)
					{
						last_capture_stats = time(NULL);
			
						INFO_MSG("Captured %llu packets %llu of which were handled by a plug-in", pkt_count, pkt_handled);
						INFO_MSG("Received %llu bytes from the multiplexer", bytes_recv);
					}
				}

				eemo_cx_pkt_free(pkt);
				
				eemo_cx_cmd_free(&cmd);
			}
		}
	}

	if (tls != NULL)
	{
		/* Attempt to unregister the client */
		if (eemo_cx_send(tls, MUX_CLIENT_SHUTDOWN, 0, NULL) != ERV_OK)
		{
			ERROR_MSG("Failed to send client shutdown command to the multiplexer");
		}

		SSL_shutdown(tls);
		SSL_free(tls);
		tls = NULL;

		close(mux_socket);
		mux_socket = -1;
	}

	signal(SIGINT, SIG_DFL);
	signal(SIGHUP, SIG_DFL);
	signal(SIGTERM, SIG_DFL);
}

