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
 * Main muxer code
 */

#include "config.h"
#include "eemo.h"
#include "eemo_config.h"
#include "eemo_mux_proto.h"
#include "eemo_mux_muxer.h"
#include "eemo_tlsutil.h"
#include "utlist.h"
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

#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX 			80		/* should be safe! */
#endif /* !UNIX_PATH_MAX */

/* Feed administration */
typedef struct feed_spec
{
	SSL*				tls;			/* TLS context */
	int 				socket;			/* data socket */
	unsigned int 		id;				/* feed ID */
	unsigned long long	pkt_count;		/* number of packets received on feed */
	unsigned long long  byte_count;		/* number of bytes received on feed */
	
	struct feed_spec* 	next;			/* LL next item */
}
feed_spec;

static feed_spec* feeds = NULL;

/* Client administration */
typedef struct client_spec
{
	SSL*				tls;			/* TLS context */
	int 				socket;			/* data socket */
	unsigned int 		subscribed_id;	/* to which feed is the client subscribed? */
	unsigned long long	pkt_count;		/* number of packets sent to client */
	unsigned long long	byte_count;		/* number of bytes sent to client */
	
	struct client_spec* next;			/* LL next item */
}
client_spec;

static client_spec* clients = NULL;

/* Should the communications loop keep running? */
static int run_comm_loop = 1;

/* SSL/TLS state */
static SSL_CTX* 	feed_tls_ctx	= NULL;

/* Signal handler for exit signal */
void stop_signal_handler(int signum)
{
	INFO_MSG("Received request to exit");

	run_comm_loop = 0;
}

/* Receive a specified number of bytes from a socket via TLS */
/*FIXME*/
/*int tls_sock_read_bytes(const int socket, unsigned char* data, const size_t len)*/

/* Receive a specified number of bytes from a socket */
int sock_read_bytes(const int socket, unsigned char* data, const size_t len)
{
	size_t 	total_read 	= 0;
	int		num_read	= 0;
	
	while (total_read < len)
	{
		num_read = read(socket, &data[total_read], len - total_read);
		
		if (num_read <= 0)
		{
			return -1;
		}
		
		total_read += num_read;
	}
	
	return 0;
}

/* Receive an unsigned short value from a socket */
int sock_read_ushort(const int socket, unsigned short* value)
{
	*value = 0;
	
	if (sock_read_bytes(socket, (unsigned char*) value, sizeof(unsigned short)) != 0)
	{
		return -1;
	}
	
	*value = ntohs(*value);
	
	return 0;
}

/* Send an unsigned short value to a socket */
int sock_write_ushort(const int socket, unsigned short value)
{
	value = htons(value);
	
	if (write(socket, &value, sizeof(unsigned short)) != sizeof(unsigned short))
	{
		return -1;
	}
	
	return 0;
}

/* Handle a feed registration */
void eemo_mux_new_feed(const int feed_socket)
{
	struct sockaddr_storage	feed_addr 		= { 0 };
	socklen_t				addr_len		= sizeof(feed_addr);
	struct sockaddr_in6*	inet6_addr		= (struct sockaddr_in6*) &feed_addr;
	int						feed_sock		= -1;
	char					addr_str[100]	= { 0 };
	feed_spec*				new_feed		= (feed_spec*) malloc(sizeof(feed_spec));
	int						err				= -1;
	
	memset(new_feed, 0, sizeof(feed_spec));
	
	/* First, accept the incoming connection */
	if ((feed_sock = accept(feed_socket, (struct sockaddr*) &feed_addr, &addr_len)) < 0)
	{
		ERROR_MSG("New feed failed to connect");
		
		free(new_feed);
		
		return;
	}
	
	if (feed_addr.ss_family == AF_INET6)
	{
		if (IN6_IS_ADDR_V4MAPPED(&inet6_addr->sin6_addr))
		{
			INFO_MSG("New feed connected from %d.%d.%d.%d", inet6_addr->sin6_addr.s6_addr[12], inet6_addr->sin6_addr.s6_addr[13], inet6_addr->sin6_addr.s6_addr[14], inet6_addr->sin6_addr.s6_addr[15]);
		}
		else
		{
			INFO_MSG("New feed connected from %s", inet_ntop(AF_INET6, (struct sockaddr*) &feed_addr, &addr_str[0], addr_len));
		}
	}
	else
	{
		WARNING_MSG("New feed connected with unknown address family");
	}
	
	/* Start TLS negotiation */
	new_feed->tls = SSL_new(feed_tls_ctx);
	new_feed->socket = feed_sock;
	
	if ((new_feed->tls == NULL) || (SSL_set_fd(new_feed->tls, feed_sock) != 1))
	{
		ERROR_MSG("Failed to set up new TLS context");
		
		SSL_free(new_feed->tls);
		
		close(feed_sock);
		
		free(new_feed);
		
		return;
	}
	
	/* Perform TLS handshake */
	if ((err = SSL_accept(new_feed->tls)) != 1)
	{
		ERROR_MSG("TLS handshake failed, closing connection (%s, %d)", eemo_tls_get_err(new_feed->tls, err), err);
		
		SSL_shutdown(new_feed->tls);
		SSL_free(new_feed->tls);
		
		close(feed_sock);
		
		free(new_feed);
		
		return;
	}
}

/* Handle a feed deregistration */
void eemo_mux_unregister_feed(const int socket)
{
}

/* Handle a client registration */
void eemo_mux_new_client(const int socket)
{
}

/* Handle a client deregistration */
void eemo_mux_unregister_client(const int socket)
{
}

/* Handle a feed packet */
int eemo_mux_handle_feed_packet(const int socket)
{
	return 0;
}

/* Handle a client packet */
int eemo_mux_handle_client_packet(const int socket)
{
	return 0;
}

/* Set up feed server socket */
int eemo_mux_setup_feed_socket(void)
{
	int 	feed_socket 				= -1;
	int 	on							= 1;
	int 	server_port					= 6969;
	struct 	sockaddr_in6 server_addr 	= { 0 };
	char*	cert_file					= NULL;
	char*	key_file					= NULL;
	
	/* Open socket */
	if ((feed_socket = socket(AF_INET6, SOCK_STREAM, 0)) < 0)
	{
		ERROR_MSG("Failed to create a new feed server socket");
		
		return -1;
	}
	
	/* Allow address re-use without time-out */
	setsockopt(feed_socket, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	
	/* Bind to port on IPv4 and IPv6 */
	server_addr.sin6_family = AF_INET6;
	
	if (eemo_conf_get_int("server", "server_port", &server_port, 6969) != ERV_OK)
	{
		ERROR_MSG("Failed to read configuration value for feed server port");
		
		close(feed_socket);
		
		return -1;
	}
	
	server_addr.sin6_port = htons(server_port);
	server_addr.sin6_addr = in6addr_any;
	
	if (bind(feed_socket, (struct sockaddr*) &server_addr, sizeof(server_addr)) != 0)
	{
		ERROR_MSG("Failed to bind feed server to port %d", server_port);
		
		close(feed_socket);
		
		return -1;
	}
	
	INFO_MSG("Feed server bound to port %d", server_port);
	
	/* Now set up TLS */
	feed_tls_ctx = SSL_CTX_new(TLSv1_server_method());
	
	if (feed_tls_ctx == NULL)
	{
		ERROR_MSG("Failed to setup up TLS v1 on the server socket");
		
		close(feed_socket);
		
		return -1;
	}
	
	/* Load the certificate and private key */
	if ((eemo_conf_get_string("server", "server_cert", &cert_file, NULL) != ERV_OK) || (cert_file == NULL))
	{
		ERROR_MSG("No TLS server certificate configured");
		
		SSL_CTX_free(feed_tls_ctx);
		feed_tls_ctx = NULL;
		close(feed_socket);
		
		return -1;
	}
	
	if ((eemo_conf_get_string("server", "server_key", &key_file, NULL) != ERV_OK) || (key_file == NULL))
	{
		ERROR_MSG("No TLS key configured");
		
		SSL_CTX_free(feed_tls_ctx);
		feed_tls_ctx = NULL;
		free(cert_file);
		close(feed_socket);
		
		return -1;
	}
	
	if ((SSL_CTX_use_certificate_file(feed_tls_ctx, cert_file, SSL_FILETYPE_PEM) != 1) &&
	    (SSL_CTX_use_certificate_file(feed_tls_ctx, cert_file, SSL_FILETYPE_ASN1) != 1))
	{
		ERROR_MSG("Failed to load TLS certificate from %s", cert_file);
		
		SSL_CTX_free(feed_tls_ctx);
		feed_tls_ctx = NULL;
		free(cert_file);
		free(key_file);
		close(feed_socket);
		
		return -1;
	}
	
	INFO_MSG("Loaded TLS certificate");
	
	if ((SSL_CTX_use_PrivateKey_file(feed_tls_ctx, key_file, SSL_FILETYPE_PEM) != 1) &&
	    (SSL_CTX_use_PrivateKey_file(feed_tls_ctx, key_file, SSL_FILETYPE_ASN1) != 1))
	{
		ERROR_MSG("Failed to load TLS key from %s", key_file);
		
		SSL_CTX_free(feed_tls_ctx);
		feed_tls_ctx = NULL;
		free(cert_file);
		free(key_file);
		close(feed_socket);
		
		return -1;
	}
	
	INFO_MSG("Loaded TLS key");
	
	free(cert_file);
	free(key_file);
	
	/* Set TLS options */
	if (SSL_CTX_set_cipher_list(feed_tls_ctx, "HIGH:!DSS:!aNULL@STRENGTH'") != 1)
	{
		ERROR_MSG("Failed to select safe TLS ciphers, giving up");
		
		SSL_CTX_free(feed_tls_ctx);
		feed_tls_ctx = NULL;
		close(feed_socket);
		
		return -1;
	}
	
	/* Start listening */
	if (listen(feed_socket, 10) < 0)
	{
		ERROR_MSG("Failed to listen to feed server port %d", server_port);
		
		SSL_CTX_free(feed_tls_ctx);
		feed_tls_ctx = NULL;
		close(feed_socket);
		
		return -1;
	}
	
	INFO_MSG("Listening for incoming feeds");
	
	return feed_socket;
}

/* Tear down feed server socket */
void eemo_mux_teardown_feed_socket(const int feed_socket)
{	
	if (feed_tls_ctx != NULL)
	{
		SSL_CTX_free(feed_tls_ctx);
		feed_tls_ctx = NULL;
	}
	
	/* Close the socket */
	close(feed_socket);
	
	INFO_MSG("Closed feed socket");
}

/* Set up multiplexer client server socket */
int eemo_mux_setup_client_socket(void)
{
	int client_socket	= -1;
	char* sock_filename	= NULL;
	struct sockaddr_un server_addr = { 0 };
	
	if (eemo_conf_get_string("multiplexer", "socket_path", &sock_filename, "/tmp/eemo_mux.socket") != ERV_OK)
	{
		return -1;
	}
	
	/* Clean up lingering old socket*/
	unlink(sock_filename);
	
	/* Set up UNIX domain socket */
	if ((client_socket = socket(PF_UNIX, SOCK_STREAM, 0)) < 0)
	{
		free(sock_filename);
		
		ERROR_MSG("Failed to create new UNIX domain socket");
		
		return -1;
	}
	
	server_addr.sun_family = AF_UNIX;
	snprintf(server_addr.sun_path, UNIX_PATH_MAX, "%s", sock_filename);
	
	if (bind(client_socket, (struct sockaddr*) &server_addr, sizeof(struct sockaddr_un)) != 0)
	{
		ERROR_MSG("Failed to bind to multiplexer client server socket %s", sock_filename);
		
		free(sock_filename);
		
		close(client_socket);
		
		return -1;
	}
	
	INFO_MSG("Multiplexer client server bound to %s", sock_filename);
	
	free(sock_filename);
	
	if (listen(client_socket, 10) < 0)
	{
		ERROR_MSG("Failed to listen to client server socket");
		
		close(client_socket);
		
		return -1;
	}
	
	INFO_MSG("Listening for new clients");
	
	return client_socket;
}

/* Disconnect all feeds */
void eemo_mux_disconnect_feeds(void)
{
	feed_spec* feed_it = NULL;
	feed_spec* tmp_it = NULL;
	int ctr = 0;
	
	LL_FOREACH_SAFE(feeds, feed_it, tmp_it)
	{
		if (feed_it->tls != NULL)
		{
			SSL_shutdown(feed_it->tls);
			SSL_free(feed_it->tls);
		}
		
		close(feed_it->socket);
		ctr++;
		
		LL_DELETE(feeds, feed_it);
	}
	
	INFO_MSG("Disconnected %d feed%s", ctr, (ctr == 1) ? "" : "s");
}

/* Disconnect all clients */
void eemo_mux_disconnect_clients(void)
{
	client_spec* client_it = NULL;
	client_spec* tmp_it = NULL;
	int ctr = 0;
	
	LL_FOREACH_SAFE(clients, client_it, tmp_it)
	{
		if (client_it->tls != NULL)
		{
			SSL_shutdown(client_it->tls);
			SSL_free(client_it->tls);
		}
		
		close(client_it->socket);
		ctr++;
		
		LL_DELETE(clients, client_it);
	}
	
	INFO_MSG("Disconnected %d client%s", ctr, (ctr == 1) ? "" : "s");
}

/* Build the file descriptor set for select(...) */
void eemo_mux_build_fd_set(fd_set* select_socks, const int feed_server_socket, const int client_server_socket)
{
	feed_spec* 		feed_it 	= NULL;
	client_spec* 	client_it 	= NULL;
	
	FD_ZERO(select_socks);

	/* Add feed and client server sockets */
	FD_SET(feed_server_socket, select_socks);
	FD_SET(client_server_socket, select_socks);
	
	/* Add feed data sockets */
	LL_FOREACH(feeds, feed_it)
	{
		FD_SET(feed_it->socket, select_socks);
	}
	
	/* Add client data sockets */
	LL_FOREACH(clients, client_it)
	{
		FD_SET(client_it->socket, select_socks);
	}
}

/* Main communications loop */
void eemo_mux_comm_loop(void)
{
	int 			feed_server_socket 		= 0;
	int 			client_server_socket	= 0;
	feed_spec*		feed_it					= NULL;
	client_spec*	client_it				= NULL;
	fd_set			select_socks;
	
	/* Set up feed server socket */
	feed_server_socket = eemo_mux_setup_feed_socket();
	
	if (feed_server_socket < 0)
	{
		close(client_server_socket);
		
		return;
	}
	
	/* Set up multiplexer client server socket */
	client_server_socket = eemo_mux_setup_client_socket();
	
	if (client_server_socket < 0)
	{
		return;
	}
	
	run_comm_loop = 1;
	
	/* Register the signal handler for termination */
	signal(SIGINT, stop_signal_handler);
	signal(SIGHUP, stop_signal_handler);
	signal(SIGTERM, stop_signal_handler);
	
	while (run_comm_loop)
	{
		struct timeval timeout = { 1, 0 }; /* 1 second */
		
		eemo_mux_build_fd_set(&select_socks, feed_server_socket, client_server_socket);	
		
		int rv = select(FD_SETSIZE, &select_socks, NULL, NULL, &timeout);
		
		if (rv < 0)
		{
			switch(errno)
			{
			case EINTR:
				continue;
			default:
				ERROR_MSG("Call to select(...) returned an error unexpectedly, giving up");
				run_comm_loop = 0;
				continue;
			}
		}
		else if (rv == 0)
		{
			continue;
		}
		
		/* Determine which sockets require action */
		if (FD_ISSET(feed_server_socket, &select_socks))
		{
			/* New feed */
			eemo_mux_new_feed(feed_server_socket);
			
			rv--;
		}
		
		if (rv && FD_ISSET(client_server_socket, &select_socks))
		{
			/* New client */
			
			rv--;
		}
		
		if (rv) LL_FOREACH(feeds, feed_it)
		{
			if (FD_ISSET(feed_it->socket, &select_socks))
			{
				if (eemo_mux_handle_feed_packet(feed_it->socket) != 0)
				{
					eemo_mux_unregister_feed(feed_it->socket);
				}
				
				rv--;
				
				if (!rv) break;
			}
		}
		
		if (rv)	LL_FOREACH(clients, client_it)
		{
			if (FD_ISSET(client_it->socket, &select_socks))
			{
				/* This can only be a client that disconnects */
				eemo_mux_handle_client_packet(client_it->socket);
			}
			
			rv--;
			
			if (!rv) break;
		}
	}
	
	/* Unregister signal handlers */
	signal(SIGINT, SIG_DFL);
	signal(SIGHUP, SIG_DFL);
	signal(SIGTERM, SIG_DFL);
	
	eemo_mux_disconnect_feeds();
	eemo_mux_disconnect_clients();
	
	close(feed_server_socket);
	close(client_server_socket);
}

/* Run the multiplexer */
void eemo_mux_run_multiplexer(void)
{
	INFO_MSG("Starting multiplexer feed service");
	
	clients = NULL;
	feeds = NULL;
	
	eemo_mux_comm_loop();
}
