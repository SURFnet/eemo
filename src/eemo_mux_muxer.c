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
#include "utlist.h"
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <signal.h>
#include <stdlib.h>

#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX 			80		/* should be safe! */
#endif /* !UNIX_PATH_MAX */

/* Feed administration */
typedef struct feed_spec
{
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
void eemo_mux_new_feed(const int socket)
{
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
	int feed_socket = -1;
	int on			= 1;
	int server_port	= 6969;
	struct sockaddr_in6 server_addr = { 0 };
	
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
	
	/* Start listening */
	if (listen(feed_socket, 10) < 0)
	{
		ERROR_MSG("Failed to listen to feed server port %d", server_port);
		
		close(feed_socket);
		
		return -1;
	}
	
	INFO_MSG("Listening for incoming feeds");
	
	return feed_socket;
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
	int				rebuild_fd_set			= 0;
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
	
	/* Build file descriptor set for the first time */
	eemo_mux_build_fd_set(&select_socks, feed_server_socket, client_server_socket);
	
	run_comm_loop = 1;
	
	/* Register the signal handler for termination */
	signal(SIGINT, stop_signal_handler);
	signal(SIGHUP, stop_signal_handler);
	signal(SIGTERM, stop_signal_handler);
	
	while (run_comm_loop)
	{
		struct timeval timeout = { 1, 0 }; /* 1 second */
		
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
					
					rebuild_fd_set = 1;
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
				rebuild_fd_set = 1;
			}
			
			rv--;
			
			if (!rv) break;
		}
		
		if (rebuild_fd_set) eemo_mux_build_fd_set(&select_socks, feed_server_socket, client_server_socket);
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
