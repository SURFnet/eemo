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
#include "eemo_tlscomm.h"
#include "eemo_mux_cmdxfer.h"
#include "utlist.h"
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <signal.h>
#include <stdlib.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX 			80		/* should be safe! */
#endif /* !UNIX_PATH_MAX */

#define SENSOR_ID_UNREGISTERED				-1

/* Feed administration */
typedef struct sensor_spec
{
	SSL*			tls;				/* TLS context */
	int 			socket;				/* data socket */
	int 			id;				/* sensor ID */
	char*			feed_guid;			/* long identifier */
	char*			feed_desc;			/* feed description */
	unsigned long long	pkt_count;			/* number of packets received on feed */
	unsigned long long	byte_count;			/* number of bytes received on feed */
	char			ip_str[INET6_ADDRSTRLEN];	/* IP address of the sensor */

	struct sensor_spec* 	next;				/* LL next item */
}
sensor_spec;

static sensor_spec* sensors = NULL;

/* Client administration */
typedef struct client_spec
{
	SSL*			tls;				/* TLS context */
	int 			socket;				/* data socket */
	int 			subscribed_id;			/* to which feed is the client subscribed? */
	unsigned long long	pkt_count;			/* number of packets sent to client */
	unsigned long long	byte_count;			/* number of bytes sent to client */
	char			ip_str[INET6_ADDRSTRLEN];	/* IP address of the client */
	
	struct client_spec* next;				/* LL next item */
}
client_spec;

static client_spec*	clients		= NULL;

/* Should the communications loop keep running? */
static int 		run_comm_loop 	= 1;

/* SSL/TLS state */
static SSL_CTX* 	sensor_tls_ctx	= NULL;

/* Current sensor ID */
static int		current_id	= 1;

/* Signal handler for exit signal */
void stop_signal_handler(int signum)
{
	INFO_MSG("Received request to exit");

	run_comm_loop = 0;
}

/* Handle a feed registration */
void eemo_mux_new_sensor(const int sensor_socket)
{
	struct sockaddr_storage	sensor_addr 			= { 0 };
	socklen_t		addr_len			= sizeof(struct sockaddr_storage);
	struct sockaddr_in6*	inet6_addr			= (struct sockaddr_in6*) &sensor_addr;
	int			sensor_sock			= -1;
	char			addr_str[INET6_ADDRSTRLEN]	= { 0 };
	sensor_spec*		new_sensor			= (sensor_spec*) malloc(sizeof(sensor_spec));
	int			err				= -1;
	X509*			peer_cert			= NULL;
	X509_NAME*		peer_subject			= NULL;
	
	memset(new_sensor, 0, sizeof(sensor_spec));
	
	/* First, accept the incoming connection */
	if ((sensor_sock = accept(sensor_socket, (struct sockaddr*) &sensor_addr, &addr_len)) < 0)
	{
		ERROR_MSG("New sensor failed to connect");
		
		free(new_sensor);
		
		return;
	}
	
	if (sensor_addr.ss_family == AF_INET6)
	{
		if (IN6_IS_ADDR_V4MAPPED(&inet6_addr->sin6_addr))
		{
			INFO_MSG("New sensor connected from %d.%d.%d.%d", inet6_addr->sin6_addr.s6_addr[12], inet6_addr->sin6_addr.s6_addr[13], inet6_addr->sin6_addr.s6_addr[14], inet6_addr->sin6_addr.s6_addr[15]);

			snprintf(new_sensor->ip_str, INET6_ADDRSTRLEN, "%d.%d.%d.%d", inet6_addr->sin6_addr.s6_addr[12], inet6_addr->sin6_addr.s6_addr[13], inet6_addr->sin6_addr.s6_addr[14], inet6_addr->sin6_addr.s6_addr[15]);
		}
		else
		{
			INFO_MSG("New sensor connected from %s", inet_ntop(AF_INET6, (struct in6_addr*) &inet6_addr->sin6_addr, &addr_str[0], sizeof(struct in6_addr)));

			strcpy(new_sensor->ip_str, addr_str);
		}
	}
	else
	{
		WARNING_MSG("New sensor connected with unknown address family");
	}
	
	/* Start TLS negotiation */
	new_sensor->tls = SSL_new(sensor_tls_ctx);
	new_sensor->socket = sensor_sock;
	
	if ((new_sensor->tls == NULL) || (SSL_set_fd(new_sensor->tls, sensor_sock) != 1))
	{
		ERROR_MSG("Failed to set up new TLS context");
		
		SSL_free(new_sensor->tls);
		
		close(sensor_sock);
		
		free(new_sensor);
		
		return;
	}
	
	/* Perform TLS handshake */
	if ((err = SSL_accept(new_sensor->tls)) != 1)
	{
		ERROR_MSG("TLS handshake failed, closing connection (%s, %d)", eemo_tls_get_err(new_sensor->tls, err), err);
		ERROR_MSG("Did you run c_rehash on the sensor certificate directory?");
		
		SSL_shutdown(new_sensor->tls);
		SSL_free(new_sensor->tls);
		
		close(sensor_sock);
		
		free(new_sensor);
		
		return;
	}
	
	INFO_MSG("TLS handshake successful");
	
	/* Get peer certificate */
	peer_cert = SSL_get_peer_certificate(new_sensor->tls);
	
	if (peer_cert == NULL)
	{
		ERROR_MSG("Peer did not send a client certificate, closing connection");
		ERROR_MSG("Did you run c_rehash on the sensor certificate directory?");
		
		SSL_shutdown(new_sensor->tls);
		SSL_free(new_sensor->tls);
		
		close(sensor_sock);
		
		free(new_sensor);
		
		return;
	}
	
	peer_subject = X509_get_subject_name(peer_cert);
	
	if (peer_subject != NULL)
	{
		char buf[4096] = { 0 };
		
		X509_NAME_oneline(peer_subject, buf, 4096);
		
		INFO_MSG("Peer certificate subject: %s", buf);
	}
	
	X509_free(peer_cert);
	
	new_sensor->pkt_count = 0;
	new_sensor->byte_count = 0;
	new_sensor->id = current_id++;

	/* Add a new sensor to the administration */
	LL_APPEND(sensors, new_sensor);

	INFO_MSG("Register sensor with ID %d", new_sensor->id);
}

/* Handle a sensor deregistration */
void eemo_mux_unregister_sensor(const int socket, const int is_graceful)
{
	sensor_spec*	sensor_it	= NULL;
	
	LL_FOREACH(sensors, sensor_it)
	{
		if (sensor_it->socket == socket)
		{
			if (sensor_it->tls != NULL)
			{
				SSL_shutdown(sensor_it->tls);
				SSL_free(sensor_it->tls);

				if (!is_graceful)
				{
					WARNING_MSG("Performed hard TLS shutdown for sensor %d", sensor_it->id);
				}
				else
				{
					INFO_MSG("TLS shutdown complete for sensor %d", sensor_it->id);
				}
			}
			
			if (sensor_it->socket >= 0)
			{
				close(sensor_it->socket);

				if (!is_graceful)
				{
					WARNING_MSG("Performed hard disconnect for sensor %d", sensor_it->id);
				}
				else
				{	
					INFO_MSG("Connection to sensor %d closed", sensor_it->id);
				}
			}
			
			LL_DELETE(sensors, sensor_it);
		
			INFO_MSG("Sensor %d sent %llu packets totalling %llu bytes", sensor_it->id, sensor_it->pkt_count, sensor_it->byte_count);
			INFO_MSG("Unregistered sensor %d (%s)", sensor_it->id, sensor_it->ip_str);
		
			free(sensor_it->feed_guid);
			free(sensor_it->feed_desc);
			free(sensor_it);
			
			return;			
		}
	}
	
	ERROR_MSG("Request to unregister unknown sensor on socket %d", socket);
}

/* Handle a client registration */
void eemo_mux_new_client(const int socket)
{
}

/* Handle a client deregistration */
void eemo_mux_unregister_client(const int socket)
{
}

/* Handle a sensor packet */
eemo_rv eemo_mux_handle_sensor_packet(const int socket)
{
	sensor_spec*	sensor_it	= NULL;
	eemo_rv		rv		= 0;
	eemo_mux_cmd	cmd		= { 0, 0, NULL };
	
	/* Find the sensor */
	LL_SEARCH_SCALAR(sensors, sensor_it, socket, socket);
	
	if (sensor_it == NULL)
	{
		ERROR_MSG("Received data on unregistered sensor socket %d", socket);
		
		return ERV_GENERAL_ERROR;
	}
	
	/* Receive command */
	if ((rv = eemo_cx_recv(sensor_it->tls, &cmd)) != ERV_OK)
	{
		ERROR_MSG("Failed to receive command data from sensor socket %d", socket);

		return rv;
	}

	switch(cmd.cmd_id)
	{
	case SENSOR_GET_PROTO_VERSION:
		{
			uint16_t	proto_version	= htons(SENSOR_PROTO_VERSION);

			/* Send protocol version back to the sensor */
			DEBUG_MSG("Sending protocol version %d to sensor on socket %d", SENSOR_PROTO_VERSION, socket);

			eemo_cx_cmd_free(&cmd);
			
			return eemo_cx_send(sensor_it->tls, SENSOR_GET_PROTO_VERSION, sizeof(uint16_t), (const uint8_t*) &proto_version);
		}
		break;
	case SENSOR_REGISTER:
		{
			if (sensor_it->feed_guid != NULL)
			{
				free(sensor_it->feed_guid);
				sensor_it->feed_guid = NULL;
			}

			sensor_it->feed_guid = strdup((char*) cmd.cmd_data);

			INFO_MSG("Sensor %d feed GUID = %s", sensor_it->id, sensor_it->feed_guid);

			eemo_cx_cmd_free(&cmd);

			/* Send ACK */
			return eemo_cx_send(sensor_it->tls, SENSOR_REGISTER, 0, NULL);
		}
		break;
	case SENSOR_SET_DESCRIPTION:
		{
			if (sensor_it->feed_desc != NULL)
			{
				free(sensor_it->feed_desc);
				sensor_it->feed_desc = NULL;
			}

			sensor_it->feed_desc = strdup((char*) cmd.cmd_data);

			INFO_MSG("Sensor %d feed has description \"%s\"", sensor_it->id, sensor_it->feed_desc);

			eemo_cx_cmd_free(&cmd);

			/* Send ACK */
			return eemo_cx_send(sensor_it->tls, SENSOR_SET_DESCRIPTION, 0, NULL);
		}
		break;
	case SENSOR_UNREGISTER:
		{
			INFO_MSG("Sensor %d has unregistered feed %s (%s)", sensor_it->id, sensor_it->feed_guid, sensor_it->feed_desc);

			eemo_cx_cmd_free(&cmd);

			free(sensor_it->feed_guid);
			free(sensor_it->feed_desc);

			sensor_it->feed_guid = NULL;
			sensor_it->feed_desc = NULL;

			/* Send ACK */
			return eemo_cx_send(sensor_it->tls, SENSOR_UNREGISTER, 0, NULL);
		}
		break;
	case SENSOR_SHUTDOWN:
		{
			INFO_MSG("Sensor %d is shutting down", sensor_it->id);

			eemo_cx_cmd_free(&cmd);

			/* Send ACK */
			if (eemo_cx_send(sensor_it->tls, SENSOR_SHUTDOWN, 0, NULL) != ERV_OK)
			{
				WARNING_MSG("Failed to acknowledge shutdown of the sensor");

				eemo_mux_unregister_sensor(socket, 0);
			}
			else
			{
				/* Gracefully disconnect and unregister the sensor */
				eemo_mux_unregister_sensor(socket, 1);
			}

			return ERV_OK;
		}
		break;
	case SENSOR_DATA:
		{
			/* Acknowledge receipt */
			if ((rv = eemo_cx_send(sensor_it->tls, SENSOR_DATA, 0, NULL)) != ERV_OK)
			{
				ERROR_MSG("Failed to send acknowledgement for data");

				return rv;
			}

			/* Unpack the data */
			eemo_mux_pkt*	pkt	= eemo_cx_deserialize_pkt(&cmd);

			eemo_cx_cmd_free(&cmd);

			/* TODO: send data to all interested clients */

			/* Keep tally of the amount of data received */
			sensor_it->pkt_count++;
			sensor_it->byte_count += pkt->pkt_len;

			/* Clean up */
			eemo_cx_pkt_free(pkt);
		}
		break;
	default:
		{
			ERROR_MSG("Unknown command received from sensor %d on socket %d", sensor_it->id, socket);

			return ERV_GENERAL_ERROR;
		}
		break;
	}
	
	return ERV_OK;
}

/* Handle a client packet */
int eemo_mux_handle_client_packet(const int socket)
{
	return 0;
}

/* Set up sensor server socket */
int eemo_mux_setup_sensor_socket(void)
{
	int 			sensor_socket 	= -1;
	int 			on		= 1;
	int 			server_port	= 6969;
	struct sockaddr_in6	server_addr 	= { 0 };
	char*			cert_file	= NULL;
	char*			key_file	= NULL;
	char*			cert_dir	= NULL;
	
	
	/* Open socket */
	if ((sensor_socket = socket(AF_INET6, SOCK_STREAM, 0)) < 0)
	{
		ERROR_MSG("Failed to create a new sensor server socket");
		
		return -1;
	}
	
	/* Allow address re-use without time-out */
	setsockopt(sensor_socket, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	
	/* Bind to port on IPv4 and IPv6 */
	server_addr.sin6_family = AF_INET6;
	
	if (eemo_conf_get_int("server", "server_port", &server_port, 6969) != ERV_OK)
	{
		ERROR_MSG("Failed to read configuration value for sensor server port");
		
		close(sensor_socket);
		
		return -1;
	}
	
	server_addr.sin6_port = htons(server_port);
	server_addr.sin6_addr = in6addr_any;
	
	if (bind(sensor_socket, (struct sockaddr*) &server_addr, sizeof(server_addr)) != 0)
	{
		ERROR_MSG("Failed to bind sensor server to port %d", server_port);
		
		close(sensor_socket);
		
		return -1;
	}
	
	INFO_MSG("Feed server bound to port %d", server_port);
	
	/* Now set up TLS */
	sensor_tls_ctx = SSL_CTX_new(TLSv1_server_method());
	
	if (sensor_tls_ctx == NULL)
	{
		ERROR_MSG("Failed to setup up TLS v1 on the server socket");
		
		close(sensor_socket);
		
		return -1;
	}
	
	/* Load the certificate and private key */
	if ((eemo_conf_get_string("server", "server_cert", &cert_file, NULL) != ERV_OK) || (cert_file == NULL))
	{
		ERROR_MSG("No TLS server certificate configured");
		
		SSL_CTX_free(sensor_tls_ctx);
		sensor_tls_ctx = NULL;
		close(sensor_socket);
		
		return -1;
	}
	
	if ((eemo_conf_get_string("server", "server_key", &key_file, NULL) != ERV_OK) || (key_file == NULL))
	{
		ERROR_MSG("No TLS key configured");
		
		SSL_CTX_free(sensor_tls_ctx);
		sensor_tls_ctx = NULL;
		free(cert_file);
		close(sensor_socket);
		
		return -1;
	}
	
	if ((SSL_CTX_use_certificate_file(sensor_tls_ctx, cert_file, SSL_FILETYPE_PEM) != 1) &&
	    (SSL_CTX_use_certificate_file(sensor_tls_ctx, cert_file, SSL_FILETYPE_ASN1) != 1))
	{
		ERROR_MSG("Failed to load TLS certificate from %s", cert_file);
		
		SSL_CTX_free(sensor_tls_ctx);
		sensor_tls_ctx = NULL;
		free(cert_file);
		free(key_file);
		close(sensor_socket);
		
		return -1;
	}
	
	INFO_MSG("Loaded TLS certificate");
	
	if ((SSL_CTX_use_PrivateKey_file(sensor_tls_ctx, key_file, SSL_FILETYPE_PEM) != 1) &&
	    (SSL_CTX_use_PrivateKey_file(sensor_tls_ctx, key_file, SSL_FILETYPE_ASN1) != 1))
	{
		ERROR_MSG("Failed to load TLS key from %s", key_file);
		
		SSL_CTX_free(sensor_tls_ctx);
		sensor_tls_ctx = NULL;
		free(cert_file);
		free(key_file);
		close(sensor_socket);
		
		return -1;
	}
	
	INFO_MSG("Loaded TLS key");
	
	free(cert_file);
	free(key_file);
	
	/* Set TLS options */
	if (SSL_CTX_set_cipher_list(sensor_tls_ctx, "HIGH:!DSS:!aNULL@STRENGTH'") != 1)
	{
		ERROR_MSG("Failed to select safe TLS ciphers, giving up");
		
		SSL_CTX_free(sensor_tls_ctx);
		sensor_tls_ctx = NULL;
		close(sensor_socket);
		
		return -1;
	}
	
	/* Configure valid certificates */
	if (eemo_conf_get_string("server", "sensor_cert_dir", &cert_dir, NULL) == ERV_OK)
	{
		INFO_MSG("Checking for valid client certificates in %s", cert_dir);
		
		SSL_CTX_load_verify_locations(sensor_tls_ctx, NULL, cert_dir);
		
		free(cert_dir);
	}
	else
	{
		ERROR_MSG("Failed to obtain configuration option server/sensor_cert_dir");
		
		SSL_CTX_free(sensor_tls_ctx);
		sensor_tls_ctx = NULL;
		close(sensor_socket);
		
		return -1;
	}
	
	SSL_CTX_set_verify(sensor_tls_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
	
	/* Start listening */
	if (listen(sensor_socket, 10) < 0)
	{
		ERROR_MSG("Failed to listen to sensor server port %d", server_port);
		
		SSL_CTX_free(sensor_tls_ctx);
		sensor_tls_ctx = NULL;
		close(sensor_socket);
		
		return -1;
	}
	
	INFO_MSG("Listening for incoming sensors");
	
	return sensor_socket;
}

/* Tear down sensor server socket */
void eemo_mux_teardown_sensor_socket(const int sensor_socket)
{	
	if (sensor_tls_ctx != NULL)
	{
		SSL_CTX_free(sensor_tls_ctx);
		sensor_tls_ctx = NULL;
	}
	
	/* Close the socket */
	close(sensor_socket);
	
	INFO_MSG("Closed sensor socket %d", sensor_socket);
}

/* Set up multiplexer client server socket */
int eemo_mux_setup_client_socket(void)
{
	int 			client_socket	= -1;
	char* 			sock_filename	= NULL;
	struct sockaddr_un	server_addr	= { 0 };
	
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

/* Disconnect all sensors */
void eemo_mux_disconnect_sensors(void)
{
	sensor_spec*	sensor_it	= NULL;
	sensor_spec*	tmp_it	= NULL;
	int ctr = 0;
	
	LL_FOREACH_SAFE(sensors, sensor_it, tmp_it)
	{
		if (sensor_it->tls != NULL)
		{
			SSL_shutdown(sensor_it->tls);
			SSL_free(sensor_it->tls);
		}
		
		close(sensor_it->socket);
		ctr++;
		
		LL_DELETE(sensors, sensor_it);
		
		free(sensor_it);
	}
	
	INFO_MSG("Disconnected %d sensor%s", ctr, (ctr == 1) ? "" : "s");
}

/* Disconnect all clients */
void eemo_mux_disconnect_clients(void)
{
	client_spec*	client_it	= NULL;
	client_spec*	tmp_it		= NULL;
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
		
		free(client_it);
	}
	
	INFO_MSG("Disconnected %d client%s", ctr, (ctr == 1) ? "" : "s");
}

/* Build the file descriptor set for select(...) */
void eemo_mux_build_fd_set(fd_set* select_socks, const int sensor_server_socket, const int client_server_socket)
{
	sensor_spec*	sensor_it 	= NULL;
	client_spec* 	client_it 	= NULL;
	
	FD_ZERO(select_socks);

	/* Add sensor and client server sockets */
	FD_SET(sensor_server_socket, select_socks);
	FD_SET(client_server_socket, select_socks);
	
	/* Add sensor data sockets */
	LL_FOREACH(sensors, sensor_it)
	{
		FD_SET(sensor_it->socket, select_socks);
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
	int 		sensor_server_socket	= 0;
	int 		client_server_socket	= 0;
	sensor_spec*	sensor_it			= NULL;
	client_spec*	client_it		= NULL;
	fd_set		select_socks;
	
	/* Set up sensor server socket */
	sensor_server_socket = eemo_mux_setup_sensor_socket();
	
	if (sensor_server_socket < 0)
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
		
		eemo_mux_build_fd_set(&select_socks, sensor_server_socket, client_server_socket);	
		
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
		if (FD_ISSET(sensor_server_socket, &select_socks))
		{
			/* New sensor */
			eemo_mux_new_sensor(sensor_server_socket);
			
			rv--;
		}
		
		if (rv && FD_ISSET(client_server_socket, &select_socks))
		{
			/* New client */
			
			rv--;
		}
		
		if (rv) LL_FOREACH(sensors, sensor_it)
		{
			if (FD_ISSET(sensor_it->socket, &select_socks))
			{
				if (eemo_mux_handle_sensor_packet(sensor_it->socket) != ERV_OK)
				{
					eemo_mux_unregister_sensor(sensor_it->socket, 0);
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
	
	eemo_mux_disconnect_sensors();
	eemo_mux_disconnect_clients();
	
	close(sensor_server_socket);
	close(client_server_socket);
}

/* Run the multiplexer */
void eemo_mux_run_multiplexer(void)
{
	INFO_MSG("Starting multiplexer service");
	
	clients = NULL;
	sensors = NULL;
	
	eemo_mux_comm_loop();

	INFO_MSG("Exiting multiplexer service");
}

