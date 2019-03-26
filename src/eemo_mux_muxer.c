/*
 * Copyright (c) 2010-2015 SURFnet bv
 * Copyright (c) 2015 Roland van Rijswijk-Deij
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
#include "eemo_mux_queue.h"
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
#include <openssl/ec.h>
#include <openssl/bn.h>

/* Sensor administration */
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

/* Client subscriptions */
typedef struct client_subs
{
	int			id;				/* ID of sensor subscribed to */
	char*			guid;				/* GUID of the feed subscribed to */
	struct client_subs*	next;
}
client_subs;

/* Client administration */
typedef struct client_spec
{
	SSL*			tls;				/* TLS context */
	int 			socket;				/* data socket */
	client_subs*		subscriptions;			/* subscriptions to feeds from sensors */
	mux_queue*		q;				/* client queue */
	unsigned long long	pkt_count;			/* number of packets sent to client */
	unsigned long long	byte_count;			/* number of bytes sent to client */
	char			ip_str[INET6_ADDRSTRLEN];	/* IP address of the client */
	
	struct client_spec* 	next;				/* LL next item */
}
client_spec;

static client_spec*	clients		= NULL;

/* Should the communications loop keep running? */
static int 		run_comm_loop 	= 1;

/* SSL/TLS state */
static SSL_CTX* 	sensor_tls_ctx	= NULL;
static SSL_CTX* 	client_tls_ctx	= NULL;

/* Current sensor ID */
static int		current_id	= 1;

/* Queue configuration */
static int		max_queue_len	= 0;
static int		q_flush_th	= 1000;

/* Signal handler for exit signal */
static void stop_signal_handler(int signum)
{
	INFO_MSG("Received request to exit");

	run_comm_loop = 0;
}

/* Handle a feed registration */
static void eemo_mux_new_sensor(const int sensor_socket)
{
	struct sockaddr_storage	sensor_addr 			= { 0 };
	socklen_t		addr_len			= sizeof(struct sockaddr_storage);
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
		struct sockaddr_in6	inet6_addr;

		memcpy(&inet6_addr, &sensor_addr, sizeof(struct sockaddr_in6));

		if (IN6_IS_ADDR_V4MAPPED(&inet6_addr.sin6_addr))
		{
			INFO_MSG("New sensor connected from %d.%d.%d.%d", inet6_addr.sin6_addr.s6_addr[12], inet6_addr.sin6_addr.s6_addr[13], inet6_addr.sin6_addr.s6_addr[14], inet6_addr.sin6_addr.s6_addr[15]);

			snprintf(new_sensor->ip_str, INET6_ADDRSTRLEN, "%d.%d.%d.%d", inet6_addr.sin6_addr.s6_addr[12], inet6_addr.sin6_addr.s6_addr[13], inet6_addr.sin6_addr.s6_addr[14], inet6_addr.sin6_addr.s6_addr[15]);
		}
		else
		{
			INFO_MSG("New sensor connected from %s", inet_ntop(AF_INET6, (struct in6_addr*) &inet6_addr.sin6_addr, &addr_str[0], INET6_ADDRSTRLEN));

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

	INFO_MSG("Registered sensor with ID %d", new_sensor->id);

}

/* Shut down a sensor */
static void eemo_mux_shutdown_sensor(sensor_spec* sensor, const int is_graceful)
{
	if (sensor->tls != NULL)
	{
		SSL_shutdown(sensor->tls);
		SSL_free(sensor->tls);

		if (!is_graceful)
		{
			WARNING_MSG("Performed hard TLS shutdown for sensor %d", sensor->id);
		}
		else
		{
			INFO_MSG("TLS shutdown complete for sensor %d", sensor->id);
		}
	}
	
	if (sensor->socket >= 0)
	{
		close(sensor->socket);

		if (!is_graceful)
		{
			WARNING_MSG("Performed hard disconnect for sensor %d", sensor->id);
		}
		else
		{	
			INFO_MSG("Connection to sensor %d closed", sensor->id);
		}
	}

	INFO_MSG("Sensor %d sent %llu packets totalling %llu bytes", sensor->id, sensor->pkt_count, sensor->byte_count);
}

/* Handle a sensor deregistration */
static void eemo_mux_unregister_sensor(const int socket, const int is_graceful)
{
	sensor_spec*	sensor_it	= NULL;
	client_spec*	client_it	= NULL;
	
	LL_FOREACH(sensors, sensor_it)
	{
		if (sensor_it->socket == socket)
		{
			eemo_mux_shutdown_sensor(sensor_it, is_graceful);

			LL_DELETE(sensors, sensor_it);
		
			INFO_MSG("Unregistered sensor %d (%s)", sensor_it->id, sensor_it->ip_str);
	
			/* Update client subscriptions */
			LL_FOREACH(clients, client_it)
			{
				client_subs*	subs_it	= NULL;

				LL_FOREACH(client_it->subscriptions, subs_it)
				{
					if (subs_it->id == sensor_it->id)
					{
						subs_it->id = -1;

						INFO_MSG("Client from %s will no longer receive data from sensor %d", client_it->ip_str, sensor_it->id);
					}
				}
			}

			free(sensor_it->feed_guid);
			free(sensor_it->feed_desc);
			free(sensor_it);
			
			return;			
		}
	}
	
	ERROR_MSG("Request to unregister unknown sensor on socket %d", socket);
}

/* Handle a client registration */
static void eemo_mux_new_client(const int client_socket)
{
	struct sockaddr_storage	client_addr 			= { 0 };
	socklen_t		addr_len			= sizeof(struct sockaddr_storage);
	int			client_sock			= -1;
	char			addr_str[INET6_ADDRSTRLEN]	= { 0 };
	client_spec*		new_client			= (client_spec*) malloc(sizeof(client_spec));
	int			err				= -1;
	X509*			peer_cert			= NULL;
	X509_NAME*		peer_subject			= NULL;
	
	memset(new_client, 0, sizeof(client_spec));
	
	/* First, accept the incoming connection */
	if ((client_sock = accept(client_socket, (struct sockaddr*) &client_addr, &addr_len)) < 0)
	{
		ERROR_MSG("New client failed to connect");
		
		free(new_client);
		
		return;
	}
	
	if (client_addr.ss_family == AF_INET6)
	{
		struct sockaddr_in6	inet6_addr;

		memcpy(&inet6_addr, &client_addr, sizeof(struct sockaddr_in6));

		if (IN6_IS_ADDR_V4MAPPED(&inet6_addr.sin6_addr))
		{
			INFO_MSG("New client connected from %d.%d.%d.%d", inet6_addr.sin6_addr.s6_addr[12], inet6_addr.sin6_addr.s6_addr[13], inet6_addr.sin6_addr.s6_addr[14], inet6_addr.sin6_addr.s6_addr[15]);

			snprintf(new_client->ip_str, INET6_ADDRSTRLEN, "%d.%d.%d.%d", inet6_addr.sin6_addr.s6_addr[12], inet6_addr.sin6_addr.s6_addr[13], inet6_addr.sin6_addr.s6_addr[14], inet6_addr.sin6_addr.s6_addr[15]);
		}
		else
		{
			INFO_MSG("New client connected from %s", inet_ntop(AF_INET6, (struct in6_addr*) &inet6_addr.sin6_addr, &addr_str[0], INET6_ADDRSTRLEN));

			strcpy(new_client->ip_str, addr_str);
		}
	}
	else
	{
		WARNING_MSG("New client connected with unknown address family");
	}
	
	/* Start TLS negotiation */
	new_client->tls = SSL_new(client_tls_ctx);
	new_client->socket = client_sock;
	
	if ((new_client->tls == NULL) || (SSL_set_fd(new_client->tls, client_sock) != 1))
	{
		ERROR_MSG("Failed to set up new TLS context");
		
		SSL_free(new_client->tls);
		
		close(client_sock);
		
		free(new_client);
		
		return;
	}
	
	/* Perform TLS handshake */
	if ((err = SSL_accept(new_client->tls)) != 1)
	{
		ERROR_MSG("TLS handshake failed, closing connection (%s, %d)", eemo_tls_get_err(new_client->tls, err), err);
		ERROR_MSG("Did you run c_rehash on the client certificate directory?");
		
		SSL_shutdown(new_client->tls);
		SSL_free(new_client->tls);
		
		close(client_sock);
		
		free(new_client);
		
		return;
	}
	
	INFO_MSG("TLS handshake successful");
	
	/* Get peer certificate */
	peer_cert = SSL_get_peer_certificate(new_client->tls);
	
	if (peer_cert == NULL)
	{
		ERROR_MSG("Peer did not send a client certificate, closing connection");
		ERROR_MSG("Did you run c_rehash on the client certificate directory?");
		
		SSL_shutdown(new_client->tls);
		SSL_free(new_client->tls);
		
		close(client_sock);
		
		free(new_client);
		
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
	
	new_client->pkt_count = 0;
	new_client->byte_count = 0;

	/* Start new client queue */
	new_client->q = eemo_q_new(new_client->tls, max_queue_len, q_flush_th, 1000);

	if (new_client->q == NULL)
	{
		ERROR_MSG("Failed to open new client queue for this client, giving up!");

		SSL_shutdown(new_client->tls);
		SSL_free(new_client->tls);

		close(client_sock);

		free(new_client);

		return;
	}

	/* Add a new client to the administration */
	LL_APPEND(clients, new_client);

	INFO_MSG("Client registration complete");
}

/* Shut down a client */
static void eemo_mux_shutdown_client(client_spec* client, const int is_graceful)
{
	/* Stop and clean up the client queue */
	if (client->q != NULL)
	{
		eemo_q_stop(client->q);
		client->q = NULL;
	}

	if (client->tls != NULL)
	{
		SSL_shutdown(client->tls);
		SSL_free(client->tls);

		if (!is_graceful)
		{
			WARNING_MSG("Performed hard TLS shutdown for client from %s", client->ip_str);
		}
		else
		{
			INFO_MSG("TLS shutdown complete for client from %s", client->ip_str);
		}

		client->tls = NULL;
	}
	
	if (client->socket >= 0)
	{
		close(client->socket);

		if (!is_graceful)
		{
			WARNING_MSG("Performed hard disconnect for client from %s", client->ip_str);
		}
		else
		{	
			INFO_MSG("Connection to client from %s closed", client->ip_str);
		}
	}

	INFO_MSG("Client from %s received %llu packets totalling %llu bytes", client->ip_str, client->pkt_count, client->byte_count);
}

/* Handle a client deregistration */
static void eemo_mux_unregister_client(const int socket, const int is_graceful)
{
	client_spec*	client_it	= NULL;
	client_subs*	subs_it		= NULL;
	client_subs*	subs_tmp	= NULL;
	
	LL_FOREACH(clients, client_it)
	{
		if (client_it->socket == socket)
		{
			eemo_mux_shutdown_client(client_it, is_graceful);

			LL_DELETE(clients, client_it);
		
			INFO_MSG("Unregistered client from %s", client_it->ip_str);

			LL_FOREACH_SAFE(client_it->subscriptions, subs_it, subs_tmp)
			{
				free(subs_it->guid);
				free(subs_it);
			}

			free(client_it);
			
			return;			
		}
	}
	
	ERROR_MSG("Request to unregister unknown client on socket %d", socket);
}

/* Handle a sensor packet */
static eemo_rv eemo_mux_handle_sensor_packet(const int socket)
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
			client_spec*	client_it	= NULL;

			if (sensor_it->feed_guid != NULL)
			{
				free(sensor_it->feed_guid);
				sensor_it->feed_guid = NULL;
			}

			sensor_it->feed_guid = strdup((char*) cmd.cmd_data);

			INFO_MSG("Sensor %d feed GUID = %s", sensor_it->id, sensor_it->feed_guid);

			eemo_cx_cmd_free(&cmd);
	
			/* Update client subscriptions */
			LL_FOREACH(clients, client_it)
			{
				client_subs*	subs_it	= NULL;

				LL_FOREACH(client_it->subscriptions, subs_it)
				{
					if (strcasecmp(sensor_it->feed_guid, subs_it->guid) == 0)
					{
						subs_it->id = sensor_it->id;

						INFO_MSG("Client from %s will now receive feed data from sensor %d", client_it->ip_str, sensor_it->id);
					}
				}
			}

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
			client_spec*	client_it	= NULL;

			INFO_MSG("Sensor %d has unregistered feed %s (%s)", sensor_it->id, sensor_it->feed_guid, sensor_it->feed_desc);

			eemo_cx_cmd_free(&cmd);

			free(sensor_it->feed_guid);
			free(sensor_it->feed_desc);

			sensor_it->feed_guid = NULL;
			sensor_it->feed_desc = NULL;

			/* Update client subscriptions */
			LL_FOREACH(clients, client_it)
			{
				client_subs*	subs_it	= NULL;

				LL_FOREACH(client_it->subscriptions, subs_it)
				{
					if (subs_it->id == sensor_it->id)
					{
						subs_it->id = -1;

						INFO_MSG("Client from %s will no longer receive data from sensor %d", client_it->ip_str, sensor_it->id);
					}
				}
			}

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
			client_spec*	client_it	= NULL;
			client_spec*	client_tmp	= NULL;
			client_subs*	subs_it		= NULL;
			client_subs*	subs_tmp	= NULL;

			/* Unpack the data */
			eemo_mux_pkt*	pkt	= eemo_cx_deserialize_pkt(&cmd);

			eemo_cx_cmd_free(&cmd);

			/* Send data to all interested clients */
			LL_FOREACH_SAFE(clients, client_it, client_tmp)
			{
				LL_FOREACH_SAFE(client_it->subscriptions, subs_it, subs_tmp)
				{
					if (subs_it->id == sensor_it->id)
					{
						if ((rv = eemo_q_enqueue(client_it->q, pkt)) != ERV_OK)
						{
							if (rv == ERV_QUEUE_OVERFLOW)
							{
								WARNING_MSG("Client queue overflow for client from %s", client_it->ip_str);

								client_it->pkt_count++;
								client_it->byte_count += pkt->pkt_len;
							}
							else if (rv == ERV_QUEUE_OK)
							{
								INFO_MSG("Client queue no longer overflowing for client from %s", client_it->ip_str);

								client_it->pkt_count++;
								client_it->byte_count += pkt->pkt_len;
							}
							else
							{
								ERROR_MSG("Client error for client from %s", client_it->ip_str);

								eemo_mux_unregister_client(client_it->socket, 0);
							}
						}
						else
						{
							client_it->pkt_count++;
							client_it->byte_count += pkt->pkt_len;
						}
					}
				}
			}

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
static eemo_rv eemo_mux_handle_client_packet(const int socket)
{
	client_spec*	client_it	= NULL;
	eemo_rv		rv		= 0;
	eemo_mux_cmd	cmd		= { 0, 0, NULL };
	
	/* Find the client */
	LL_SEARCH_SCALAR(clients, client_it, socket, socket);
	
	if (client_it == NULL)
	{
		ERROR_MSG("Received data on unregistered client socket %d", socket);
		
		return ERV_GENERAL_ERROR;
	}
	
	/* Receive command */
	if ((rv = eemo_cx_recv(client_it->tls, &cmd)) != ERV_OK)
	{
		ERROR_MSG("Failed to receive command data from client socket %d", socket);

		eemo_cx_cmd_free(&cmd);

		return rv;
	}

	switch(cmd.cmd_id)
	{
	case MUX_CLIENT_GET_PROTO_VERSION:
		{
			uint16_t	proto_version	= htons(MUX_CLIENT_PROTO_VERSION);

			/* Send protocol version back to the client */
			DEBUG_MSG("Sending protocol version %d to client on socket %d", MUX_CLIENT_PROTO_VERSION, socket);

			eemo_cx_cmd_free(&cmd);
			
			return eemo_cx_send(client_it->tls, MUX_CLIENT_GET_PROTO_VERSION, sizeof(uint16_t), (const uint8_t*) &proto_version);
		}
		break;
	case MUX_CLIENT_SUBSCRIBE:
		{
			uint8_t	result		= MUX_SUBS_RES_NX;
			char*	subs_guid	= (char*) cmd.cmd_data;

			if (cmd.cmd_len > 0)
			{
				sensor_spec*	sensor_it	= NULL;
				sensor_spec*	sensor_tmp	= NULL;
				client_subs*	subs_it		= NULL;
				int		subs_exists	= 0;

				/* Check if the subscription already exists */
				LL_FOREACH(client_it->subscriptions, subs_it)
				{
					if (strcasecmp(subs_it->guid, subs_guid) == 0)
					{
						subs_exists = 1;
						break;
					}
				}

				if (!subs_exists)
				{
					LL_FOREACH_SAFE(sensors, sensor_it, sensor_tmp)
					{
						if (sensor_it->feed_guid == NULL)
						{
							WARNING_MSG("Skipping sensor that has not yet registered");

							continue;
						}

						if (strcasecmp(sensor_it->feed_guid, subs_guid) == 0)
						{
							client_subs*	new_subs	= (client_subs*) malloc(sizeof(client_subs));
	
							new_subs->guid = strdup(subs_guid);
							new_subs->id = sensor_it->id;
							LL_APPEND(client_it->subscriptions, new_subs);

							INFO_MSG("Client from %s subscribed to feed %s from sensor %d (%s)", client_it->ip_str, subs_guid, sensor_it->id, sensor_it->ip_str);
	
							result = MUX_SUBS_RES_OK;
							break;
						}
					}
	
					if (result == MUX_SUBS_RES_NX)
					{
						client_subs*	new_subs	= (client_subs*) malloc(sizeof(client_subs));

						new_subs->guid = strdup(subs_guid);
						new_subs->id = -1;
						LL_APPEND(client_it->subscriptions, new_subs);

						WARNING_MSG("Client from %s subscribed to absent feed %s", client_it->ip_str, subs_guid);
					}
				}
				else
				{
					ERROR_MSG("Client from %s attempted to subscribe to a feed that it has already subscribed to");

					result = MUX_SUBS_RES_ERR;
				}
			}

			eemo_cx_cmd_free(&cmd);

			return ERV_OK;
		}
		break;
	case MUX_CLIENT_SHUTDOWN:
		{
			INFO_MSG("Client from %s is shutting down", client_it->ip_str);

			eemo_cx_cmd_free(&cmd);

			/* Gracefully disconnect and unregister the client */
			eemo_mux_unregister_client(socket, 1);
			
			return ERV_OK;
		}
		break;
	default:
		{
			ERROR_MSG("Unknown command received from client from %s on socket %d", client_it->ip_str, socket);

			eemo_cx_cmd_free(&cmd);

			return ERV_GENERAL_ERROR;
		}
		break;
	}
	
	return ERV_OK;
}

/* Set up sensor server socket */
static int eemo_mux_setup_sensor_socket(void)
{
	int 			sensor_socket 	= -1;
	int 			on		= 1;
	int 			server_port	= 6969;
	struct sockaddr_in6	server_addr 	= { 0 };
	char*			cert_file	= NULL;
	char*			key_file	= NULL;
	char*			cert_dir	= NULL;
	EC_KEY*			dh_key		= NULL;
	
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
	
	if (eemo_conf_get_int("sensors", "server_port", &server_port, 6969) != ERV_OK)
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
	
	INFO_MSG("Sensor server bound to port %d", server_port);
	
	/* Now set up TLS */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	sensor_tls_ctx = SSL_CTX_new(TLSv1_2_server_method());
#else
	sensor_tls_ctx = SSL_CTX_new(TLS_server_method());
#endif
	
	if (sensor_tls_ctx == NULL)
	{
		ERROR_MSG("Failed to setup up TLS v1.2 on the server socket");
		
		close(sensor_socket);
		
		return -1;
	}

	/* Set renegotiation behaviour */
	SSL_CTX_set_mode(sensor_tls_ctx, SSL_MODE_AUTO_RETRY);

	/* Set DH behaviour */
	dh_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	
	if (dh_key == NULL)
	{
		ERROR_MSG("Failed to generate a new ECC key for ephemeral DH");

		SSL_CTX_free(sensor_tls_ctx);
		sensor_tls_ctx = NULL;
		close(sensor_socket);

		return -1;
	}

	if (SSL_CTX_set_tmp_ecdh(sensor_tls_ctx, dh_key) != 1)
	{
		ERROR_MSG("Failed to set DH parameters on TLS context");

		SSL_CTX_free(sensor_tls_ctx);
		sensor_tls_ctx = NULL;
		close(sensor_socket);

		return -1;
	}

	EC_KEY_free(dh_key);
	
	/* Load the certificate and private key */
	if ((eemo_conf_get_string("sensors", "server_cert", &cert_file, NULL) != ERV_OK) || (cert_file == NULL))
	{
		ERROR_MSG("No TLS server certificate configured");
		
		SSL_CTX_free(sensor_tls_ctx);
		sensor_tls_ctx = NULL;
		close(sensor_socket);
		
		return -1;
	}
	
	if ((eemo_conf_get_string("sensors", "server_key", &key_file, NULL) != ERV_OK) || (key_file == NULL))
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
	if (SSL_CTX_set_cipher_list(sensor_tls_ctx, EEMO_MUX_CIPHERSUITES) != 1)
	{
		ERROR_MSG("Failed to select safe TLS ciphers, giving up");
		
		SSL_CTX_free(sensor_tls_ctx);
		sensor_tls_ctx = NULL;
		close(sensor_socket);
		
		return -1;
	}
	
	/* Configure valid certificates */
	if (eemo_conf_get_string("sensors", "cert_dir", &cert_dir, NULL) == ERV_OK)
	{
		INFO_MSG("Checking for valid client certificates in %s", cert_dir);
		
		SSL_CTX_load_verify_locations(sensor_tls_ctx, NULL, cert_dir);
		
		free(cert_dir);
	}
	else
	{
		ERROR_MSG("Failed to obtain configuration option sensors/sensor_cert_dir");
		
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
static void eemo_mux_teardown_sensor_socket(const int sensor_socket)
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
static int eemo_mux_setup_client_socket(void)
{
	int 			client_socket 	= -1;
	int 			on		= 1;
	int 			server_port	= 6969;
	struct sockaddr_in6	server_addr 	= { 0 };
	char*			cert_file	= NULL;
	char*			key_file	= NULL;
	char*			cert_dir	= NULL;
	EC_KEY*			dh_key		= NULL;
	
	/* Open socket */
	if ((client_socket = socket(AF_INET6, SOCK_STREAM, 0)) < 0)
	{
		ERROR_MSG("Failed to create a new client server socket");
		
		return -1;
	}
	
	/* Allow address re-use without time-out */
	setsockopt(client_socket, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	
	/* Bind to port on IPv4 and IPv6 */
	server_addr.sin6_family = AF_INET6;
	
	if (eemo_conf_get_int("clients", "server_port", &server_port, 6970) != ERV_OK)
	{
		ERROR_MSG("Failed to read configuration value for client server port");
		
		close(client_socket);
		
		return -1;
	}
	
	server_addr.sin6_port = htons(server_port);
	server_addr.sin6_addr = in6addr_any;
	
	if (bind(client_socket, (struct sockaddr*) &server_addr, sizeof(server_addr)) != 0)
	{
		ERROR_MSG("Failed to bind client server to port %d", server_port);
		
		close(client_socket);
		
		return -1;
	}
	
	INFO_MSG("Client server bound to port %d", server_port);
	
	/* Now set up TLS */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	client_tls_ctx = SSL_CTX_new(TLSv1_2_server_method());
#else
	client_tls_ctx = SSL_CTX_new(TLS_server_method());
#endif
	
	if (client_tls_ctx == NULL)
	{
		ERROR_MSG("Failed to setup up TLS v1.2 on the client server socket");
		
		close(client_socket);
		
		return -1;
	}
	
	/* Set renegotiation behaviour */
	SSL_CTX_set_mode(client_tls_ctx, SSL_MODE_AUTO_RETRY);

	/* Set DH behaviour */
	dh_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	
	if (dh_key == NULL)
	{
		ERROR_MSG("Failed to generate a new ECC key for ephemeral DH");

		SSL_CTX_free(client_tls_ctx);
		client_tls_ctx = NULL;
		close(client_socket);

		return -1;
	}

	if (SSL_CTX_set_tmp_ecdh(client_tls_ctx, dh_key) != 1)
	{
		ERROR_MSG("Failed to set DH parameters on TLS context");

		SSL_CTX_free(client_tls_ctx);
		client_tls_ctx = NULL;
		close(client_socket);

		return -1;
	}

	EC_KEY_free(dh_key);
	
	/* Load the certificate and private key */
	if ((eemo_conf_get_string("clients", "server_cert", &cert_file, NULL) != ERV_OK) || (cert_file == NULL))
	{
		ERROR_MSG("No TLS server certificate configured");
		
		SSL_CTX_free(client_tls_ctx);
		client_tls_ctx = NULL;
		close(client_socket);
		
		return -1;
	}
	
	if ((eemo_conf_get_string("clients", "server_key", &key_file, NULL) != ERV_OK) || (key_file == NULL))
	{
		ERROR_MSG("No TLS key configured");
		
		SSL_CTX_free(client_tls_ctx);
		client_tls_ctx = NULL;
		free(cert_file);
		close(client_socket);
		
		return -1;
	}
	
	if ((SSL_CTX_use_certificate_file(client_tls_ctx, cert_file, SSL_FILETYPE_PEM) != 1) &&
	    (SSL_CTX_use_certificate_file(client_tls_ctx, cert_file, SSL_FILETYPE_ASN1) != 1))
	{
		ERROR_MSG("Failed to load TLS certificate from %s", cert_file);
		
		SSL_CTX_free(client_tls_ctx);
		client_tls_ctx = NULL;
		free(cert_file);
		free(key_file);
		close(client_socket);
		
		return -1;
	}
	
	INFO_MSG("Loaded TLS certificate");
	
	if ((SSL_CTX_use_PrivateKey_file(client_tls_ctx, key_file, SSL_FILETYPE_PEM) != 1) &&
	    (SSL_CTX_use_PrivateKey_file(client_tls_ctx, key_file, SSL_FILETYPE_ASN1) != 1))
	{
		ERROR_MSG("Failed to load TLS key from %s", key_file);
		
		SSL_CTX_free(client_tls_ctx);
		client_tls_ctx = NULL;
		free(cert_file);
		free(key_file);
		close(client_socket);
		
		return -1;
	}
	
	INFO_MSG("Loaded TLS key");
	
	free(cert_file);
	free(key_file);
	
	/* Set TLS options */
	if (SSL_CTX_set_cipher_list(client_tls_ctx, EEMO_MUX_CIPHERSUITES) != 1)
	{
		ERROR_MSG("Failed to select safe TLS ciphers, giving up");
		
		SSL_CTX_free(client_tls_ctx);
		client_tls_ctx = NULL;
		close(client_socket);
		
		return -1;
	}
	
	/* Configure valid certificates */
	if (eemo_conf_get_string("clients", "cert_dir", &cert_dir, NULL) == ERV_OK)
	{
		INFO_MSG("Checking for valid client certificates in %s", cert_dir);
		
		SSL_CTX_load_verify_locations(client_tls_ctx, NULL, cert_dir);
		
		free(cert_dir);
	}
	else
	{
		ERROR_MSG("Failed to obtain configuration option clients/client_cert_dir");
		
		SSL_CTX_free(client_tls_ctx);
		client_tls_ctx = NULL;
		close(client_socket);
		
		return -1;
	}
	
	SSL_CTX_set_verify(client_tls_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
	
	/* Start listening */
	if (listen(client_socket, 10) < 0)
	{
		ERROR_MSG("Failed to listen to client server port %d", server_port);
		
		SSL_CTX_free(client_tls_ctx);
		client_tls_ctx = NULL;
		close(client_socket);
		
		return -1;
	}
	
	INFO_MSG("Listening for incoming clients");
	
	return client_socket;
}

/* Tear down client server socket */
static void eemo_mux_teardown_client_socket(const int client_socket)
{	
	if (client_tls_ctx != NULL)
	{
		SSL_CTX_free(client_tls_ctx);
		client_tls_ctx = NULL;
	}
	
	/* Close the socket */
	close(client_socket);
	
	INFO_MSG("Closed client socket %d", client_socket);
}

/* Disconnect all sensors */
static void eemo_mux_disconnect_sensors(void)
{
	sensor_spec*	sensor_it	= NULL;
	sensor_spec*	tmp_it	= NULL;
	int ctr = 0;
	
	LL_FOREACH_SAFE(sensors, sensor_it, tmp_it)
	{
		eemo_mux_shutdown_sensor(sensor_it, 0);

		ctr++;
		
		LL_DELETE(sensors, sensor_it);
		
		free(sensor_it->feed_guid);
		free(sensor_it->feed_desc);
		free(sensor_it);
	}
	
	INFO_MSG("Disconnected %d sensor%s", ctr, (ctr == 1) ? "" : "s");
}

/* Disconnect all clients */
static void eemo_mux_disconnect_clients(void)
{
	client_spec*	client_it	= NULL;
	client_spec*	tmp_it		= NULL;
	client_subs*	subs_it		= NULL;
	client_subs*	subs_tmp	= NULL;
	int ctr = 0;
	
	LL_FOREACH_SAFE(clients, client_it, tmp_it)
	{
		eemo_mux_shutdown_client(client_it, 0);

		ctr++;
		
		LL_DELETE(clients, client_it);

		LL_FOREACH_SAFE(client_it->subscriptions, subs_it, subs_tmp)
		{
			free(subs_it->guid);
			free(subs_it);
		}
		
		free(client_it);
	}
	
	INFO_MSG("Disconnected %d client%s", ctr, (ctr == 1) ? "" : "s");
}

/* Build the file descriptor set for select(...) */
static void eemo_mux_build_fd_set(fd_set* select_socks, const int sensor_server_socket, const int client_server_socket, int* max_fd)
{
	assert(max_fd != NULL);
	assert(select_socks != NULL);

	sensor_spec*	sensor_it 	= NULL;
	client_spec* 	client_it 	= NULL;
	int		local_max_fd	= -1;
	
	FD_ZERO(select_socks);

	/* Add sensor and client server sockets */
	FD_SET(sensor_server_socket, select_socks);
	local_max_fd = (sensor_server_socket > local_max_fd) ? sensor_server_socket : local_max_fd;

	FD_SET(client_server_socket, select_socks);
	local_max_fd = (client_server_socket > local_max_fd) ? client_server_socket : local_max_fd;
	
	/* Add sensor data sockets */
	LL_FOREACH(sensors, sensor_it)
	{
		FD_SET(sensor_it->socket, select_socks);
		local_max_fd = (sensor_it->socket > local_max_fd) ? sensor_it->socket : local_max_fd;
	}
	
	/* Add client data sockets */
	LL_FOREACH(clients, client_it)
	{
		FD_SET(client_it->socket, select_socks);
		local_max_fd = (client_it->socket > local_max_fd) ? client_it->socket : local_max_fd;
	}

	*max_fd = local_max_fd + 1;
}

/* Main communications loop */
void eemo_mux_comm_loop(void)
{
	int 		sensor_server_socket	= 0;
	int 		client_server_socket	= 0;
	sensor_spec*	sensor_it		= NULL;
	sensor_spec*	sensor_tmp		= NULL;
	client_spec*	client_it		= NULL;
	client_spec*	client_tmp		= NULL;
	fd_set		select_socks;
	int		max_fd			= 0;
	
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
		
		eemo_mux_build_fd_set(&select_socks, sensor_server_socket, client_server_socket, &max_fd);	
		
		int rv = select(max_fd, &select_socks, NULL, NULL, &timeout);
		
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
		
			/* The set of file descriptors has been altered! */
			continue;
		}
		
		if (rv && FD_ISSET(client_server_socket, &select_socks))
		{
			/* New client */
			eemo_mux_new_client(client_server_socket);
			
			/* The set of file descriptors has been altered! */
			continue;
		}
		
		if (rv) LL_FOREACH_SAFE(sensors, sensor_it, sensor_tmp)
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
		
		if (rv)	LL_FOREACH_SAFE(clients, client_it, client_tmp)
		{
			if (FD_ISSET(client_it->socket, &select_socks))
			{
				/* This can only be a client that disconnects */
				if (eemo_mux_handle_client_packet(client_it->socket) != ERV_OK)
				{
					eemo_mux_unregister_client(client_it->socket, 0);
				}

				rv--;
			
				if (!rv) break;
			}
		}
	}
	
	/* Unregister signal handlers */
	signal(SIGINT, SIG_DFL);
	signal(SIGHUP, SIG_DFL);
	signal(SIGTERM, SIG_DFL);
	
	eemo_mux_disconnect_sensors();
	eemo_mux_disconnect_clients();
	
	eemo_mux_teardown_sensor_socket(sensor_server_socket);
	eemo_mux_teardown_client_socket(client_server_socket);
}

/* Run the multiplexer */
void eemo_mux_run_multiplexer(void)
{
	INFO_MSG("Starting multiplexer service");
	
	clients = NULL;
	sensors = NULL;

	if (eemo_conf_get_int("clients", "max_queue_len", &max_queue_len, 100000) != ERV_OK)
	{
		ERROR_MSG("Failed to retrieve the maximum client packet queue length from the configuration");

		return;
	}

	INFO_MSG("Multiplexer maximum client queue length set to %d", max_queue_len);

	if ((eemo_conf_get_int("clients", "flush_threshold", &q_flush_th, 1000) != ERV_OK) || (q_flush_th <= 0))
	{
		ERROR_MSG("Invalid queue flush threshold (%d)", q_flush_th);

		return;
	}

	INFO_MSG("Multiplexer queue flush threshold set to %d packets", q_flush_th);
	
	eemo_mux_comm_loop();

	INFO_MSG("Exiting multiplexer service");
}

