/*
 * Copyright (c) 2010-2015 SURFnet bv
 * Copyright (c) 2021 Roland van Rijswijk-Deij
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
#include "eemo_tlscomm.h"
#include "eemo_mux_cmdxfer.h"
#include "eemo_mux_proto.h"
#include "eemo_mux_queue.h"
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <signal.h>
#include <stdlib.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <pcap.h>

/* Server configuration */
static char*	mux_hostname	= NULL;	
static int	mux_port	= -1;

/* Connection to the multiplexer */
static SSL_CTX*		tls_ctx				= NULL;
static SSL*		tls				= NULL;
static int		mux_socket			= -1;
static char		mux_ip_str[INET6_ADDRSTRLEN]	= { 0 };
static int 		max_qlen			= 100000;
static int		q_flush_threshold		= 1000;
static mux_queue*	mux_q				= NULL;

/* Sensor state */
static int	sensor_exit	= 0;

/* Sensor ID and description */
static char*	sensor_guid	= NULL;
static char*	sensor_desc	= NULL;
static char*	sensor_filter	= NULL;
static char*	sensor_iface	= NULL;

/* Capture */
static pcap_t*	pcap_handle	= NULL;
static int	cap_buf_size	= 32;		/* default to 32MB */

/* Initialise the sensor */
eemo_rv eemo_sensor_init(void)
{
	/* Retrieve mux information from the configuration */
	if ((eemo_conf_get_string("sensor", "mux_host", &mux_hostname, NULL) != ERV_OK) || (mux_hostname == NULL))
	{
		ERROR_MSG("No multiplexer host configured, giving up");
		
		return ERV_CONFIG_ERROR;
	}
	
	if ((eemo_conf_get_int("sensor", "mux_port", &mux_port, 6969) != ERV_OK) || (mux_port < 1))
	{
		ERROR_MSG("Incorrect multiplexer port (%d) configured, giving up", mux_port);
		
		free(mux_hostname);
		
		return ERV_CONFIG_ERROR;
	}

	if ((eemo_conf_get_int("sensor", "bufsize", &cap_buf_size, 32) != ERV_OK) || (cap_buf_size <= 0))
	{
		ERROR_MSG("Invalid sensor capture buffer size (%d) configured, giving up", cap_buf_size);

		free(mux_hostname);

		return ERV_CONFIG_ERROR;
	}

	INFO_MSG("Sensor capture buffer size set to %dMB", cap_buf_size);

	if ((eemo_conf_get_int("sensor", "max_queue_len", &max_qlen, 100000) != ERV_OK) || (max_qlen <= 0))
	{
		ERROR_MSG("Invalid maximum transmission queue length (%d) configured, giving up", max_qlen);

		free(mux_hostname);

		return ERV_CONFIG_ERROR;
	}

	INFO_MSG("Sensor maximum outgoing queue length set to %d", max_qlen);

	if ((eemo_conf_get_int("sensor", "flush_threshold", &q_flush_threshold, 1000) != ERV_OK) || (q_flush_threshold <= 0))
	{
		ERROR_MSG("Invalid queue flush threshold (%d)", q_flush_threshold);

		free(mux_hostname);

		return ERV_CONFIG_ERROR;
	}
	else
	{
		INFO_MSG("Queue flush threshold set to %d", q_flush_threshold);
	}

	if ((eemo_conf_get_string("sensor", "sensor_guid", &sensor_guid, NULL) != ERV_OK) || (sensor_guid == NULL))
	{
		ERROR_MSG("Failed to retrieve the sensor GUID from the configuration");

		free(mux_hostname);
		
		return ERV_CONFIG_ERROR;
	}

	INFO_MSG("Sensor GUID set to %s", sensor_guid);

	if (eemo_conf_get_string("sensor", "sensor_description", &sensor_desc, "no description provided") != ERV_OK)
	{
		ERROR_MSG("Failed to retrieve the sensor description from the configuration");

		free(sensor_guid);
		free(mux_hostname);

		return ERV_CONFIG_ERROR;
	}

	INFO_MSG("Sensor description set to '%s'", sensor_desc);

	if (eemo_conf_get_string("sensor", "sensor_filter", &sensor_filter, NULL) != ERV_OK)
	{
		ERROR_MSG("Failed to retrieve the sensor BNF filter from the configuration");

		free(sensor_guid);
		free(sensor_desc);
		free(mux_hostname);

		return ERV_CONFIG_ERROR;
	}

	if (eemo_conf_get_string("sensor", "sensor_interface", &sensor_iface, NULL) != ERV_OK)
	{
		ERROR_MSG("Failed to retrieve the sensor interface from the configuration");

		free(sensor_guid);
		free(sensor_desc);
		free(sensor_filter);
		free(mux_hostname);

		return ERV_CONFIG_ERROR;
	}

	return ERV_OK;
}

/* Uninitialise the sensor */
eemo_rv eemo_sensor_finalize(void)
{
	free(sensor_guid);
	free(sensor_desc);
	free(sensor_filter);
	free(mux_hostname);

	ERR_free_strings();

	return ERV_OK;
}

/* Signal handler for exit signals */
void stop_signal_handler(int signum)
{
	INFO_MSG("Received signal to exit");

	sensor_exit = 1;

	if (pcap_handle != NULL)
	{
		pcap_breakloop(pcap_handle);
	}
}

int eemo_sensor_connect_mux(void)
{
	struct addrinfo* 	mux_addrs	= NULL;
	struct addrinfo*	addr_it		= NULL;
	struct addrinfo 	hints;
	char 			port_str[16]	= { 0 };
	
	/* Resolve the address of the multiplexer */
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = 0;
	hints.ai_protocol = 0;

	snprintf(port_str, 16, "%d", mux_port);

	if (getaddrinfo(mux_hostname, port_str, &hints, &mux_addrs) != 0)
	{
		ERROR_MSG("Unable to resolve host %s", mux_hostname);
		
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
				
				return -2;
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
				
				mux_socket = -1;
				
				addr_it = addr_it->ai_next;
				
				continue;
			}

			INFO_MSG("Established a connection to %s:%d", mux_hostname, mux_port);

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
		char* 		cert_file	= NULL;
		char* 		key_file	= NULL;
		char*		cert_dir	= NULL;
		int		err		= -1;
		eemo_mux_cmd	cmd		= { 0, 0, NULL };
		eemo_rv		rv		= ERV_OK;
		
		/* Set up new TLS context */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
		tls_ctx = SSL_CTX_new(TLSv1_2_client_method());
#else
		tls_ctx = SSL_CTX_new(TLS_client_method());
#endif
	
		if (tls_ctx == NULL)
		{
			ERROR_MSG("Failed to setup up TLS v1.2 on the client socket");
			
			close(mux_socket);
			
			return -1;
		}

		/* Set renegotiation behaviour */
		SSL_CTX_set_mode(tls_ctx, SSL_MODE_AUTO_RETRY);
		
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
		if (SSL_CTX_set_cipher_list(tls_ctx, EEMO_MUX_CIPHERSUITES) != 1)
		{
			ERROR_MSG("Failed to select safe TLS ciphers, giving up");
			
			SSL_CTX_free(tls_ctx);
			close(mux_socket);
			
			mux_socket = -1;
			
			return -1;
		}

		/* Configure valid certificates */
		if (eemo_conf_get_string("sensor", "mux_cert_dir", &cert_dir, NULL) == ERV_OK)
		{
			INFO_MSG("Checking for valid mux server certificates in %s", cert_dir);
			
			SSL_CTX_load_verify_locations(tls_ctx, NULL, cert_dir);
			
			free(cert_dir);
		}
		else
		{
			ERROR_MSG("Failed to obtain configuration option sensor/mux_cert_dir");
			
			SSL_CTX_free(tls_ctx);
			tls_ctx = NULL;
			close(mux_socket);
			
			return -1;
		}

		SSL_CTX_set_verify(tls_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
		
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
		
			goto errorcond;
		}
		
		INFO_MSG("Successfully connected to the multiplexer");

		/* Do protocol negotiation */
		if ((rv = eemo_cx_send(tls, SENSOR_GET_PROTO_VERSION, 0, NULL)) != ERV_OK)
		{
			ERROR_MSG("Failed to request protocol version information with the server, giving up");

			goto errorcond;
		}

		/* Wait for return information */
		if ((rv = eemo_cx_recv(tls, &cmd)) != ERV_OK)
		{
			ERROR_MSG("Failed to receive protocol version information from the server, giving up");

			goto errorcond;
		}

		/* Check protocol version */
		if ((cmd.cmd_id != SENSOR_GET_PROTO_VERSION) || (cmd.cmd_len != sizeof(uint16_t)))
		{
			ERROR_MSG("Server returned invalid response to request for protocol version information, giving up");

			goto errorcond;
		}

		if (ntohs(*((uint16_t*) cmd.cmd_data)) != SENSOR_PROTO_VERSION)
		{
			ERROR_MSG("Server returned a different protocol version (server = %u, client = %d)", ntohs(*((uint16_t*) cmd.cmd_data)), SENSOR_PROTO_VERSION);

			eemo_cx_cmd_free(&cmd);

			goto errorcond;
		}

		eemo_cx_cmd_free(&cmd);

		/* Register the sensor GUID */
		if ((rv = eemo_cx_send(tls, SENSOR_REGISTER, strlen(sensor_guid) + 1, (uint8_t*) sensor_guid)) != ERV_OK)
		{
			ERROR_MSG("Failed to register the sensor GUID with the server, giving up");

			goto errorcond;
		}

		/* Wait for acknowledgement */
		if ((rv = eemo_cx_recv(tls, &cmd)) != ERV_OK)
		{
			ERROR_MSG("Failed to receive registration acknowledgement from the server, giving up");

			goto errorcond;
		}

		if ((cmd.cmd_id != SENSOR_REGISTER) || (cmd.cmd_len != 0))
		{
			ERROR_MSG("Server returned an invalid registration acknowledgement, giving up");

			eemo_cx_cmd_free(&cmd);

			goto errorcond;
		}

		eemo_cx_cmd_free(&cmd);

		/* Send the sensor description */
		if ((rv = eemo_cx_send(tls, SENSOR_SET_DESCRIPTION, strlen(sensor_desc) + 1, (uint8_t*) sensor_desc)) != ERV_OK)
		{
			ERROR_MSG("Failed to send the sensor description to the server, giving up");

			goto errorcond;
		}

		/* Wait for acknowledgement */
		if ((rv = eemo_cx_recv(tls, &cmd)) != ERV_OK)
		{
			ERROR_MSG("Failed to receive acknowledgement from the server, giving up");

			goto errorcond;
		}

		if ((cmd.cmd_id != SENSOR_SET_DESCRIPTION) || (cmd.cmd_len != 0))
		{
			ERROR_MSG("Server returned an invalid acknowledgement to setting the sensor description");

			eemo_cx_cmd_free(&cmd);

			goto errorcond;
		}

		eemo_cx_cmd_free(&cmd);

		mux_q = eemo_q_new(tls, max_qlen, q_flush_threshold, 0);

		assert(mux_q != NULL);
		
		return 0;

		/* Nasty but makes the code more readable */
errorcond:
			SSL_shutdown(tls);
			SSL_free(tls);
			SSL_CTX_free(tls_ctx);
			tls = NULL;
			tls_ctx = NULL;
			
			close(mux_socket);
			
			mux_socket = -1;

			return -1;
	}
	else
	{	
		ERROR_MSG("Failed to connect to the multiplexer on any address");
		
		return -1;
	}
}

void eemo_sensor_disconnect_mux(void)
{
	eemo_mux_cmd	cmd	= { 0, 0, NULL };

	if (mux_q != NULL)
	{
		eemo_q_stop(mux_q);
		mux_q = NULL;
	}

	if ((tls == NULL) || (tls_ctx == NULL) || (mux_socket < 0))
	{
		goto shutdown;
	}

	/* Unregister our sensor */
	if (eemo_cx_send(tls, SENSOR_UNREGISTER, 0, NULL) != ERV_OK)
	{
		ERROR_MSG("Failed to unregister sensor at the server, proceeding immediately to TLS shutdown");

		goto shutdown;
	}

	if ((eemo_cx_recv(tls, &cmd) != ERV_OK) || (cmd.cmd_id != SENSOR_UNREGISTER) || (cmd.cmd_len != 0))
	{
		ERROR_MSG("Server failed to acknowledge sensor unregistration, proceeding immediately to TLS shutdown");

		eemo_cx_cmd_free(&cmd);

		goto shutdown;
	}

	eemo_cx_cmd_free(&cmd);

	/* Signal to the server that we are shutting down */
	if (eemo_cx_send(tls, SENSOR_SHUTDOWN, 0, NULL) != ERV_OK)
	{
		ERROR_MSG("Failed to signal shutdown to the server, proceeding with TLS shutdown");

		goto shutdown;
	}

	if ((eemo_cx_recv(tls, &cmd) != ERV_OK) || (cmd.cmd_id != SENSOR_SHUTDOWN) || (cmd.cmd_len != 0))
	{
		ERROR_MSG("Server failed to acknowledge sensor shutdown correctly");
	}

	eemo_cx_cmd_free(&cmd);

	/* Again, nasty but makes the code more readable */
shutdown:
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

/* PCAP callback handler */
void eemo_sensor_pcap_cb(u_char* user_ptr, const struct pcap_pkthdr* hdr, const u_char* data)
{
	eemo_rv		rv	= ERV_OK;
	eemo_mux_pkt*	pkt	= NULL;

	if (sensor_exit)
	{
		pcap_breakloop(pcap_handle);
	}

	if (mux_q == NULL)
	{
		ERROR_MSG("No active multiplexer queue, should not happen!");

		pcap_breakloop(pcap_handle);

		return;
	}

	if (!mux_q->queue_state)
	{
		WARNING_MSG("Multiplexer queue state changed to invalid, stopping capture");

		pcap_breakloop(pcap_handle);

		return;
	}

	/* Send the captured packet to the multiplexer */
	pkt = eemo_cx_pkt_from_capture(hdr->ts, data, hdr->len);

	if (pkt == NULL)
	{
		ERROR_MSG("Failed to construct packet to send, giving up on capture");

		pcap_breakloop(pcap_handle);

		return;
	}

	if ((rv = eemo_q_enqueue(mux_q, pkt)) != ERV_OK)
	{
		if (rv == ERV_QUEUE_OVERFLOW)
		{
			WARNING_MSG("Send queue to multiplexer overflowing");
		}
		else if (rv == ERV_QUEUE_OK)
		{
			INFO_MSG("Send queue to multiplexer no longer overflowing");
		}
		else
		{
			ERROR_MSG("Error enqueueing packet to send to multiplexer");

			pcap_breakloop(pcap_handle);
		}
	}

	eemo_cx_pkt_free(pkt);
}

/* Start and run capture */
eemo_rv eemo_sensor_capture(void)
{
	char			errbuf[PCAP_ERRBUF_SIZE]	= { 0 };
	pcap_if_t*		alldevs				= NULL;
	struct bpf_program	packet_filter;
	char*			pcap_if				= NULL;
	char			filter_expr[4096]		= { 0 };
	pcap_t*			new_handle			= NULL;

	pcap_handle = NULL;

	if (sensor_iface != NULL)
	{
		pcap_if = sensor_iface;
	}
	else
	{
		if (!pcap_findalldevs(&alldevs, errbuf))
		{
			pcap_if_t* it = alldevs;

			while(it)
			{
				if (FLAG_SET(it->flags, PCAP_IF_UP))
				{
					pcap_if = strdup(it->name);
				}
				else
				{
					INFO_MSG("Skipping %s because it is not up", it->name);
				}

				it = it->next;
			}

			pcap_freealldevs(alldevs);
		}
	}

	if (pcap_if == NULL)
	{
		ERROR_MSG("Unable to find interface for capture, giving up");

		return ERV_ETH_NOT_EXIST;
	}

	INFO_MSG("Opening device %s for packet capture", pcap_if);

	if ((new_handle = pcap_create(pcap_if, errbuf)) == NULL)
	{
		ERROR_MSG("Failed to open capture handle");

		return ERV_ETH_NOT_EXIST;
	}

	if (pcap_set_snaplen(new_handle, 65536) != 0)
	{
		ERROR_MSG("Failed to set snap length for capture, giving up");

		pcap_close(new_handle);

		return ERV_GENERAL_ERROR;
	}

	if (pcap_set_promisc(new_handle, 1) != 0)
	{
		ERROR_MSG("Failed to set promiscuous mode on network device, giving up");

		pcap_close(new_handle);

		return ERV_GENERAL_ERROR;
	}

	if (pcap_set_timeout(new_handle, 1000) != 0)
	{
		ERROR_MSG("Failed to set timeout on capture, giving up");

		pcap_close(new_handle);

		return ERV_GENERAL_ERROR;
	}

	/* Set capture buffer size */
	if (pcap_set_buffer_size(new_handle, cap_buf_size*1024*1024) != 0)
	{
		WARNING_MSG("Failed to change capture buffer size");
	}
	else
	{
		INFO_MSG("Set capture buffer size to %d bytes", cap_buf_size*1024*1024);
	}

	/* Activate capture */
	if (pcap_activate(new_handle) != 0)
	{
		ERROR_MSG("Failed to activate packet capture, giving up");

		pcap_close(new_handle);

		return ERV_GENERAL_ERROR;
	}
	else
	{
		INFO_MSG("Activated capture");
	}

	if (sensor_filter == NULL)
	{
		snprintf(filter_expr, 4096, "not (host %s and port %d)", mux_ip_str, mux_port);
	}
	else
	{
		snprintf(filter_expr, 4096, "(%s) and (not (host %s and port %d))", sensor_filter, mux_ip_str, mux_port);
	}

	INFO_MSG("Capture filter expression \"%s\"", filter_expr);

	if (pcap_compile(new_handle, &packet_filter, filter_expr, 0, 0) == -1)
	{
		ERROR_MSG("Failed to compile the capture filter expression, giving up");

		pcap_close(new_handle);

		return ERV_INVALID_FILTER;
	}

	if (pcap_setfilter(new_handle, &packet_filter) == -1)
	{
		ERROR_MSG("Failed to activate capture filter, giving up");

		pcap_freecode(&packet_filter);
		pcap_close(new_handle);

		return ERV_INVALID_FILTER;
	}

	pcap_freecode(&packet_filter);

	INFO_MSG("Starting packet capture");

	pcap_handle = new_handle;

	if (pcap_loop(pcap_handle, -1, &eemo_sensor_pcap_cb, NULL) == -1)
	{
		ERROR_MSG("pcap_loop(...) returned an error (%s)", pcap_geterr(pcap_handle));

		pcap_handle = NULL;

		pcap_close(new_handle);

		return ERV_CAPTURE_ERROR;
	}

	INFO_MSG("Packet capture ended");

	pcap_close(new_handle);

	return ERV_OK;
}

/* Run the sensor */
#define MAX_RECONNECT_INTERVAL			512

void eemo_sensor_run(void)
{
	unsigned int	reconnect_interval	= 1;

	/* Register signal handler */
	signal(SIGINT, stop_signal_handler);
	signal(SIGHUP, stop_signal_handler);
	signal(SIGTERM, stop_signal_handler);

	while (!sensor_exit)
	{
		int	rv	= 0;

		/* Attempt to establish an initial connection to the multiplexer */
		if ((rv = eemo_sensor_connect_mux()) == -2)
		{
			ERROR_MSG("Fatal error, giving up");

			break;
		}

		if (rv != 0)
		{
			ERROR_MSG("Failed to establish a connection to the multiplexer, trying again in %ds", reconnect_interval);

			sleep(reconnect_interval);

			if (reconnect_interval <= MAX_RECONNECT_INTERVAL)
			{
				/* Perform exponential backoff */
				reconnect_interval *= 2;
			}

			continue;
		}

		/* Reset exponential backoff */
		reconnect_interval = 1;

		if (eemo_sensor_capture() != ERV_OK)
		{
			ERROR_MSG("Capture ended with an error status, giving up");

			sensor_exit = 1;
		}

		/* Disconnect from the multiplexer */
		eemo_sensor_disconnect_mux();
	}
	
	/* Unregister signal handler */
	signal(SIGINT, SIG_DFL);
	signal(SIGHUP, SIG_DFL);
	signal(SIGTERM, SIG_DFL);
}
