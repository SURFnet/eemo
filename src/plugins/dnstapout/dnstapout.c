/*
 * Copyright (c) 2018 SURFnet bv
 * Copyright (c) 2018 Roland van Rijswijk-Deij
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
 *
 * dnstap code is based on the implementation of dnstap in Unbound
 * Copyright (C) 2013-2014 Farsight Security, Inc. under a 3-clause
 * BSD license.
 *
 * For more information, see the latest Unbound source at
 * https://unbound.net/
 *
 */

/*
 * The Extensible Ethernet Monitor (EEMO)
 * dnstap output module to UNIX domain socket
 */

#include "config.h"
#include <stdlib.h>
#include "eemo.h"
#include "eemo_api.h"
#include "eemo_plugin_log.h"
#include "udp_handler.h"
#include "tcp_handler.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <fstrm.h>
#include <protobuf-c/protobuf-c.h>
#include "dnstap.pb-c.h"

const static char* plugin_description = "EEMO dnstap output module " PACKAGE_VERSION;

#define DNSTAP_CONTENT_TYPE		"protobuf:dnstap.Dnstap"

/* TCP and UDP handler handles */
static unsigned long 		udp_handler_handle 	= 0;
static unsigned long 		tcp_handler_handle 	= 0;

/* Destination port and IP traffic to which needs to be retransmitted locally */
static int			cap_dst_port		= 0;
static char**			cap_dst_ips		= NULL;
static int			cap_dst_ips_count	= 0;

/* UNIX domain socket path for dnstap destination */
static char*				dnstap_socket_path	= NULL;
static struct fstrm_iothr*		fstrm_iothread		= NULL;
static struct fstrm_iothr_queue*	fstrm_ioqueue		= NULL;
static char*				fstrm_id		= "eemo dnstapout";
static char*				fstrm_version		= "0.1";
static unsigned 			len_id			= 0;
static unsigned				len_version		= 0;

/* Attempt to connect to the dnstap domain socket */
static eemo_rv eemo_dnstapout_connect(void)
{
	assert(dnstap_socket_path != NULL);

	struct fstrm_iothr_options*		fstrm_options		= NULL;
	struct fstrm_unix_writer_options*	fstrm_uw_options	= NULL;
	struct fstrm_writer*			fstrm_uw		= NULL;
	struct fstrm_writer_options*		fstrm_uw_wr_options	= NULL;
	fstrm_res				res			= fstrm_res_success;

	len_id = strlen(fstrm_id);
	len_version = strlen(fstrm_version);

	/* Construct fstrm options */
	fstrm_uw_wr_options = fstrm_writer_options_init();
	res = fstrm_writer_options_add_content_type(fstrm_uw_wr_options, DNSTAP_CONTENT_TYPE, sizeof(DNSTAP_CONTENT_TYPE) - 1);

	if (res != fstrm_res_success)
	{
		ERROR_MSG("Failed to initialise fstrm options");

		return ERV_GENERAL_ERROR;
	}

	fstrm_uw_options = fstrm_unix_writer_options_init();
	fstrm_unix_writer_options_set_socket_path(fstrm_uw_options, dnstap_socket_path);

	fstrm_uw = fstrm_unix_writer_init(fstrm_uw_options, fstrm_uw_wr_options);

	if (fstrm_uw == NULL)
	{
		ERROR_MSG("Failed to initialise fstrm writer");

		return ERV_GENERAL_ERROR;
	}

	fstrm_options = fstrm_iothr_options_init();
	fstrm_iothr_options_set_num_input_queues(fstrm_options, 1);
	fstrm_iothr_options_set_reopen_interval(fstrm_options, 5);	/* attempt to re-open every 5 seconds */
	fstrm_iothr_options_set_output_queue_size(fstrm_options, 1024);

	fstrm_iothread = fstrm_iothr_init(fstrm_options, &fstrm_uw);

	if (fstrm_iothread == NULL)
	{
		ERROR_MSG("Failed to create fstrm I/O thread");

		return ERV_GENERAL_ERROR;
	}

	fstrm_iothr_options_destroy(&fstrm_options);
	fstrm_unix_writer_options_destroy(&fstrm_uw_options);
	fstrm_writer_options_destroy(&fstrm_uw_wr_options);

	fstrm_ioqueue = fstrm_iothr_get_input_queue(fstrm_iothread);

	if (fstrm_ioqueue == NULL)
	{
		ERROR_MSG("Failed to get fstrm input queue");

		return ERV_GENERAL_ERROR;
	}

	return ERV_OK;
}

/* Cleanup fstrm environment */
static void eemo_dnstapout_cleanup(void)
{
	if (fstrm_iothread != NULL)
	{
		fstrm_iothr_destroy(&fstrm_iothread);

		fstrm_iothread = NULL;
		fstrm_ioqueue = NULL;
	}
}

/* Transmit a DNS message to the dnstap output */
static void eemo_dnstapout_send(const unsigned char* dns_dgram, const size_t dns_dgram_len, eemo_ip_packet_info ip_info, u_short srcport, u_short dstport)
{
	Dnstap__Dnstap		d;
	Dnstap__Message		m;
	size_t			buf_len	= 0;
	ProtobufCBufferSimple	pbuf;
	fstrm_res		res	= fstrm_res_success;

	/* Initialize protocol buffers structure */
	memset(&pbuf, 0, sizeof(pbuf));

	pbuf.base.append = protobuf_c_buffer_simple_append;
	pbuf.len = 0;
	pbuf.alloced = 256;
	pbuf.data = malloc(pbuf.alloced);

	assert(pbuf.data != NULL);

	/* Initialize dnstap message */
	memset(&d, 0, sizeof(d));
	memset(&m, 0, sizeof(m));

	d.base.descriptor = &dnstap__dnstap__descriptor;
	m.base.descriptor = &dnstap__message__descriptor;
	d.type = DNSTAP__DNSTAP__TYPE__MESSAGE;
	d.message = &m;
	m.type = DNSTAP__MESSAGE__TYPE__CLIENT_QUERY;

	d.identity.data = (uint8_t*) fstrm_id;
	d.identity.len = (size_t) len_id;
	d.version.data = (uint8_t*) fstrm_version;
	d.version.len = (size_t) len_version;

	/* Copy query timestamp */
	m.query_time_sec = ip_info.ts.tv_sec;
	m.query_time_nsec = ip_info.ts.tv_usec * 1000;
	m.has_query_time_sec = 1;
	m.has_query_time_nsec = 1;

	/* Point to query message */
	m.query_message.data = (void*) dns_dgram;
	m.query_message.len = dns_dgram_len;

	/* Set address information */
	if (ip_info.ip_type == IP_TYPE_V4)
	{
		m.socket_family = DNSTAP__SOCKET_FAMILY__INET;
		m.has_socket_family = 1;

		m.query_address.data = (void*) &ip_info.src_addr.v4;
		m.query_address.len = 4;
		m.query_port = htons(srcport);
	}
	else if (ip_info.ip_type == IP_TYPE_V6)
	{
		m.socket_family = DNSTAP__SOCKET_FAMILY__INET6;
		m.has_socket_family = 1;

		m.query_address.data = (void*) &ip_info.src_addr.v6[0];
		m.query_address.len = 16;
		m.query_port = htons(srcport);
	}
	else
	{
		/* Yikes */
		assert(ip_info.ip_type == IP_TYPE_V4 || ip_info.ip_type == IP_TYPE_V6);
	}

	m.has_query_address = 1;
	m.has_query_port = 1;

	/* Pack it up... */
	buf_len = dnstap__dnstap__pack_to_buffer(&d, (ProtobufCBuffer *) &pbuf);

	if (pbuf.data == NULL)
	{
		ERROR_MSG("Failed to pack protocol buffer frame");
	}
	else
	{
		/* ...and send it! */
		res = fstrm_iothr_submit(fstrm_iothread, fstrm_ioqueue, pbuf.data, buf_len, fstrm_free_wrapper, NULL);

		if (res != fstrm_res_success)
		{
			ERROR_MSG("Failed to send protocol buffer frame, forcing reconnect");

			eemo_dnstapout_cleanup();
			eemo_dnstapout_connect();
		}
	}
}

/* UDP handler */
eemo_rv eemo_dnstapout_udp_handler(const eemo_packet_buf* pkt, eemo_ip_packet_info ip_info, u_short srcport, u_short dstport, u_short length)
{
	int	i		= 0;
	int	ip_match	= 0;

	if (dstport != 53)
	{
		/* This is a response, skip it */
		return ERV_SKIPPED;
	}

	for (i = 0; i < cap_dst_ips_count; i++)
	{
		if (strcmp(cap_dst_ips[i], ip_info.ip_dst) == 0)
		{
			ip_match = 1;
			break;
		}
	}

	if (!ip_match)
	{
		/* Packet is not for us */
		return ERV_SKIPPED;
	}

	eemo_dnstapout_send(pkt->data, pkt->len, ip_info, srcport, dstport);

	return ERV_HANDLED;
}

/* TCP handler */
eemo_rv eemo_dnstapout_tcp_handler(const eemo_packet_buf* pkt, eemo_ip_packet_info ip_info, eemo_tcp_packet_info tcp_info)
{
	int		i		= 0;
	int		ip_match	= 0;
	u_short		dns_length	= 0;

	if (tcp_info.dstport != 53)
	{
		/* This is a response, skip it */
		return ERV_SKIPPED;
	}

	for (i = 0; i < cap_dst_ips_count; i++)
	{
		if (strcmp(cap_dst_ips[i], ip_info.ip_dst) == 0)
		{
			ip_match = 1;
			break;
		}
	}

	if (!ip_match)
	{
		/* Packet is not for us */
		return ERV_SKIPPED;
	}

	/* Skip SYN, RST and FIN packets */
	if (FLAG_SET(tcp_info.flags, TCP_SYN) ||
	    FLAG_SET(tcp_info.flags, TCP_RST) ||
	    FLAG_SET(tcp_info.flags, TCP_FIN))
	{
		return ERV_SKIPPED;
	}

	/* Check minimal length */
	if (pkt->len < 2)
	{
		/* Malformed packet */
		return ERV_MALFORMED;
	}

	/* Take length field */
	dns_length = ntohs(*((u_short*) pkt->data));

	/* Check length */
	if ((pkt->len - 2) != dns_length)
	{
		/* Packet data is truncated and we currently don't do reassembly */
		return ERV_MALFORMED;
	}

	eemo_dnstapout_send(&pkt->data[2], (pkt->len)-2, ip_info, tcp_info.srcport, tcp_info.dstport);

	return ERV_HANDLED;
}

/* Plugin initialisation */
eemo_rv eemo_dnstapout_init(eemo_export_fn_table_ptr eemo_fn, const char* conf_base_path)
{
	eemo_rv	rv	= ERV_OK;

	/* Initialise logging for the plugin */
	eemo_init_plugin_log(eemo_fn->log);

	INFO_MSG("Initialising dnstapout plugin");

	/* Read configuration */
	if (((eemo_fn->conf_get_string_array)(conf_base_path, "dst_ips", &cap_dst_ips, &cap_dst_ips_count) != ERV_OK) || (cap_dst_ips_count == 0))
	{
		ERROR_MSG("Unable to retrieve the destination IP(s) from the capture stream to retransmit");

		return ERV_CONFIG_ERROR;
	}

	if (((eemo_fn->conf_get_int)(conf_base_path, "dst_port", &cap_dst_port, -1) != ERV_OK) || (cap_dst_port <= 0))
	{
		ERROR_MSG("Unable to retrieve valid destination port from the capture stream to retransmit");

		(eemo_fn->conf_free_string_array)(cap_dst_ips, cap_dst_ips_count);

		return ERV_CONFIG_ERROR;
	}

	if (((eemo_fn->conf_get_string)(conf_base_path, "dnstap_socket_path", &dnstap_socket_path, NULL) != ERV_OK) || (dnstap_socket_path == NULL))
	{
		ERROR_MSG("Unable to retrieve local dnstap UNIX domain socket path from the configuration");

		return ERV_CONFIG_ERROR;
	}

	/* Register UDP handler */
	if ((eemo_fn->reg_udp_handler)(UDP_ANY_PORT, cap_dst_port, &eemo_dnstapout_udp_handler, &udp_handler_handle) != ERV_OK)
	{
		ERROR_MSG("Failed to register dnstapout UDP handler");

		return ERV_GENERAL_ERROR;
	}

	/* Register TCP handler */
	if ((eemo_fn->reg_tcp_handler)(TCP_ANY_PORT, cap_dst_port, &eemo_dnstapout_tcp_handler, &tcp_handler_handle) != ERV_OK)
	{
		ERROR_MSG("Failed to register dnstapout TCP handler");

		return ERV_GENERAL_ERROR;
	}

	if ((rv = eemo_dnstapout_connect()) != ERV_OK)
	{
		return rv;
	}

	INFO_MSG("dnstapout plugin initialisation complete");

	return ERV_OK;
}

/* Plugin uninitialisation */
eemo_rv eemo_dnstapout_uninit(eemo_export_fn_table_ptr eemo_fn)
{
	INFO_MSG("Uninitialising dnstapout plugin");

	/* Clean up fstrm environment */
	eemo_dnstapout_cleanup();

	/* Unregister UDP handler */
	if ((eemo_fn->unreg_udp_handler)(udp_handler_handle) != ERV_OK)
	{
		ERROR_MSG("Failed to unregister dnstapout UDP handler");
	}

	/* Unregister TCP handler */
	if ((eemo_fn->unreg_tcp_handler)(tcp_handler_handle) != ERV_OK)
	{
		ERROR_MSG("Failed to unregister dnstapout TCP handler");
	}

	if (cap_dst_ips != NULL)
	{
		(eemo_fn->conf_free_string_array)(cap_dst_ips, cap_dst_ips_count);
	}

	free(dnstap_socket_path);

	INFO_MSG("Finished uninitialising dnstapout plugin");

	return ERV_OK;
}

/* Retrieve plugin description */
const char* eemo_dnstapout_getdescription(void)
{
	return plugin_description;
}

/* Retrieve plugin status */
eemo_rv eemo_dnstapout_status(void)
{
	return ERV_OK;
}

/* Plugin function table */
static eemo_plugin_fn_table dnstapout_fn_table =
{
	EEMO_PLUGIN_FN_VERSION,
	&eemo_dnstapout_init,
	&eemo_dnstapout_uninit,
	&eemo_dnstapout_getdescription,
	&eemo_dnstapout_status
};

/* Entry point for retrieving plugin function table */
eemo_rv eemo_plugin_get_fn_table(eemo_plugin_fn_table_ptrptr fn_table)
{
	if (fn_table == NULL)
	{
		return ERV_PARAM_INVALID;
	}

	*fn_table = &dnstapout_fn_table;

	return ERV_OK;
}

