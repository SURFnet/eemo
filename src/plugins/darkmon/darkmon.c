/*
 * Copyright (c) 2010-2016 SURFnet bv
 * Copyright (c) 2016 Roland van Rijswijk-Deij
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
 * Darknet traffic monitoring plugin
 */

#include "config.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include "eemo.h"
#include "eemo_api.h"
#include "eemo_plugin_log.h"
#include "udp_handler.h"
#include "tcp_handler.h"
#include "hyperloglogpp.h"
#include "uthash.h"

const static char* plugin_description = "EEMO darknet monitoring plugin " PACKAGE_VERSION;

/* TCP and UDP handler handles */
static unsigned long 		udp_handler_handle 	= 0;
static unsigned long 		tcp_handler_handle 	= 0;

/* Configuration */
static char*			output_dir		= NULL;
static int			monitoring_interval	= 300;

/* Types */
typedef struct 
{
	int			port;
	unsigned long long	seen_count;
	hll_stor		ips_prob_count;
	UT_hash_handle		hh;
}
port_ht_entry;

/* State */
static int			last_write		= 0;

static port_ht_entry*		tcp_ht			= NULL;
static port_ht_entry*		udp_ht			= NULL;

static eemo_export_fn_table_ptr	eemo_fn_exp		= NULL;

/* Writer thread types */
typedef struct
{
	port_ht_entry*	write_udp_ht;
	port_ht_entry*	write_tcp_ht;
	int		dump_time;
}
writer_thread_params;

/*
 * Output file format:
 *
 * {
	 "timestamp":<epoch timestamp>,
	 "udp": [ {"port": <port>, "seen_count": <seen_count>, "ips_prob_count": <ips_prob_count>}, ... ],
	 "tcp": [ {"port": <port>, "seen_count": <seen_count>, "ips_prob_count": <ips_prob_count>}, ... ]
 * }
 *
 */

/* Writer thread */
static void* eemo_darkmon_writer_thread(void* params)
{
	assert(params != NULL);

	writer_thread_params*	writer_params	= (writer_thread_params*) params;
	char			out_name[1024]	= { 0 };
	int			out_hour	= (writer_params->dump_time / 3600) * 3600;
	FILE*			out_file	= NULL;
	port_ht_entry*		ht_it		= NULL;
	port_ht_entry*		ht_tmp		= NULL;

	snprintf(out_name, 1024, "%s/darknet_%d.csv", output_dir, out_hour);

	out_file = fopen(out_name, "a");

	if (out_file != NULL)
	{
		int	is_first	= 1;

		fprintf(out_file, "{");

		fprintf(out_file, "\"timestamp\": %d,", writer_params->dump_time);

		fprintf(out_file, "\"udp\": [");

		HASH_ITER(hh, writer_params->write_udp_ht, ht_it, ht_tmp)
		{
			if (!is_first)
			{
				fprintf(out_file, ",");
			}
			else
			{
				is_first = 0;
			}

			fprintf(out_file, "{ \"port\": %d, \"seen_count\": %llu, \"ips_prob_count\": %llu }", ht_it->port, ht_it->seen_count, (unsigned long long) eemo_fn_exp->hll_count(ht_it->ips_prob_count));

			HASH_DEL(writer_params->write_udp_ht, ht_it);
			free(ht_it);
		}

		fprintf(out_file, " ],");

		is_first = 1;

		fprintf(out_file, "\"tcp\": [");

		HASH_ITER(hh, writer_params->write_tcp_ht, ht_it, ht_tmp)
		{
			if (!is_first)
			{
				fprintf(out_file, ",");
			}
			else
			{
				is_first = 0;
			}

			fprintf(out_file, "{ \"port\": %d, \"seen_count\": %llu, \"ips_prob_count\": %llu }", ht_it->port, ht_it->seen_count, (unsigned long long) eemo_fn_exp->hll_count(ht_it->ips_prob_count));

			HASH_DEL(writer_params->write_tcp_ht, ht_it);
			free(ht_it);
		}

		fprintf(out_file, " ]");

		fprintf(out_file, "}\n");

		fclose(out_file);
	}
	else
	{
		HASH_ITER(hh, writer_params->write_udp_ht, ht_it, ht_tmp)
		{
			HASH_DEL(writer_params->write_udp_ht, ht_it);
			free(ht_it);
		}

		HASH_ITER(hh, writer_params->write_tcp_ht, ht_it, ht_tmp)
		{
			HASH_DEL(writer_params->write_tcp_ht, ht_it);
			free(ht_it);
		}

		ERROR_MSG("Failed to append %s", out_name);
	}

	free(writer_params);

	return NULL;
}

/* Check if we need to write statistics */
static void write_if_needed(int timestamp)
{
	if ((timestamp > last_write) && (timestamp % monitoring_interval == 0))
	{
		writer_thread_params*	writer_params = (writer_thread_params*) malloc(sizeof(writer_thread_params));
		pthread_t		writer_thread;

		last_write = timestamp;

		writer_params->dump_time	= timestamp;
		writer_params->write_udp_ht	= udp_ht;
		writer_params->write_tcp_ht	= tcp_ht;

		udp_ht = NULL;
		tcp_ht = NULL;

		if (pthread_create(&writer_thread, NULL, eemo_darkmon_writer_thread, writer_params) != 0)
		{
			ERROR_MSG("Failed to create new writer thread");
		}
		else
		{
			pthread_detach(writer_thread);
		}
	}
}

/* UDP handler */
eemo_rv eemo_darkmon_udp_handler(const eemo_packet_buf* pkt, eemo_ip_packet_info ip_info, u_short srcport, u_short dstport, u_short length)
{
	port_ht_entry*	udp_ht_ent	= NULL;
	int		port		= dstport;

	HASH_FIND_INT(udp_ht, &port, udp_ht_ent);

	if (udp_ht_ent == NULL)
	{
		udp_ht_ent = (port_ht_entry*) malloc(sizeof(port_ht_entry));

		memset(udp_ht_ent, 0, sizeof(port_ht_entry));

		udp_ht_ent->port = (int) dstport;

		eemo_fn_exp->hll_init(udp_ht_ent->ips_prob_count);

		HASH_ADD_INT(udp_ht, port, udp_ht_ent);
	}

	udp_ht_ent->seen_count++;

	eemo_fn_exp->hll_add(udp_ht_ent->ips_prob_count, &ip_info.dst_addr.v4, sizeof(uint32_t));

	write_if_needed(ip_info.ts.tv_sec);

	return ERV_HANDLED;
}

/* TCP handler */
eemo_rv eemo_darkmon_tcp_handler(const eemo_packet_buf* pkt, eemo_ip_packet_info ip_info, eemo_tcp_packet_info tcp_info)
{
	port_ht_entry*	tcp_ht_ent	= NULL;
	int		port		= tcp_info.dstport;

	HASH_FIND_INT(tcp_ht, &port, tcp_ht_ent);

	if (tcp_ht_ent == NULL)
	{
		tcp_ht_ent = (port_ht_entry*) malloc(sizeof(port_ht_entry));

		memset(tcp_ht_ent, 0, sizeof(port_ht_entry));

		tcp_ht_ent->port = (int) tcp_info.dstport;

		eemo_fn_exp->hll_init(tcp_ht_ent->ips_prob_count);

		HASH_ADD_INT(tcp_ht, port, tcp_ht_ent);
	}

	tcp_ht_ent->seen_count++;

	eemo_fn_exp->hll_add(tcp_ht_ent->ips_prob_count, &ip_info.dst_addr.v4, sizeof(uint32_t));

	write_if_needed(ip_info.ts.tv_sec);

	return ERV_HANDLED;
}

/* Plugin initialisation */
eemo_rv eemo_darkmon_init(eemo_export_fn_table_ptr eemo_fn, const char* conf_base_path)
{
	eemo_fn_exp = eemo_fn;

	/* Initialise logging for the plugin */
	eemo_init_plugin_log(eemo_fn->log);

	INFO_MSG("Initialising darkmon plugin");

	/* Get configuration */
	if (((eemo_fn->conf_get_string)(conf_base_path, "output_dir", &output_dir, NULL) != ERV_OK) || (output_dir == NULL))
	{
		ERROR_MSG("No output directory found in the configuration");

		return ERV_CONFIG_ERROR;
	}

	if (((eemo_fn->conf_get_int)(conf_base_path, "monitoring_interval", &monitoring_interval, monitoring_interval) != ERV_OK) || (monitoring_interval <= 0))
	{
		ERROR_MSG("Invalid or no monitoring interval specified");

		return ERV_CONFIG_ERROR;
	}

	INFO_MSG("Writing data to %s", output_dir);
	INFO_MSG("Monitoring interval set to %ds", monitoring_interval);

	/* Register UDP handler */
	if ((eemo_fn->reg_udp_handler)(UDP_ANY_PORT, UDP_ANY_PORT, &eemo_darkmon_udp_handler, &udp_handler_handle) != ERV_OK)
	{
		ERROR_MSG("Failed to register darkmon UDP handler");

		return ERV_GENERAL_ERROR;
	}

	/* Register TCP handler */
	if ((eemo_fn->reg_tcp_handler)(TCP_ANY_PORT, TCP_ANY_PORT, &eemo_darkmon_tcp_handler, &tcp_handler_handle) != ERV_OK)
	{
		ERROR_MSG("Failed to register darkmon TCP handler");

		(eemo_fn->unreg_udp_handler)(udp_handler_handle);

		return ERV_GENERAL_ERROR;
	}

	INFO_MSG("Darknet monitoring plugin initialisation complete");

	return ERV_OK;
}

/* Plugin uninitialisation */
eemo_rv eemo_darkmon_uninit(eemo_export_fn_table_ptr eemo_fn)
{
	INFO_MSG("Uninitialising darkmon plugin");

	/* Unregister UDP handler */
	if ((eemo_fn->unreg_udp_handler)(udp_handler_handle) != ERV_OK)
	{
		ERROR_MSG("Failed to unregister darkmon UDP handler");
	}

	/* Unregister TCP handler */
	if ((eemo_fn->unreg_tcp_handler)(tcp_handler_handle) != ERV_OK)
	{
		ERROR_MSG("Failed to unregister darkmon TCP handler");
	}

	INFO_MSG("Finished uninitialising darkmon plugin");

	return ERV_OK;
}

/* Retrieve plugin description */
const char* eemo_darkmon_getdescription(void)
{
	return plugin_description;
}

/* Retrieve plugin status */
eemo_rv eemo_darkmon_status(void)
{
	return ERV_OK;
}

/* Plugin function table */
static eemo_plugin_fn_table darkmon_fn_table =
{
	EEMO_PLUGIN_FN_VERSION,
	&eemo_darkmon_init,
	&eemo_darkmon_uninit,
	&eemo_darkmon_getdescription,
	&eemo_darkmon_status
};

/* Entry point for retrieving plugin function table */
eemo_rv eemo_plugin_get_fn_table(eemo_plugin_fn_table_ptrptr fn_table)
{
	if (fn_table == NULL)
	{
		return ERV_PARAM_INVALID;
	}

	*fn_table = &darkmon_fn_table;

	return ERV_OK;
}

