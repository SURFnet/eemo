/* $Id$ */

/*
 * Copyright (c) 2010-2011 SURFnet bv
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

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "eemo.h"
#include "eemo_api.h"
#include "eemo_packet.h"
#include "ip_handler.h"
#include "icmp_handler.h"
#include "udp_handler.h"
#include "tcp_handler.h"
#include "dns_handler.h"
#include "dns_types.h"
#include "ifaddr_lookup.h"
#include "ether_capture.h"
#include "eemo_config.h"
#include "eemo_log.h"

void version(void)
{
	printf("Extensible Ethernet Monitor (eemo) version %s\n", VERSION);
	printf("Copyright (c) 2010-2011 SURFnet bv\n\n");
	printf("Use, modification and redistribution of this software is subject to the terms\n");
	printf("of the license agreement. This software is licensed under a 3-clause BSD-style\n");
	printf("license a copy of which is included as the file LICENSE in the distribution.\n");
}

void usage(void)
{
	printf("Extensible Ethernet Monitor (eemo) version %s\n\n", VERSION);
	printf("Usage:\n");
	printf("\teemo [-i <if>] [-f] [-c <config>] [-p <pidfile>]\n");
	printf("\teemo -h\n");
	printf("\teemo -v\n");
	printf("\n");
	printf("\t-i <if>      Capture package on interface <if>; defaults to standard packet\n");
	printf("\t             capturing interface reported by libpcap, see pcap_lookupdev(3)\n");
	printf("\t-f           Run in the foreground rather than forking as a daemon\n");
	printf("\t-c <config>  Use <config> as configuration file\n");
	printf("\t             Defaults to %s\n", DEFAULT_EEMO_CONF);
	printf("\t-p <pidfile> Specify the PID file to write the daemon process ID to\n");
	printf("\t             Defaults to %s\n", DEFAULT_EEMO_PIDFILE);
	printf("\n");
	printf("\t-h           Print this help message\n");
	printf("\n");
	printf("\t-v           Print the version number\n");
}

void write_pid(const char* pid_path, pid_t pid)
{
	FILE* pid_file = fopen(pid_path, "w");

	if (pid_file == NULL)
	{
		ERROR_MSG("Failed to write the pid file %s", pid_path);

		return;
	}

	fprintf(pid_file, "%d\n", pid);
	fclose(pid_file);
}

int main(int argc, char* argv[])
{
	char* interface = NULL;
	char* config_path = NULL;
	char* pid_path = NULL;
	int daemon = 1;
	int c = 0;
	int pid_path_set = 0;
	int daemon_set = 0;
	int interface_set = 0;
	pid_t pid = 0;
	
	while ((c = getopt(argc, argv, "i:fc:p:hv")) != -1)
	{
		switch(c)
		{
		case 'i':
			interface = strdup(optarg);

			if (interface == NULL)
			{
				fprintf(stderr, "Error allocating memory, exiting\n");
				return ERV_MEMORY;
			}

			interface_set = 1;

			break;
		case 'f':
			daemon = 0;
			daemon_set = 1;
			break;
		case 'c':
			config_path = strdup(optarg);

			if (config_path == NULL)
			{
				fprintf(stderr, "Error allocating memory, exiting\n");
				return ERV_MEMORY;
			}

			break;
		case 'p':
			pid_path = strdup(optarg);

			if (pid_path == NULL)
			{
				fprintf(stderr, "Error allocating memory, exiting\n");
				return ERV_MEMORY;
			}
			
			pid_path_set = 1;
			break;
		case 'h':
			usage();
			return 0;
		case 'v':
			version();
			return 0;
		}
	}

	if (config_path == NULL)
	{
		config_path = strdup(DEFAULT_EEMO_CONF);

		if (config_path == NULL)
		{
			fprintf(stderr, "Error allocating memory, exiting\n");
			return ERV_MEMORY;
		}
	}

	if (pid_path == NULL)
	{
		pid_path = strdup(DEFAULT_EEMO_PIDFILE);

		if (pid_path == NULL)
		{
			fprintf(stderr, "Error allocating memory, exiting\n");
			return ERV_MEMORY;
		}
	}

	/* Load the configuration */
	if (eemo_init_config_handling(config_path) != ERV_OK)
	{
		fprintf(stderr, "Failed to load the configuration, exiting\n");

		return ERV_CONFIG_ERROR;
	}

	/* Initialise logging */
	if (eemo_init_log() != ERV_OK)
	{
		fprintf(stderr, "Failed to initialise logging, exiting\n");

		return ERV_LOG_INIT_FAIL;
	}

	/* Determine configuration settings that were not specified on the command line */
	if (!pid_path_set)
	{
		char* conf_pid_path = NULL;

		if (eemo_conf_get_string("daemon", "pidfile", &conf_pid_path, NULL) != ERV_OK)
		{
			ERROR_MSG("Failed to retrieve pidfile information from the configuration");
		}
		else
		{
			if (conf_pid_path != NULL)
			{
				free(pid_path);
				pid_path = conf_pid_path;
			}
		}
	}

	if (!daemon_set)
	{
		if (eemo_conf_get_bool("daemon", "fork", &daemon, 1) != ERV_OK)
		{
			ERROR_MSG("Failed to retrieve daemon information from the configuration");
		}
	}

	if (!interface_set)
	{
		if (eemo_conf_get_string("capture", "interface", &interface, NULL) != ERV_OK)
		{
			ERROR_MSG("Failed to retrieve interface information from the configuration");
		}
	}

	/* Now fork if that was requested */
	if (daemon)
	{
		pid = fork();

		if (pid != 0)
		{
			/* This is the parent process; write the PID file and exit */
			write_pid(pid_path, pid);

			/* Unload the configuration */
			if (eemo_uninit_config_handling() != ERV_OK)
			{
				ERROR_MSG("Failed to uninitialise configuration handling");
			}
		
			/* Uninitialise logging */
			if (eemo_uninit_log() != ERV_OK)
			{
				fprintf(stderr, "Failed to uninitialise logging\n");
			}
		
			free(pid_path);
			free(config_path);
		
			if (interface != NULL)
			{
				free(interface);
			}

			return ERV_OK;
		}
	}

	/* If we forked, this is the child */

	INFO_MSG("Starting the Extensible Ethernet Monitor (eemo) version %s", VERSION);

	if (eemo_init_ether_handler() != ERV_OK)
	{
		ERROR_MSG("Failed to initialise the Ethernet packet handler");

		return ERV_GENERAL_ERROR;
	}

	if (eemo_init_ip_handler() != ERV_OK)
	{
		ERROR_MSG("Failed to initialise the IP packet handler");

		return ERV_GENERAL_ERROR;
	}

	if (eemo_init_icmp_handler() != ERV_OK)
	{
		ERROR_MSG("Failed to initialise the ICMP packet handler");
	}

	if (eemo_init_udp_handler() != ERV_OK)
	{
		ERROR_MSG("Failed to initialise the UDP packet handler");
	}

	if (eemo_init_tcp_handler() != ERV_OK)
	{
		ERROR_MSG("Failed to initialise the TCP packet handler");
	}

	if (eemo_init_dns_qhandler() != ERV_OK)
	{
		ERROR_MSG("Failed to initialise the DNS query handler");
	}

	/* Load an initialise modules */
	if (eemo_conf_load_modules() != ERV_OK)
	{
		ERROR_MSG("Failed to load modules");

		return ERV_NO_MODULES;
	}

	/* Start capturing */
	if (eemo_capture_and_handle(interface, -1, NULL) != ERV_OK)
	{
		ERROR_MSG("Failed to start packet capture");
	}

	INFO_MSG("Stopping the Extensible Ethernet Monitor (eemo) version %s", VERSION);

	/* Unload and uninitialise modules */
	if (eemo_conf_unload_modules() != ERV_OK)
	{
		ERROR_MSG("Failed to unload modules");
	}

	/* Uninitialise all handlers */
	eemo_dns_qhandler_cleanup();
	eemo_tcp_handler_cleanup();
	eemo_udp_handler_cleanup();
	eemo_icmp_handler_cleanup();
	eemo_ip_handler_cleanup();
	eemo_ether_handler_cleanup();

	/* Unload the configuration */
	if (eemo_uninit_config_handling() != ERV_OK)
	{
		ERROR_MSG("Failed to uninitialise configuration handling");
	}

	/* Uninitialise logging */
	if (eemo_uninit_log() != ERV_OK)
	{
		fprintf(stderr, "Failed to uninitialise logging\n");
	}

	free(pid_path);
	free(config_path);

	if (interface != NULL)
	{
		free(interface);
	}

	return 0;
}

