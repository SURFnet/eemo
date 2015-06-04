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

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <openssl/ssl.h>
#include "eemo.h"
#include "eemo_api.h"
#include "eemo_config.h"
#include "eemo_log.h"
#include "eemo_mux_muxer.h"
#include "mt_openssl.h"

void version(void)
{
	printf("Extensible Ethernet Monitor Sensor Multiplexer (eemo_mux) version %s\n", VERSION);
	printf("Copyright (c) 2010-2014 SURFnet bv\n\n");
	printf("Use, modification and redistribution of this software is subject to the terms\n");
	printf("of the license agreement. This software is licensed under a 3-clause BSD-style\n");
	printf("license a copy of which is included as the file LICENSE in the distribution.\n");
}

void usage(void)
{
	printf("Extensible Ethernet Monitor Sensor Multiplexer (eemo_mux) version %s\n\n", VERSION);
	printf("Usage:\n");
	printf("\teemo_mux [-c <config>] [-f] [-p <pidfile>]\n");
	printf("\teemo_mux -h\n");
	printf("\teemo_mux -v\n");
	printf("\n");
	printf("\t-c <config>   Use <config> as configuration file\n");
	printf("\t              Defaults to %s\n", DEFAULT_EEMO_MUX_CONF);
	printf("\t-f            Run in the foreground rather than forking as a daemon\n");
	printf("\t-p <pidfile>  Specify the PID file to write the daemon process ID to\n");
	printf("\t              Defaults to %s\n", DEFAULT_EEMO_MUX_PIDFILE);
	printf("\n");
	printf("\t-h            Print this help message\n");
	printf("\n");
	printf("\t-v            Print the version number\n");
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

/* Signal handler for certain exit codes */
void signal_handler(int signum)
{
	switch(signum)
	{
	case SIGABRT:
		ERROR_MSG("Caught SIGABRT");
		break;
	case SIGBUS:
		ERROR_MSG("Caught SIGBUS");
		break;
	case SIGFPE:
		ERROR_MSG("Caught SIGFPE");
		break;
	case SIGILL:
		ERROR_MSG("Caught SIGILL");
		break;
	case SIGPIPE:
		ERROR_MSG("Caught SIGPIPE");
		break;
	case SIGQUIT:
		ERROR_MSG("Caught SIGQUIT");
		break;
	case SIGSEGV:
		ERROR_MSG("Caught SIGSEGV");
		exit(-1);
		break;
	case SIGSYS:
		ERROR_MSG("Caught SIGSYS");
		break;
	case SIGXCPU:
		ERROR_MSG("Caught SIGXCPU");
		break;
	case SIGXFSZ:
		ERROR_MSG("Caught SIGXFSZ");
		break;
	default:
		ERROR_MSG("Caught unknown signal 0x%X", signum);
		break;
	}
}

int main(int argc, char* argv[])
{
	char* config_path = NULL;
	char* pid_path = NULL;
	int daemon = 1;
	int c = 0;
	int pid_path_set = 0;
	int daemon_set = 0;
	pid_t pid = 0;
	
	while ((c = getopt(argc, argv, "fc:p:hv")) != -1)
	{
		switch(c)
		{
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
		config_path = strdup(DEFAULT_EEMO_MUX_CONF);

		if (config_path == NULL)
		{
			fprintf(stderr, "Error allocating memory, exiting\n");
			return ERV_MEMORY;
		}
	}

	if (pid_path == NULL)
	{
		pid_path = strdup(DEFAULT_EEMO_MUX_PIDFILE);

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
			
			return ERV_OK;
		}
	}

	/* If we forked, this is the child */
	INFO_MSG("Starting the Extensible Ethernet Monitor Sensor Multiplexer (eemo_mux) version %s", VERSION);
	INFO_MSG("eemo_mux %sprocess ID is %d", daemon ? "daemon " : "", getpid());

	/* Install signal handlers */
	signal(SIGABRT, signal_handler);
	signal(SIGBUS, signal_handler);
	signal(SIGFPE, signal_handler);
	signal(SIGILL, signal_handler);
	signal(SIGPIPE, signal_handler);
	signal(SIGQUIT, signal_handler);
	signal(SIGSEGV, signal_handler);
	signal(SIGSYS, signal_handler);
	signal(SIGXCPU, signal_handler);
	signal(SIGXFSZ, signal_handler);
	
	/* Initialise OpenSSL */
	SSL_library_init();
	SSL_load_error_strings();
	
	DEBUG_MSG("Initialised OpenSSL");

	if (eemo_mt_openssl_init() != ERV_OK)
	{
		ERROR_MSG("Failed to initialise multi-threaded use of OpenSSL");

		return ERV_GENERAL_ERROR;
	}

	/* Run the multiplexer until it is stopped */
	eemo_mux_run_multiplexer();

	/* Remove signal handlers */
	signal(SIGABRT, SIG_DFL);
	signal(SIGBUS, SIG_DFL);
	signal(SIGFPE, SIG_DFL);
	signal(SIGILL, SIG_DFL);
	signal(SIGPIPE, SIG_DFL);
	signal(SIGQUIT, SIG_DFL);
	signal(SIGSEGV, SIG_DFL);
	signal(SIGSYS, SIG_DFL);
	signal(SIGXCPU, SIG_DFL);
	signal(SIGXFSZ, SIG_DFL);
	
	INFO_MSG("Extensible Ethernet Monitor Sensor Multiplexer exiting");

	eemo_mt_openssl_finalize();
	
	/* Uninitialise logging */
	if (eemo_uninit_log() != ERV_OK)
	{
		fprintf(stderr, "Failed to uninitialise logging\n");
	}

	free(pid_path);
	free(config_path);

	return 0;
}

