/*
 * Copyright (c) 2010-2016 SURFnet bv
 * Copyright (c) 2014-2016 Roland van Rijswijk-Deij
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
#include <pthread.h>
#include <archive.h>
#include <archive_entry.h>
#include "eemo.h"
#include "eemo_api.h"
#include "eemo_packet.h"
#include "ip_handler.h"
#include "icmp_handler.h"
#include "udp_handler.h"
#include "tcp_handler.h"
#include "dns_handler.h"
#include "dns_types.h"
#include "raw_handler.h"
#include "ifaddr_lookup.h"
#include "eemo_capture.h"
#include "eemo_config.h"
#include "eemo_modules.h"
#include "eemo_log.h"
#include "ip_metadata.h"
#include "ip_reassemble.h"
#include "cidrmatch.h"
#include "eemo_fio.h"

#define DIR_SORT_ALPHA	1
#define	DIR_SORT_CHRONO	2

void version(void)
{
	printf("Extensible Ethernet Monitor (eemo) version %s\n", VERSION);
	printf("Copyright (c) 2010-2016 SURFnet bv\n");
	printf("Copyright (c) 2014-2016 Roland van Rijswijk-Deij\n\n");
	printf("Use, modification and redistribution of this software is subject to the terms\n");
	printf("of the license agreement. This software is licensed under a 3-clause BSD-style\n");
	printf("license a copy of which is included as the file LICENSE in the distribution.\n");
}

void usage(void)
{
	printf("Extensible Ethernet Monitor (eemo) version %s\n\n", VERSION);
	printf("Usage:\n");
	printf("\teemo [-i <if>] [-f] [-c <config>] [-p <pidfile>]\n");
	printf("\teemo [-s <savefile>]\n");
	printf("\teemo [-D <directory>] [-a] [-t]\n");
	printf("\teemo [-A <archive list>] [-T <tmppath>]\n");
	printf("\teemo -h\n");
	printf("\teemo -v\n");
	printf("\n");
	printf("\t-i <if>        Capture package on interface <if>; defaults to standard packet\n");
	printf("\t               capturing interface reported by libpcap, see pcap_lookupdev(3).\n");
	printf("\t-f             Run in the foreground rather than forking as a daemon.\n");
	printf("\t-c <config>    Use <config> as configuration file.\n");
	printf("\t               Defaults to %s\n", DEFAULT_EEMO_CONF);
	printf("\t-p <pidfile>   Specify the PID file to write the daemon process ID to.\n");
	printf("\t               Defaults to %s\n", DEFAULT_EEMO_PIDFILE);
	printf("\n");
	printf("\t-s <savefile>  Play back a PCAP savefile (e.g. dumped using tcpdump) instead\n");
	printf("\t               of using a live capture; options -c and -p may also be\n");
	printf("\t               supplied, option -f is implied. PCAP files in gzipped format\n");
	printf("\t               are also accepted, and automatically detected.\n");
	printf("\n");
	printf("\t-D <directory> Read PCAP savefiles from <directory>; any file in the directory\n");
	printf("\t               is treated as a savefile in either PCAP or gzipped PCAP format.\n");
	printf("\t               Use -a or -t to select the sorting order in which the files are\n");
	printf("\t               read.\n");
	printf("\t-a             Sort files read from the directory specified with -D in\n");
	printf("\t               alphabetical order (note: strcmp respects the configure locale\n");
	printf("\t               of your system).\n");
	printf("\t-t             Sort files read from the directory specified with -D in\n");
	printf("\t               chronological order from oldest to newest.\n");
	printf("\t               (this is the default sorting order)\n");
	printf("\n");
	printf("\t-A <arclist>   Read from .tar.gz files listed in <arclist>\n");
	printf("\t-T <tmppath>   Uncompress files temporarily to <tmppath>\n");
	printf("\t               (if you have enough memory, it is recommended to create a\n");
	printf("\t                RAM disk for this purpose)\n");
	printf("\n");
	printf("\t-h             Print this help message\n");
	printf("\n");
	printf("\t-v             Print the version number\n");
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

int dir_sort_alpha(void* left, void* right)
{
	dir_entry*	left_ent	= (dir_entry*) left;
	dir_entry*	right_ent	= (dir_entry*) right;

	return strcmp(left_ent->name, right_ent->name);
}

int dir_sort_chrono(void* left, void* right)
{
	dir_entry*	left_ent	= (dir_entry*) left;
	dir_entry*	right_ent	= (dir_entry*) right;

	return (int) (left_ent->mtime - right_ent->mtime);
}

void playback_directory(const char* dir_path, const int sort_mode)
{
	dir_entry*	dir_content	= NULL;
	dir_entry*	dir_it		= NULL;
	char		full_path[4096]	= { 0 };

	INFO_MSG("Starting playback for PCAP files in %s", dir_path);

	dir_content = eemo_fio_enum_dir(dir_path);

	/* Sort according to the specified order */
	switch(sort_mode)
	{
	case DIR_SORT_ALPHA:
		LL_SORT(dir_content, dir_sort_alpha);
		break;
	case DIR_SORT_CHRONO:
	default:
		LL_SORT(dir_content, dir_sort_chrono);
		break;
	}

	LL_FOREACH(dir_content, dir_it)
	{
		snprintf(full_path, 4096, "%s/%s", dir_path, dir_it->name);

		/* Play back */
		if (eemo_capture_init(NULL, full_path) != ERV_OK)
		{
			ERROR_MSG("Failed to initialise capture, giving up");
		}
		else
		{
			eemo_capture_run();
	
			eemo_capture_finalize();
		}
	}

	eemo_fio_dir_free(dir_content);

	INFO_MSG("Processed final file in %s", dir_path);
}

void playback_archives(const char* arclist_file, const char* tmppath)
{
	FILE*	arclist_fd		= fopen(arclist_file, "r");
	char	arcname[4096]		= { 0 };
	char	pcap_tmp_path[1024]	= { 0 };
	char	tmp_dir[512]		= { 0 };

	if (arclist_fd == NULL)
	{
		ERROR_MSG("Failed to open %s for reading", arclist_file);

		return;
	}

	if (tmppath != NULL)
	{
		snprintf(tmp_dir, 512, "%s", tmppath);
	}
	else
	{
		snprintf(tmp_dir, 512, "/tmp");
	}

	snprintf(pcap_tmp_path, 1024, "%s/arctmp", tmp_dir);

	INFO_MSG("Reading archives to process from %s", arclist_file);

	while (!feof(arclist_fd))
	{
		struct archive*		arc		= NULL;
		struct archive_entry*	arc_entry	= NULL;
		FILE*			tmp		= NULL;

		if (fgets(arcname, 4096, arclist_fd) == NULL)
		{
			break;
		}

		/* Strip <CR><LF> */
		while (strrchr(arcname, '\n') != NULL) *strrchr(arcname, '\n') = '\0';
		while (strrchr(arcname, '\r') != NULL) *strrchr(arcname, '\r') = '\0';

		if (strlen(arcname) == 0) continue;

		arc = archive_read_new();

		archive_read_support_filter_all(arc);
		archive_read_support_format_all(arc);

		/* Try to open the archive */
		if (archive_read_open_filename(arc, arcname, 1024*1024) != ARCHIVE_OK)
		{
			ERROR_MSG("Failed to open archive %s", arcname);

			archive_read_free(arc);

			continue;
		}

		while (archive_read_next_header(arc, &arc_entry) == ARCHIVE_OK)
		{
			INFO_MSG("Extracting %s from %s", archive_entry_pathname(arc_entry), arcname);

			tmp = fopen(pcap_tmp_path, "w");

			if (tmp == NULL)
			{
				ERROR_MSG("Failed to open %s for writing", pcap_tmp_path);
				continue;
			}

			if (archive_read_data_into_fd(arc, fileno(tmp)) != ARCHIVE_OK)
			{
				ERROR_MSG("Extraction failed");

				fclose(tmp);

				unlink(pcap_tmp_path);

				continue;
			}

			fclose(tmp);

			/* Process the data in the PCAP */
			if (eemo_capture_init(NULL, pcap_tmp_path) != ERV_OK)
			{
				ERROR_MSG("Failed to initialise capture, giving up");
			}
			else
			{
				eemo_capture_run();
		
				eemo_capture_finalize();
			}

			unlink(pcap_tmp_path);
		}

		archive_read_free(arc);
	}

	INFO_MSG("Finished processing archives from %s", arclist_file);

	fclose(arclist_fd);
}

int main(int argc, char* argv[])
{
	char*	interface	= NULL;
	char*	config_path	= NULL;
	char*	pid_path	= NULL;
	char*	savefile_path	= NULL;
	char*	savefile_dir	= NULL;
	char*	arclist_file	= NULL;
	char*	tmppath		= NULL;
	int	arclist_set	= 0;
	int	daemon		= 1;
	int	c		= 0;
	int	pid_path_set	= 0;
	int	daemon_set	= 0;
	int	interface_set	= 0;
	int	savefile_set	= 0;
	int	savedir_set	= 0;
	int	dir_sort	= DIR_SORT_CHRONO;
	pid_t	pid		= 0;
	
	while ((c = getopt(argc, argv, "i:s:fc:p:D:atA:T:hv")) != -1)
	{
		switch(c)
		{
		case 'i':
			interface = strdup(optarg);

			interface_set = 1;

			break;
		case 's':
			savefile_path = strdup(optarg);

			savefile_set = 1;
			
			/* Always run in the foreground when playing back a recorded dump */
			daemon = 0;
			daemon_set = 1;
			break;
		case 'D':
			savefile_dir = strdup(optarg);

			savedir_set = 1;

			/* Always run in the foreground when playing back PCAPs from a directory */
			daemon = 0;
			daemon_set = 1;
			break;
		case 'a':
			dir_sort = DIR_SORT_ALPHA;
			break;
		case 't':
			dir_sort = DIR_SORT_CHRONO;
			break;
		case 'A':
			arclist_file = strdup(optarg);
			arclist_set = 1;

			/* Always run in the foreground when reading from archives */
			daemon = 0;
			daemon_set = 1;
			break;
		case 'T':
			tmppath = strdup(optarg);
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

	if (interface_set && (savefile_set || savedir_set || arclist_set))
	{
		fprintf(stderr, "Cannot combine live capture (-i) and savefile playback (-s, -D, -A), exiting\n");

		return ERV_CONFIG_ERROR;
	}

	if (savefile_set && savedir_set)
	{
		fprintf(stderr, "Cannot combine reading individual savefile (-s) with directory playback (-D), exiting\n");

		return ERV_CONFIG_ERROR;
	}

	if (savefile_set && arclist_set)
	{
		fprintf(stderr, "Cannot combine reading individual savefile (s) with reading from archives (-A), exiting\n");

		return ERV_CONFIG_ERROR;
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

	if (!interface_set && !savefile_set)
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
			free(savefile_path);
		
			if (interface != NULL)
			{
				free(interface);
			}

			return ERV_OK;
		}
	}

	/* If we forked, this is the child */
	INFO_MSG("Starting the Extensible Ethernet Monitor (eemo) version %s", VERSION);
	INFO_MSG("eemo %sprocess ID is %d", daemon ? "daemon " : "", getpid());

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

	/* Initialise metadata module */
	if (eemo_md_init() != ERV_OK)
	{
		ERROR_MSG("Failed to initialise metadata module");

		return ERV_GENERAL_ERROR;
	}

	/* Initialise IP reassembly module */
	if (eemo_reasm_init() != ERV_OK)
	{
		ERROR_MSG("Failed to initialise IP reassembly module");

		return ERV_GENERAL_ERROR;
	}

	/* Initialise CIDR block matching module */
	if (eemo_cm_init() != ERV_OK)
	{
		ERROR_MSG("Failed to initialise CIDR block matching");

		return ERV_GENERAL_ERROR;
	}

	/* Initialise packet handlers */
	if (eemo_init_raw_handler() != ERV_OK)
	{
		ERROR_MSG("Failed to initialise raw packet handler");

		return ERV_GENERAL_ERROR;
	}

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

	if (eemo_init_dns_handler() != ERV_OK)
	{
		ERROR_MSG("Failed to initialise the DNS query handler");
	}

	/* Load an initialise modules */
	if (eemo_conf_load_modules() != ERV_OK)
	{
		ERROR_MSG("Failed to load modules");

		return ERV_NO_MODULES;
	}

	if (savedir_set)
	{
		playback_directory(savefile_dir, dir_sort);
	}
	else if (arclist_set)
	{
		playback_archives(arclist_file, tmppath);
	}
	else
	{
		/* Start capturing */
		if (eemo_capture_init(interface, savefile_path) != ERV_OK)
		{
			ERROR_MSG("Failed to initialise capture, giving up");
		}
		else
		{
			eemo_capture_run();
	
			eemo_capture_finalize();
		}
	}

	INFO_MSG("Stopping the Extensible Ethernet Monitor (eemo) version %s", VERSION);

	/* Unload and uninitialise modules */
	if (eemo_conf_unload_modules() != ERV_OK)
	{
		ERROR_MSG("Failed to unload modules");
	}

	/* Uninitialise all handlers */
	eemo_dns_handler_cleanup();
	eemo_tcp_handler_cleanup();
	eemo_udp_handler_cleanup();
	eemo_icmp_handler_cleanup();
	eemo_ip_handler_cleanup();
	eemo_ether_handler_cleanup();
	eemo_raw_handler_cleanup();

	/* Uninitialise IP reassembly module */
	eemo_reasm_finalize();

	/* Uninitialise metadata handling */
	eemo_md_finalize();

	/* Uninitialise CIDR matching */
	eemo_cm_finalize();

	/* Unload the configuration */
	if (eemo_uninit_config_handling() != ERV_OK)
	{
		ERROR_MSG("Failed to uninitialise configuration handling");
	}

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

	/* Uninitialise logging */
	if (eemo_uninit_log() != ERV_OK)
	{
		fprintf(stderr, "Failed to uninitialise logging\n");
	}

	free(pid_path);
	free(config_path);
	free(savefile_path);
	free(savefile_dir);
	free(arclist_file);
	free(tmppath);

	if (interface != NULL)
	{
		free(interface);
	}

	/* Suppress valgrind warning */
	pthread_exit(NULL);

	return 0;
}

