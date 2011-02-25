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

/*
 * The Extensible Ethernet Monitor (EEMO)
 * Logging
 */

#include "config.h"
#include "eemo.h"
#include "eemo_log.h"
#include "eemo_config.h"
#include <stdio.h>
#include <time.h>
#include <stdarg.h>
#include <syslog.h>
#include <stdlib.h>

/* The log level */
static int log_level = EEMO_LOGLEVEL;

/* The log file */
static FILE* log_file = NULL;

/* Should we log to syslog? */
static int log_syslog = 1;

/* Should we log to stdout? */
static int log_stdout = 0;

/* Initialise logging */
eemo_rv eemo_init_log(void)
{
	char* log_file_path = NULL;

	/* Retrieve the log level specified in the configuration file; this will override the default log level */
	if (eemo_conf_get_int("logging", "loglevel", &log_level, EEMO_LOGLEVEL) != ERV_OK)
	{
		return ERV_LOG_INIT_FAIL;
	}

	/* Retrieve the file name of the log file, if set */
	if (eemo_conf_get_string("logging", "filelog", &log_file_path, NULL) != ERV_OK)
	{
		return ERV_LOG_INIT_FAIL;
	}

	if (log_file_path != NULL)
	{
		log_file = fopen(log_file_path, "w");

		if (log_file == NULL)
		{
			fprintf(stderr, "Failed to open log file %s for writing\n", log_file_path);

			return ERV_LOG_INIT_FAIL;
		}

		free(log_file_path);
	}
	else
	{
		log_file = NULL;
	}

	/* Check whether we should log to syslog */
	if (eemo_conf_get_bool("logging", "syslog", &log_syslog, 1) != ERV_OK)
	{
		return ERV_LOG_INIT_FAIL;
	}

	/* Check whether we should log to stdout */
	if (eemo_conf_get_bool("logging", "stdout", &log_stdout, 0) != ERV_OK)
	{
		return ERV_LOG_INIT_FAIL;
	}

	return ERV_OK;
}

/* Uninitialise logging */
eemo_rv eemo_uninit_log(void)
{
	/* Close the log file if necessary */
	if (log_file != NULL)
	{
		fclose(log_file);
	}

	return ERV_OK;
}

/* Log something */
void eemo_log(const int log_at_level, const char* file, const int line, const char* format, ...)
{
	static char log_buf[8192];
	static char timestamp[128];
	va_list args;

	/* Check the log level */
	if (log_at_level > log_level)
	{
		return;
	}

	/* Print the log message */
	va_start(args, format);

	if (log_at_level == EEMO_LOG_DEBUG)
	{
		static char debug_buf[8192];
		vsnprintf(debug_buf, 8192, format, args);
		snprintf(log_buf, 8192, "%s(%d): %s", file, line, debug_buf);
	}
	else
	{
		vsnprintf(log_buf, 8192, format, args);
	}

	va_end(args);

	/* Check if we need to log to a file or stdout */
	if (log_stdout || log_file)
	{
		time_t now = 0;
		struct tm* now_tm = NULL;

		/* Create a timestamp */
		now = time(NULL);
		now_tm = localtime(&now);

		snprintf(timestamp, 128, "%4d-%02d-%02d %02d:%02d:%02d",
			now_tm->tm_year+1900,
			now_tm->tm_mon+1,
			now_tm->tm_mday,
			now_tm->tm_hour,
			now_tm->tm_min,
			now_tm->tm_sec);

		if (log_stdout)
		{
			printf("%s %s\n", timestamp, log_buf);
			fflush(stdout);
		}

		if (log_file)
		{
			fprintf(log_file, "%s %s\n", timestamp, log_buf);
			fflush(log_file);
		}
	}

	/* Check if we need to log to syslog */
	if (log_syslog)
	{
		syslog(log_at_level, "%s", log_buf);
	}
}

