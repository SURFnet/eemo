/*
 * Copyright (c) 2010-2015 SURFnet bv
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
 * Capture handling
 */

#include "config.h"
#include "eemo.h"
#include "eemo_capture.h"
#include "eemo_config.h"
#include "eemo_log.h"
#include "ether_capture.h"
#include "file_capture.h"
#include "mux_capture.h"
#include <stdlib.h>
#include <string.h>

/* Capture modes */
#define EEMO_CAPTURE_DIRECT	1		/* Capture directly from a network interface */
#define EEMO_CAPTURE_FILE	2		/* Read from a PCAP file */
#define EEMO_CAPTURE_MUX	3		/* Receive data from one or more mux feeds */

/* Configuration */
static int		capture_mode	= EEMO_CAPTURE_DIRECT;

/* Initialise capturing */
eemo_rv eemo_capture_init(const char* interface, const char* savefile)
{
	char*	conf_mode	= NULL;
	eemo_rv	rv		= ERV_OK;

	if ((interface != NULL) && (savefile != NULL))
	{
		ERROR_MSG("Cannot capture from an interface and a PCAP file at the same time, please specify one capture option");

		return ERV_CONFIG_ERROR;
	}

	if (interface != NULL)
	{
		/* Implicitly selected direct capture */
		conf_mode = strdup("capture");

		DEBUG_MSG("Implicitly selected direct capture mode");
	}
	else if (savefile != NULL)
	{
		/* Implicitly selected reading from a PCAP file */
		conf_mode = strdup("file");

		DEBUG_MSG("Implicitly selected reading from a PCAP file");
	}
	else
	{
		if (eemo_conf_get_string("capture", "mode", &conf_mode, "capture") != ERV_OK)
		{
			ERROR_MSG("Failed to retrieve the capturing configuration");

			return ERV_CONFIG_ERROR;
		}
	}

	if (strcasecmp(conf_mode, "capture") == 0)
	{
		INFO_MSG("Will capture directly from a network interface");

		capture_mode = EEMO_CAPTURE_DIRECT;
	}
	else if (strcasecmp(conf_mode, "file") == 0)
	{
		INFO_MSG("Will read from a PCAP file");

		capture_mode = EEMO_CAPTURE_FILE;
	}
	else if (strcasecmp(conf_mode, "muxfeed") == 0)
	{
		INFO_MSG("Will capture data from one or more multiplexer feeds");

		capture_mode = EEMO_CAPTURE_MUX;
	}
	else
	{
		ERROR_MSG("Unknown capture mode %s configured", capture_mode);

		free(conf_mode);

		return ERV_CONFIG_ERROR;
	}

	free(conf_mode);

	/* Perform mode-specific initialisation */
	switch(capture_mode)
	{
	case EEMO_CAPTURE_DIRECT:
		rv = eemo_ether_capture_init(interface);
		break;
	case EEMO_CAPTURE_FILE:
		rv = eemo_file_capture_init(savefile);
		break;
	case EEMO_CAPTURE_MUX:
		rv = eemo_mux_capture_init(&eemo_handle_ether_packet);
		break;
	}

	if (rv != ERV_OK)
	{
		ERROR_MSG("Capture method-specific initialisation failed, giving up");

		return rv;
	}

	INFO_MSG("Initialised capturing");

	return ERV_OK;
}

/* Uninitialise capturing */
eemo_rv eemo_capture_finalize(void)
{
	eemo_rv	rv	= ERV_OK;

	/* Perform mode-specific uninitialisation */
	switch(capture_mode)
	{
	case EEMO_CAPTURE_DIRECT:
		rv = eemo_ether_capture_finalize();
		break;
	case EEMO_CAPTURE_FILE:
		rv = eemo_file_capture_finalize();
		break;
	case EEMO_CAPTURE_MUX:
		rv = eemo_mux_capture_finalize();
		break;
	}

	if (rv != ERV_OK)
	{
		ERROR_MSG("Capture method-specific uninitialisation failed");

		return rv;
	}

	INFO_MSG("Uninitialised capturing");

	return ERV_OK;
}

/* Run the capture until interrupted */
void eemo_capture_run(void)
{
	switch(capture_mode)
	{
	case EEMO_CAPTURE_DIRECT:
		eemo_ether_capture_run();
		break;
	case EEMO_CAPTURE_FILE:
		eemo_file_capture_run();
		break;
	case EEMO_CAPTURE_MUX:
		eemo_mux_capture_run();
		break;
	}
}

