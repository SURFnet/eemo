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
 * The Extensible Ethernet Monitor (EEMO)
 * Configuration handling
 */

#include "config.h"
#include "eemo.h"
#include "eemo_config.h"
#include "utlist.h"
#include "eemo_log.h"
#include <libconfig.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>

/* The configuration */
config_t configuration;

/* Initialise the configuration handler */
eemo_rv eemo_init_config_handling(const char* config_path)
{
	if ((config_path == NULL) || (strlen(config_path) == 0))
	{
		return ERV_NO_CONFIG;
	}

	/* Initialise the configuration */
	config_init(&configuration);

	/* Load the configuration from the specified file */
	if (config_read_file(&configuration, config_path) != CONFIG_TRUE)
	{
		fprintf(stderr, "Failed to read the configuration: %s (%s:%d)\n",
			config_error_text(&configuration),
			config_path,
			config_error_line(&configuration));

		config_destroy(&configuration);

		return ERV_CONFIG_ERROR;
	}

	return ERV_OK;
}

/* Release the configuration handler */
eemo_rv eemo_uninit_config_handling(void)
{
	/* Uninitialise the configuration */
	config_destroy(&configuration);

	return ERV_OK;
}

/* Get an integer value */
eemo_rv eemo_conf_get_int(const char* base_path, const char* sub_path, int* value, int def_val)
{
	/* Unfortunately, the kludge below is necessary since the interface for config_lookup_int changed between
	 * libconfig version 1.3 and 1.4 */
#ifndef LIBCONFIG_VER_MAJOR /* this means it is a pre 1.4 version */
	long conf_val = 0;
#else
	int conf_val = 0;
#endif /* libconfig API kludge */
	static char path_buf[8192];

	if ((base_path == NULL) || (sub_path == NULL) || (value == NULL))
	{
		return ERV_PARAM_INVALID;
	}

	snprintf(path_buf, 8192, "%s.%s", base_path, sub_path);

	if (config_lookup_int(&configuration, path_buf, &conf_val) != CONFIG_TRUE)
	{
		*value = def_val;
	}
	else
	{
		*value = conf_val;
	}

	return ERV_OK;
}

/* Get a boolean value */
eemo_rv eemo_conf_get_bool(const char* base_path, const char* sub_path, int* value, int def_val)
{
	int conf_val = 0;
	static char path_buf[8192];

	if ((base_path == NULL) || (sub_path == NULL) || (value == NULL))
	{
		return ERV_PARAM_INVALID;
	}

	snprintf(path_buf, 8192, "%s.%s", base_path, sub_path);

	if (config_lookup_bool(&configuration, path_buf, &conf_val) != CONFIG_TRUE)
	{
		*value = def_val;
	}
	else
	{
		*value = (conf_val == CONFIG_TRUE) ? 1 : 0;
	}

	return ERV_OK;
}

/* Get a string value; note: caller must free string returned in value! */
eemo_rv eemo_conf_get_string(const char* base_path, const char* sub_path, char** value, char* def_val)
{
	const char* conf_val = NULL;
	static char path_buf[8192];

	if ((base_path == NULL) || (sub_path == NULL) || (value == NULL))
	{
		return ERV_PARAM_INVALID;
	}

	snprintf(path_buf, 8192, "%s.%s", base_path, sub_path);

	if (config_lookup_string(&configuration, path_buf, &conf_val) != CONFIG_TRUE)
	{
		if (def_val == NULL)
		{
			*value = NULL;
		}
		else
		{
			*value = strdup(def_val);
		}
	}
	else
	{
		*value = strdup(conf_val);
	}

	return ERV_OK;
}

/* Get an array of string values; note: caller must free the array by calling the function below */
eemo_rv eemo_conf_get_string_array(const char* base_path, const char* sub_path, char*** value, int* count)
{
	config_setting_t* array = NULL;
	static char path_buf[8192];

	if ((base_path == NULL) || (sub_path == NULL) || (value == NULL) || (count == NULL))
	{
		return ERV_PARAM_INVALID;
	}

	snprintf(path_buf, 8192, "%s.%s", base_path, sub_path);

	*count = 0;

	array = config_lookup(&configuration, path_buf);

	if (array != NULL)
	{
		int elem_count = 0;
		int i = 0;

		/* Check if it is an array */
		if (config_setting_is_array(array) == CONFIG_FALSE)
		{
			return ERV_CONFIG_NO_ARRAY;
		}

		/* The array was found, retrieve the strings */
		elem_count = config_setting_length(array);

		/* Now allocate memory for the string array */
		*value = (char**) malloc(elem_count * sizeof(char**));

		if (*value == NULL)
		{
			return ERV_MEMORY;
		}

		for (i = 0; i < elem_count; i++)
		{
			/* Retrieve the individual element */
			const char* string_value = config_setting_get_string_elem(array, i);

			if (string_value != NULL)
			{
				(*value)[i] = strdup(string_value);
			}
			else
			{
				(*value)[i] = strdup("");
			}
		}

		*count = elem_count;
	}

	return ERV_OK;
}

/* Free an array of string values */
eemo_rv eemo_conf_free_string_array(char** array, int count)
{
	int i = 0;

	for (i = 0; i < count; i++)
	{
		free(array[i]);
	}

	free(array);

	return ERV_OK;
}

/* Get a byte string value */
eemo_rv eemo_conf_get_bytestring(const char* base_path, const char* sub_path, unsigned char** value, size_t* len)
{
	char*	str_val		= NULL;
	size_t	i		= 0;

	if ((base_path == NULL) || (sub_path == NULL) || (value == NULL) || (len == NULL))
	{
		return ERV_PARAM_INVALID;
	}

	/* Get the data as a string value first */
	if (eemo_conf_get_string(base_path, sub_path, &str_val, NULL) != ERV_OK)
	{
		return ERV_CONFIG_ERROR;
	}

	if (str_val == NULL)
	{
		/* No value configured, exit early */
		*value = NULL;
		*len = 0;

		return ERV_OK;
	}

	if (strlen(str_val) % 2 != 0)
	{
		/* The string cannot have an odd length if it's a byte string */
		free(str_val);

		return ERV_CONFIG_ERROR;
	}

	/* Convert the value from hexadecimal to bytes */
	*len = strlen(str_val) / 2;
	*value = (unsigned char*) malloc((*len) * sizeof(unsigned char));

	for (i = 0; i < *len; i++)
	{
		char	byte[3]	= { 0 };

		strncpy(byte, &str_val[i * 2], 2);

		(*value)[i] = (unsigned char) strtoul(byte, NULL, 16);
	}

	return ERV_OK;
}

/* Get a pointer to the internal configuration structure */
const config_t* eemo_conf_get_config_t(void)
{
	return &configuration;
}
