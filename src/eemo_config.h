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

#ifndef _EEMO_CONFIG_H
#define _EEMO_CONFIG_H

#include "config.h"
#include "eemo.h"
#include "eemo_api.h"
#include <libconfig.h>

/* Initialise the configuration handler */
eemo_rv eemo_init_config_handling(const char* config_path);

/* Get an integer value */
eemo_rv eemo_conf_get_int(const char* base_path, const char* sub_path, int* value, int def_val);

/* Get a boolean value */
eemo_rv eemo_conf_get_bool(const char* base_path, const char* sub_path, int* value, int def_val);

/* Get a string value; note: caller must free string returned in value! */
eemo_rv eemo_conf_get_string(const char* base_path, const char* sub_path, char** value, char* def_val);

/* Get an array of string values; note: caller must free the array by calling the function below */
eemo_rv eemo_conf_get_string_array(const char* base_path, const char* sub_path, char*** value, int* count);

/* Free an array of string values */
eemo_rv eemo_conf_free_string_array(char** array, int count);

/* Get a byte string value */
eemo_rv eemo_conf_get_bytestring(const char* base_path, const char* sub_path, unsigned char** value, size_t* len);

/* Release the configuration handler */
eemo_rv eemo_uninit_config_handling(void);

/* Get a pointer to the internal configuration structure */
const config_t* eemo_conf_get_config_t(void);

#endif /* !_EEMO_CONFIG_H */

