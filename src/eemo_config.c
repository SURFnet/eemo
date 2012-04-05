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

/* The list of modules */
static eemo_module_spec* modules = NULL;

/* The configuration */
config_t configuration;

/* The EEMO function table */
eemo_export_fn_table eemo_function_table =
{
	EEMO_EXPORT_FN_VERSION,
	&eemo_log,
	&eemo_conf_get_int,
	&eemo_conf_get_bool,
	&eemo_conf_get_string,
	&eemo_conf_get_string_array,
	&eemo_conf_free_string_array,
	&eemo_reg_ether_handler,
	&eemo_unreg_ether_handler,
	&eemo_reg_ip_handler,
	&eemo_unreg_ip_handler,
	&eemo_reg_icmp_handler,
	&eemo_unreg_icmp_handler,
	&eemo_reg_tcp_handler,
	&eemo_unreg_tcp_handler,
	&eemo_reg_udp_handler,
	&eemo_unreg_udp_handler,
	&eemo_reg_dns_qhandler,
	&eemo_unreg_dns_qhandler
};

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

/* Load and initialise the modules */
eemo_rv eemo_conf_load_modules(void)
{
	unsigned int mod_count = 0;
	config_setting_t* modules_conf = NULL;
	int i = 0;
	int loaded_modules = 0;

	/* Get a reference to the module configuration */
	modules_conf = config_lookup(&configuration, "modules");

	if (modules_conf == NULL)
	{
		ERROR_MSG("No modules have been configured");

		return ERV_NO_MODULES;
	}

	/* Initialise list of modules */
	modules = NULL;

	/* Determine the number of configured modules */
	mod_count = config_setting_length(modules_conf);

	/* Now load the configured modules one-by-one */
	for (i = 0; i < mod_count; i++)
	{
		config_setting_t* mod_conf = NULL;
		eemo_module_spec* new_mod = NULL;
		const char* lib_path = NULL;
		eemo_plugin_get_fn_table_fn mod_getfn = NULL;
		void* mod_entry = NULL;

		/* Retrieve the module to load */
		mod_conf = config_setting_get_elem(modules_conf, i);

		if (mod_conf == NULL)
		{
			ERROR_MSG("Failed to enumerate next configured module");

			continue;
		}

		/* Retrieve the module path setting */
		if ((config_setting_lookup_string(mod_conf, "lib", &lib_path) != CONFIG_TRUE) || (lib_path == NULL))
		{
			ERROR_MSG("No library specified in module section for '%s'", config_setting_name(mod_conf));

			continue;
		}

		new_mod = (eemo_module_spec*) malloc(sizeof(eemo_module_spec));

		if (new_mod == NULL)
		{
			ERROR_MSG("Error allocating memory for a new module");

			continue;
		}

		new_mod->mod_path = strdup(lib_path);

		if (new_mod->mod_path == NULL)
		{
			ERROR_MSG("Error allocating memory for a new module");

			free(new_mod);

			continue;
		}

		new_mod->mod_conf_base = (char*) malloc((strlen("modules.") + 
		                                         strlen(config_setting_name(mod_conf)) + 
							 strlen(".modconf") + 1) * sizeof(char));

		if (new_mod->mod_conf_base == NULL)
		{
			ERROR_MSG("Error allocating memory for a new module");

			free(new_mod->mod_path);
			free(new_mod);

			continue;
		}

		sprintf(new_mod->mod_conf_base, "modules.%s.modconf", config_setting_name(mod_conf));

		/* Now try to load the module */
		new_mod->mod_handle = dlopen(new_mod->mod_path, RTLD_NOW | RTLD_LOCAL);

		if (new_mod->mod_handle == NULL)
		{
			ERROR_MSG("Failed to load module %s (%s)", new_mod->mod_path, dlerror());

			free(new_mod->mod_path);
			free(new_mod->mod_conf_base);
			free(new_mod);

			continue;
		}

		INFO_MSG("Loaded module %s", new_mod->mod_path);

		/* Retrieve the module entry point */

		/* FIXME: we need to use this ugly memcpy kludge in order to avoid the compiler complaining about
		 *        data pointers getting converted to function pointers. The reason for this is that dlsym
		 *        returns a void* which is a data pointer. In effect, dlsym violates the ANSI C standard
		 *        here... See http://pubs.opengroup.org/onlinepubs/009695399/functions/dlsym.html */

		mod_entry = dlsym(new_mod->mod_handle, "eemo_plugin_get_fn_table");
		memcpy(&mod_getfn, &mod_entry, sizeof(void*));

		if (mod_getfn == NULL)
		{
			ERROR_MSG("Failed to resolve entry point eemo_plugin_get_fn_table in %s", new_mod->mod_path);

			free(new_mod->mod_path);
			free(new_mod->mod_conf_base);
			free(new_mod);

			continue;
		}

		/* Retrieve the module function table */
		if ((mod_getfn)(&new_mod->mod_fn_table) != ERV_OK)
		{
			ERROR_MSG("Failed to retrieve the function table in %s", new_mod->mod_path);

			dlclose(new_mod->mod_handle);
			free(new_mod->mod_path);
			free(new_mod->mod_conf_base);
			free(new_mod);

			continue;
		}

		/* Check the function table version */
		if (new_mod->mod_fn_table->fn_table_version > EEMO_PLUGIN_FN_VERSION)
		{
			ERROR_MSG("Unsupported plugin module API version %d in module %s",
				new_mod->mod_fn_table->fn_table_version,
				new_mod->mod_path);

			dlclose(new_mod->mod_handle);
			free(new_mod->mod_path);
			free(new_mod->mod_conf_base);
			free(new_mod);

			continue;
		}

		/* Initialise the module */
		if ((new_mod->mod_fn_table->plugin_init)(&eemo_function_table, new_mod->mod_conf_base) != ERV_OK)
		{
			ERROR_MSG("Failed to initialise module %s", (new_mod->mod_fn_table->plugin_getdescription)());

			dlclose(new_mod->mod_handle);
			free(new_mod->mod_path);
			free(new_mod->mod_conf_base);
			free(new_mod);

			continue;
		}

		INFO_MSG("Initialised module %s", (new_mod->mod_fn_table->plugin_getdescription)());

		/* Add it to the list of modules */
		LL_APPEND(modules, new_mod);

		loaded_modules++;
	}

	if (loaded_modules == 0)
	{
		ERROR_MSG("Failed to load any modules");

		return ERV_NO_MODULES;
	}

	return ERV_OK;
}

/* Unload and uninitialise the modules */
eemo_rv eemo_conf_unload_modules(void)
{
	eemo_module_spec* module_it = NULL;
	eemo_module_spec* module_tmp = NULL;

	/* Unload all loaded modules and clean up the list of modules */
	LL_FOREACH_SAFE(modules, module_it, module_tmp)
	{
		/* Uninitialise the module */
		if (module_it->mod_fn_table->plugin_uninit(&eemo_function_table) != ERV_OK)
		{
			ERROR_MSG("Failed to uninitialise plugin module %s", module_it->mod_path);
		}
		else
		{
			INFO_MSG("Uninitialised plugin module %s", module_it->mod_path);
		}

		/* Unload the module */
		if (dlclose(module_it->mod_handle) != 0)
		{
			ERROR_MSG("Failed to unload %s", module_it->mod_path);
		}
		else
		{
			INFO_MSG("Unloaded plugin module %s", module_it->mod_path);
		}

		/* Free up memory taken by the module path */
		free(module_it->mod_path);
	
		LL_DELETE(modules, module_it);

		free(module_it);
	}

	return ERV_OK;
}

