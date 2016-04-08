/*
 * Copyright (c) 2014-2016 Roland van Rijswijk-Deij
 * Copyright (c) 2016 SURFnet bv
 * All rights reserved
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
 */

/*
 * Generic file and directory I/O functions
 */

#include "config.h"
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include "eemo_fio.h"
#include "eemo_log.h"
#include "eemo.h"
#include "utlist.h"

/* Enumerate all regular files in a directory */
dir_entry* eemo_fio_enum_dir(const char* dir)
{
	dir_entry*	enumerated_dir	= NULL;
	DIR*		enum_dir	= NULL;
	struct dirent*	entry		= NULL;
	struct stat	file_stat;
	char		full_path[4096]	= { 0 };

	enum_dir = opendir(dir);

	if (enum_dir == NULL)
	{
		WARNING_MSG("Failed to open directory %s for enumerating", dir);

		return NULL;
	}

	while((entry = readdir(enum_dir)) != NULL)
	{
		dir_entry*	new_entry	= NULL;

#if defined(_DIRENT_HAVE_D_TYPE) && defined(_BSD_SOURCE)
		if (entry->d_type != DT_REG)
		{
			/* Only add regular files */
			continue;
		}
#else
		struct stat entry_stat;

		if ((lstat(entry->d_name, &entry_stat) != 0) || !S_ISREG(entry_state.st_mode))
		{
			/* Only add regular files */
			continue;
		}
#endif

		/* Get information on the file */
		snprintf(full_path, 4096, "%s/%s", dir, entry->d_name);

		if (stat(full_path, &file_stat) != 0)
		{
			ERROR_MSG("Failed to stat(..) %s", full_path);
			continue;
		}

		new_entry = (dir_entry*) malloc(sizeof(dir_entry));

		new_entry->name = strdup(entry->d_name);
		new_entry->mtime = file_stat.st_mtime;

		LL_APPEND(enumerated_dir, new_entry);
	}

	closedir(enum_dir);

	return enumerated_dir;
}

/* Free a list of directory entries */
void eemo_fio_dir_free(dir_entry* enumerated_dir)
{
	dir_entry*	dir_it	= NULL;
	dir_entry*	dir_tmp	= NULL;

	LL_FOREACH_SAFE(enumerated_dir, dir_it, dir_tmp)
	{
		free(dir_it->name);
		free(dir_it);
	}
}

