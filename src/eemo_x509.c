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
 * X.509 certificate handling
 */


#include "config.h"
#include "eemo.h"
#include "eemo_api.h"
#include "eemo_log.h"
#include "eemo_x509.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

/* Check if the supplied certificate matches any of the certificates in the specified directory */
int eemo_x509_check_cert(X509* cert, const char* cert_dir)
{
	struct dirent*	entry			= NULL;
	DIR* 			dir 			= opendir(cert_dir);
	char			cert_fn[1024]	= { 0 };
#if !defined(_DIRENT_HAVE_D_TYPE) || !defined(_BSD_SOURCE)
	struct stat		entry_stat		= { 0 };
#endif
	
	if (dir == NULL)
	{
		ERROR_MSG("Failed to open directory %s for listing", cert_dir);
		
		return -1;
	}
	
	/* Enumerate the directory and see if the certificate matches */
	while ((entry = readdir(dir)) != NULL)
	{
		/* Skip . and .. */
		if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
		{
			continue;
		}
		
		/* FIXME: we assume that the path separator is '/' */
		snprintf(cert_fn, 1024, "%s/%s", cert_dir, entry->d_name);
		
#if defined(_DIRENT_HAVE_D_TYPE) && defined(_BSD_SOURCE)
		/* Use d_type from dirent structure */
		if (entry->d_type == DT_REG)
		{
#else
		/* We need lstat to determine the entry type */
		if (!lstat(cert_fn, &entry_stat) && (S_ISREG(entry_stat.st_mode)))
		{
#endif
			/* Regular file, try to read as a certificate */
			X509* 	read_cert 		= NULL;
			FILE*	cert_file		= NULL;
			
			DEBUG_MSG("Trying to match against certificate in %s", cert_fn);
			
			cert_file = fopen(cert_fn, "r");
			
			if (cert_file != NULL)
			{
				/* Try to read as DER encoding */
				read_cert = d2i_X509_fp(cert_file, NULL);
				
				if (read_cert == NULL)
				{
					/* That didn't work, try PEM instead */
					rewind(cert_file);
					
					read_cert = PEM_read_X509(cert_file, NULL, NULL, NULL);
				}
				
				fclose(cert_file);
				
				if ((read_cert != NULL) && !X509_cmp(cert, read_cert))
				{
					X509_free(read_cert);
					
					DEBUG_MSG("Matching certificate found");
					
					return 1;
				}
			}
		}
	}
	
	DEBUG_MSG("No matching certificate found");
	
	return 0;
}
