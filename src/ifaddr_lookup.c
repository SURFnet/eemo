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
 * Local Ethernet interface address database
 */

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "ifaddr_lookup.h"
#include "eemo.h"

/* Append an address to the list */
eemo_rv eemo_ifaddr_info_append(eemo_ifaddr_info** info, unsigned char iftype, const struct sockaddr* sa)
{
	eemo_ifaddr_info* new_record = NULL;

	new_record = (eemo_ifaddr_info*) malloc(sizeof(eemo_ifaddr_info));

	if (new_record == NULL)
	{
		/* Memory allocation error! */
		return ERV_MEMORY;
	}

	new_record->ifaddr_type = iftype;

	if (getnameinfo(sa, (iftype == IFADDR_TYPE_V4) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
		new_record->ifaddr_addr, NI_MAXHOST, NULL, 0, NI_NUMERICHOST) != 0)
	{
		/* Interface name conversion error */
		free(new_record);

		return ERV_GENERAL_ERROR;
	}

	new_record->next = NULL;

	/* Check if it is an IPv6 link local address; if so, do not append it */
	if ((new_record->ifaddr_type == IFADDR_TYPE_V6) && !strncmp(new_record->ifaddr_addr, "fe80", 4))
	{
		free(new_record);

		return ERV_OK;
	}

	/* Append the record */
	if (*info == NULL)
	{
		*info = new_record;
	}
	else
	{
		eemo_ifaddr_info* current = *info;

		/* Proceed to the end of the list */
		while (current->next != NULL) current = current->next;

		/* Append the new record */
		current->next = new_record;
	}

	return ERV_OK;
}

/* Retrieve address information for the specified interface */
eemo_ifaddr_info* eemo_get_ifaddr_info(const char* interface)
{
	struct ifaddrs* ifaddrs = NULL;
	struct ifaddrs* current = NULL;
	eemo_ifaddr_info* rv = NULL;

	/* Retrieve all interface addresses */
	if (getifaddrs(&ifaddrs) != 0)
	{
		return NULL;
	}

	/* Iterate over the list of addresses */
	for (current = ifaddrs; current != NULL; current = current->ifa_next)
	{
		/* Check if the interface name matches */
		if (!strcmp(current->ifa_name, interface))
		{
			/* Check the family */
			switch (current->ifa_addr->sa_family)
			{
			case AF_INET:
				if (eemo_ifaddr_info_append(&rv, IFADDR_TYPE_V4, current->ifa_addr) != ERV_OK)
				{
					/* Failed to append address information for IPv4 address */
					eemo_ifaddr_info_free(rv);

					return NULL;
				}
				break;
			case AF_INET6:
				if (eemo_ifaddr_info_append(&rv, IFADDR_TYPE_V6, current->ifa_addr) != ERV_OK)
				{
					/* Failed to append address information for IPv6 address */
					eemo_ifaddr_info_free(rv);

					return NULL;
				}
				break;
			default:
				break;
			}
		}
	}

	/* Free up the list of addresses */
	freeifaddrs(ifaddrs);

	/* Return the list of retrieved addresses in string form */
	return rv;
}

/* Clean up address information */
void eemo_ifaddr_info_free(eemo_ifaddr_info* info)
{
	eemo_ifaddr_info* to_delete = NULL;

	while (info != NULL)
	{
		to_delete = info;
		info = info->next;

		to_delete->next = NULL;
		free(to_delete);
	}
}

