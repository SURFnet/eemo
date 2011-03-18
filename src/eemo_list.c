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
 * Linked list handling
 */

#include <stdlib.h>
#include "config.h"
#include "eemo.h"
#include "eemo_list.h"

/* Append a new list entry */
eemo_rv eemo_ll_append(eemo_ll_entry** list, void* elem_data)
{
	eemo_ll_entry* it = NULL;
	eemo_ll_entry* new_entry = NULL;

	/* Check parameter validity */
	if ((list == NULL) || (elem_data == NULL))
	{
		return ERV_PARAM_INVALID;
	}
	
	/* Create new entry */
	new_entry = (eemo_ll_entry*) malloc(sizeof(eemo_ll_entry));

	if (new_entry == NULL)
	{
		return ERV_MEMORY;
	}

	new_entry->elem_data = elem_data;
	new_entry->next = NULL;

	/* Append new entry */
	if (*list == NULL)
	{
		/* This is the first entry in the list */
		*list = new_entry;
	}
	else
	{
		/* Iterate to the end of the list */
		it = *list;

		while (it->next != NULL) it = it->next;

		it->next = new_entry;
	}

	return ERV_OK;
}

/* Remove a list entry */
eemo_rv eemo_ll_remove(eemo_ll_entry** list, eemo_ll_elem_compare_fn compare, void* compare_data)
{
	eemo_ll_entry* it = NULL;
	eemo_ll_entry* prev = NULL;
	eemo_ll_entry* to_delete = NULL;

	/* Check parameters */
	if ((list == NULL) || (compare == NULL) || (compare_data == NULL))
	{
		return ERV_PARAM_INVALID;
	}

	it = *list;

	while (it != NULL)
	{
		if ((compare)(it->elem_data, compare_data))
		{
			/* Delete entry from the list */
			to_delete = it;

			if (prev == NULL)
			{
				*list = it->next;
			}
			else
			{
				prev->next = it->next;
			}

			free(to_delete->elem_data);
			free(to_delete);

			return ERV_OK;
		}

		prev = it;
		it = it->next;
	}

	return ERV_NOT_FOUND;
}

/* Search for a list entry */
eemo_rv eemo_ll_find(const eemo_ll_entry* list, void** found_data, eemo_ll_elem_compare_fn compare, void* compare_data)
{
	const eemo_ll_entry* it = NULL;

	/* Check input parameters */
	if ((found_data == NULL) || (compare == NULL) || (compare_data == NULL))
	{
		return ERV_PARAM_INVALID;
	}

	/* Search for the requested item */
	it = list;

	while (it != NULL)
	{
		if ((compare)(it->elem_data, compare_data))
		{
			*found_data = it->elem_data;

			return ERV_OK;
		}

		it = it->next;
	}

	return ERV_NOT_FOUND;
}

/* Search for multiple list entries */
eemo_rv eemo_ll_find_multi(const eemo_ll_entry* list, eemo_ll_entry** found_data, eemo_ll_elem_compare_fn compare, void* compare_data,
                           eemo_ll_elem_clone_fn clone)
{
	const eemo_ll_entry* it = NULL;
	eemo_ll_entry* result = NULL;

	/* Check input parameters */
	if ((found_data == NULL) || (compare == NULL) || (compare_data == NULL) || (clone == NULL))
	{
		return ERV_PARAM_INVALID;
	}

	/* Search for the requested data */
	it = list;

	while (it != NULL)
	{
		if ((compare)(it->elem_data, compare_data))
		{
			eemo_rv rv = ERV_OK;
			void* new_elem_data = (clone)(it->elem_data);

			if (new_elem_data == NULL)
			{
				eemo_ll_free(&result);

				return ERV_MEMORY;
			}

			if ((rv = eemo_ll_append(&result, new_elem_data)) != ERV_OK)
			{
				eemo_ll_free(&result);

				return rv;
			}
		}

		it = it->next;
	}

	if (result == NULL)
	{
		return ERV_NOT_FOUND;
	}
	else
	{
		*found_data = result;

		return ERV_OK;
	}
}

/* Free the space taken up by a list */
eemo_rv eemo_ll_free(eemo_ll_entry** list)
{
	eemo_ll_entry* it = NULL;
	eemo_ll_entry* to_delete = NULL;

	/* Check input parameters */
	if (list == NULL)
	{
		return ERV_PARAM_INVALID;
	}

	/* Clean up the list */
	it = *list;
	*list = NULL;

	while (it != NULL)
	{
		to_delete = it;
		it = it->next;

		free(to_delete->elem_data);
		free(to_delete);
	}

	return ERV_OK;
}

