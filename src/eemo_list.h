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

#ifndef _EEMO_LIST_H
#define _EEMO_LIST_H

#include "config.h"
#include "eemo.h"

typedef struct eemo_ll_entry
{
	void*			elem_data;	/* element data */
	struct eemo_ll_entry*	next;		/* next list entry */
}
eemo_ll_entry;

/* Element comparison function */
typedef int (*eemo_ll_elem_compare_fn) (void* /*elem_data*/, void* /*compare_data*/);

/* Element clone function */
typedef void* (*eemo_ll_elem_clone_fn) (const void* /*elem_data*/);

/* Append a new list entry */
eemo_rv eemo_ll_append(eemo_ll_entry** list, void* elem_data);

/* Remove a list entry */
eemo_rv eemo_ll_remove(eemo_ll_entry** list, eemo_ll_elem_compare_fn compare, void* compare_data);

/* Search for a list entry */
eemo_rv eemo_ll_find(const eemo_ll_entry* list, void** found_data, eemo_ll_elem_compare_fn compare, void* compare_data);

/* Search for multiple list entries */
eemo_rv eemo_ll_find_multi(const eemo_ll_entry* list, eemo_ll_entry** found_data, eemo_ll_elem_compare_fn compare, void* compare_data,
                           eemo_ll_elem_clone_fn clone);

/* Free the space taken up by a list */
eemo_rv eemo_ll_free(eemo_ll_entry** list);

#endif /* !_EEMO_LIST_H */

