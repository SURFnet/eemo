/*
 * Copyright (c) 2010-2018 SURFnet bv
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
 * InfluxDB DNS statistics item manager
 */

#ifndef _DNSINFLUX_ITEMMGR_H
#define _DNSINFLUX_ITEMMGR_H

#include "config.h"
#include <time.h>
#include <stdlib.h>
#include "eemo.h"
#include "eemo_api.h"
#include "eemo_plugin_log.h"

/* Initialise the item manager */
eemo_rv dnsinflux_itemmgr_init(const char* influx_file, const char* influx_cmd, const char* stats_file, const int stats_interval, const char* hostname);

/* Uninitialise the item manager */
eemo_rv dnsinflux_itemmgr_finalise(void);

/* Add a new local statistics item */
eemo_rv dnsinflux_add_localstat(const char* item_name, const int is_absolute, const int reset_on_flush);

/* Add a new remote statistics item */
eemo_rv dnsinflux_add_remotestat(const char* item_name, const int is_absolute, const int reset_on_flush);

/* Add a local average item */
eemo_rv dnsinflux_add_localavg(const char* item_name, const char* left_item, const char* right_item);

/* Add a remote average item */
eemo_rv dnsinflux_add_remoteavg(const char* item_name, const char* left_item, const char* right_item);

/* Flush local stats */
eemo_rv dnsinflux_flush_localstats(const time_t ts);

/* Flush remote stats */
eemo_rv dnsinflux_flush_remotestats(const time_t ts);

/* Increment value of local stat */
void dnsinflux_inc_localstat(const char* item_name);

/* Increment value of remote stat */
void dnsinflux_inc_remotestat(const char* item_name);

/* Add to value of local stat */
void dnsinflux_addto_localstat(const char* item_name, const unsigned long long to_add);

/* Add to value of remote stat */
void dnsinflux_addto_remotestat(const char* item_name, const unsigned long long to_add);

/* Retrieve value of a local stat */
unsigned long long dnsinflux_get_localstat(const char* item_name);

/* Set the value of a local stat */
void dnsinflux_set_localstat(const char* item_name, const unsigned long long value);

/* Retrieve the value of a remote stat */
unsigned long long dnsinflux_get_remotestat(const char* item_name);

/* Set the value of a remote stat */
void dnsinflux_set_remotestat(const char* item_name, const unsigned long long value);

#endif /* !_DNSINFLUX_ITEMMGR_H */

