/*
 * Copyright (c) 2010-2015 SURFnet bv
 * Copyright (c) 2015 Roland van Rijswijk-Deij
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
 * IP metadata functions
 */

#include "config.h"
#include "eemo.h"
#include "eemo_config.h"
#include "eemo_log.h"
#include "ip_metadata.h"
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#ifdef HAVE_SQLITE3
#include <sqlite3.h>

/* Global database handles */
static sqlite3*	asdb_handle	= NULL;
static sqlite3*	geoipdb_handle	= NULL;
#endif /* HAVE_SQLITE3 */

#define ULL_HI(x)	(x>>32)
#define ULL_LO(x)	(x&0xffffffff)

#ifdef HAVE_SQLITE3
static void eemo_md_db_to_mem(sqlite3** db_handle, const char* desc)
{
	assert(db_handle != NULL);
	assert(*db_handle != NULL);

	sqlite3*	new_db_h	= NULL;
	sqlite3_backup*	new_db_bu	= NULL;

	if (sqlite3_open_v2(":memory:", &new_db_h, SQLITE_OPEN_CREATE | SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOMUTEX, NULL) != 0)
	{
		WARNING_MSG("Failed to open in-memory database (%s)", sqlite3_errmsg(new_db_h));
		
		return;
	}
	
	/* Now copy the tables from the metadata database into memory */
	if ((new_db_bu = sqlite3_backup_init(new_db_h, "main", *db_handle, "main")) == NULL)
	{
		ERROR_MSG("Failed to initiate in-memory restore of the %s database (%s)", desc, sqlite3_errmsg(new_db_h));

		sqlite3_close(new_db_h);

		return;
	}

	if (sqlite3_backup_step(new_db_bu, -1) != SQLITE_DONE)
	{
		ERROR_MSG("Failed to load the %s database into memory during backup (%s)", desc, sqlite3_errmsg(new_db_h));

		sqlite3_close(new_db_h);

		return;
	}

	sqlite3_backup_finish(new_db_bu);

	/* Close the on-disk database handle */
	sqlite3_close(*db_handle);

	*db_handle = new_db_h;

	INFO_MSG("Loaded a copy of the %s database into memory", desc);
}
#endif /* HAVE_SQLITE3 */

/* Initialise metadata module */
eemo_rv eemo_md_init(void)
{
	char*	as_db_name	= NULL;
	char*	geoip_db_name	= NULL;

	if (eemo_conf_get_string("metadata", "asdb", &as_db_name, NULL) != ERV_OK)
	{
		ERROR_MSG("Failed to get database name for IP-to-AS database from the configuration");

		return ERV_CONFIG_ERROR;
	}

	if (eemo_conf_get_string("metadata", "geoipdb", &geoip_db_name, NULL) != ERV_OK)
	{
		ERROR_MSG("Failed to get database name for the Geo IP database from the configuration");

		return ERV_CONFIG_ERROR;
	}

#ifdef HAVE_SQLITE3
	if (as_db_name != NULL)
	{
		if (sqlite3_open_v2(as_db_name, &asdb_handle, SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX, NULL) != 0)
		{
			asdb_handle = NULL;

			ERROR_MSG("Failed to open IP-to-AS database %s", as_db_name);
		}
		else
		{
			INFO_MSG("Loaded IP-to-AS database %s", as_db_name);

			/* Attempt to load it into memory */
			eemo_md_db_to_mem(&asdb_handle, "IP-to-AS");
		}
	}

	if (geoip_db_name != NULL)
	{
		if (sqlite3_open_v2(geoip_db_name, &geoipdb_handle, SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX, NULL) != 0)
		{
			geoipdb_handle = NULL;

			ERROR_MSG("Failed to open Geo IP database %s", geoip_db_name);
		}
		else
		{
			INFO_MSG("Loaded Geo IP database %s", geoip_db_name);

			/* Attempt to load it into memory */
			eemo_md_db_to_mem(&asdb_handle, "Geo IP");
		}
	}
#else /* !HAVE_SQLITE3 */
	if (as_db_name != NULL)
	{
		WARNING_MSG("IP-to-AS database configured but eemo was compiled without SQLite3 support; please consider recompiling and re-installing eemo with SQLite3 support enabled");
	}

	if (geoip_db_name != NULL)
	{
		WARNING_MSG("GeoIP database configured but eemo was compiled without SQLite3 support; please consider recompiling and re-installing eemo with SQLite3 support enabled");
	}
#endif

	free(as_db_name);
	free(geoip_db_name);

	INFO_MSG("Initialised IP metadata module");

	return ERV_OK;
}

/* Uninitialise metadata module */
eemo_rv eemo_md_finalize(void)
{
#ifdef HAVE_SQLITE3
	if (asdb_handle != NULL)
	{
		sqlite3_close(asdb_handle);
	}

	if (geoipdb_handle != NULL)
	{
		sqlite3_close(geoipdb_handle);
	}
#endif /* HAVE_SQLITE3 */

	INFO_MSG("Uninitialised IP metadata module");

	return ERV_OK;
}

#ifdef HAVE_SQLITE3
/* Convert an IPv4 address to an integer */
static void v4_to_uint(struct in_addr* addr, unsigned int* uint_val)
{
	assert(uint_val != NULL);

	unsigned int*	addr_uint_p	= (unsigned int*) addr;
	
	*uint_val = ntohl(*addr_uint_p);
}

/* Convert an IPv6 address to two 64-bit integers */
static void v6_to_ull(struct in6_addr* addr, unsigned long long* hi_val, unsigned long long* lo_val)
{
	assert(hi_val != NULL);
	assert(lo_val != NULL);

	unsigned char*	addr_buf	= (unsigned char*) addr;
	int		i		= 0;

	*hi_val = 0;
	*lo_val = 0;

	/* Convert 128-bit IPv6 address to local byte order */
	for (i = 0; i < 8; i++)
	{
		*hi_val <<= 8;
		*hi_val += addr_buf[i];

		*lo_val <<= 8;
		*lo_val += addr_buf[i + 8];
	}
}

typedef struct ip2as_cb_rv
{
	char**	AS;
	char**	AS_full;
	int	sel_count;
}
ip2as_cb_rv;

static int ip2as_lookup_cb(void* data, int argc, char* argv[], char* colname[])
{
	assert(data != NULL);
	assert(argc == 3);

	ip2as_cb_rv* rv = (ip2as_cb_rv*) data;

	if (rv->sel_count > 0)
	{
		rv->sel_count++;

		return 0;
	}

	*(rv->AS) = strdup(argv[0]);
	*(rv->AS_full) = strdup(argv[1]);

	rv->sel_count++;

	return 0;
}

typedef struct geoip_cb_rv
{
	char**	country;
	int	sel_count;
}
geoip_cb_rv;

static int i2l_lookup_cb(void* data, int argc, char* argv[], char* colname[])
{
	assert(data != NULL);
	assert(argc == 1);

	geoip_cb_rv* rv = (geoip_cb_rv*) data;

	if (rv->sel_count == 0)
	{
		*(rv->country) = strdup(argv[0]);
	}

	rv->sel_count++;

	return 0;
}
#endif /* HAVE_SQLITE3 */

/* Look up the AS for an IPv4 address */
eemo_rv eemo_md_lookup_as_v4(struct in_addr* addr, char** AS_short, char** AS_full)
{
#ifdef HAVE_SQLITE3
	assert(AS_full != NULL);
	assert(AS_short != NULL);

	unsigned int		addr_uint	= 0;
	char*			sql		= NULL;
	char*			errmsg		= NULL;
	char			sql_buf[4096]	= { 0 };
	ip2as_cb_rv		sel_rv		= { AS_short, AS_full, 0 };

	/* Exit early if we have no open database */
	if (asdb_handle == NULL)
	{
		*AS_short = NULL;
		*AS_full = NULL;

		return ERV_OK;
	}

	v4_to_uint(addr, &addr_uint);

	sql =	"SELECT as_single,as_full,prefix FROM (SELECT * FROM IP4_TO_AS WHERE from_ip <= %u ORDER BY from_ip DESC,prefix DESC LIMIT 1) WHERE to_ip >= %u;";

	snprintf(sql_buf, 4096, sql, addr_uint, addr_uint);

	if (sqlite3_exec(asdb_handle, sql_buf, ip2as_lookup_cb, (void*) &sel_rv, &errmsg) != 0)
	{
		ERROR_MSG("Failed to look up IPv4 address in the database (%s) (%s)\n", errmsg, sql_buf);

		sqlite3_free(errmsg);

		return ERV_MDDB_ERROR;
	}

	if (sel_rv.sel_count == 0)
	{
		/* 
		 * Retry without limiting the first subquery to 1 result; because the
		 * IP-to-AS data sometimes has rows with enclosing IP ranges this is
		 * necessary; we first try limiting to 5, as that is more efficient,
		 * if that does not work we drop the limit altogether.
		 */
		sql =	"SELECT as_single,as_full,prefix FROM (SELECT * FROM IP4_TO_AS WHERE from_ip <= %u ORDER BY from_ip DESC,prefix DESC LIMIT 5) WHERE to_ip >= %u LIMIT 1;";
	
		snprintf(sql_buf, 4096, sql, addr_uint, addr_uint);
	
		if (sqlite3_exec(asdb_handle, sql_buf, ip2as_lookup_cb, (void*) &sel_rv, &errmsg) != 0)
		{
			ERROR_MSG("Failed to look up IPv4 address in the database (%s) (%s)\n", errmsg, sql_buf);
	
			sqlite3_free(errmsg);
	
			return ERV_MDDB_ERROR;
		}

		if (sel_rv.sel_count == 0)
		{
			sql =	"SELECT as_single,as_full,prefix FROM (SELECT * FROM IP4_TO_AS WHERE from_ip <= %u ORDER BY from_ip DESC,prefix DESC) WHERE to_ip >= %u LIMIT 1;";
		
			snprintf(sql_buf, 4096, sql, addr_uint, addr_uint);
		
			if (sqlite3_exec(asdb_handle, sql_buf, ip2as_lookup_cb, (void*) &sel_rv, &errmsg) != 0)
			{
				ERROR_MSG("Failed to look up IPv4 address in the database (%s) (%s)\n", errmsg, sql_buf);
		
				sqlite3_free(errmsg);
		
				return ERV_MDDB_ERROR;
			}
		}
	}

	if (sel_rv.sel_count != 1)
	{
		DEBUG_MSG("Found an unexpected number of matches in the database (%d)\n", sel_rv.sel_count);
	}
#endif /* HAVE_SQLITE3 */

	return ERV_OK;
}

/* Look up the AS for an IPv6 address */
eemo_rv eemo_md_lookup_as_v6(struct in6_addr* addr, char** AS_short, char** AS_full)
{
#ifdef HAVE_SQLITE3
	assert(AS_full != NULL);
	assert(AS_short != NULL);

	unsigned long long	addr_hi		= 0;
	unsigned long long	addr_lo		= 0;
	char*			sql		= NULL;
	char*			errmsg		= NULL;
	char			sql_buf[4096]	= { 0 };
	ip2as_cb_rv		sel_rv		= { AS_short, AS_full, 0 };

	/* Exit early if we have no open database */
	if (asdb_handle == NULL)
	{
		*AS_short = NULL;
		*AS_full = NULL;

		return ERV_OK;
	}

	v6_to_ull(addr, &addr_hi, &addr_lo);

	sql =	"SELECT as_single,as_full,prefix FROM (SELECT * FROM IP6_TO_AS WHERE from_i4 <= %u AND from_i3 <= %u AND from_i2 <= %u AND from_i1 <= %u ORDER BY from_i4 DESC,from_i3 DESC,from_i2 DESC,from_i1 DESC,prefix DESC LIMIT 1) WHERE to_i4 >= %u AND to_i3 >= %u AND to_i2 >= %u AND to_i1 >= %u;";

	snprintf(sql_buf, 4096, sql, ULL_HI(addr_hi), ULL_LO(addr_hi), ULL_HI(addr_lo), ULL_LO(addr_lo), ULL_HI(addr_hi), ULL_LO(addr_hi), ULL_HI(addr_lo), ULL_LO(addr_lo));

	if (sqlite3_exec(asdb_handle, sql_buf, ip2as_lookup_cb, (void*) &sel_rv, &errmsg) != 0)
	{
		ERROR_MSG("Failed to look up IPv6 address in the database (%s) (%s)\n", errmsg, sql_buf);

		sqlite3_free(errmsg);

		return ERV_MDDB_ERROR;
	}

	if (sel_rv.sel_count == 0)
	{
		/* 
		 * Retry without limiting the first subquery to 1 result; because the
		 * IP-to-AS data sometimes has rows with enclosing IP ranges this is
		 * necessary; we first try limiting to 5, as that is more efficient,
		 * if that does not work we drop the limit altogether.
		 */
		sql =	"SELECT as_single,as_full,prefix FROM (SELECT * FROM IP6_TO_AS WHERE from_i4 <= %u AND from_i3 <= %u AND from_i2 <= %u AND from_i1 <= %u ORDER BY from_i4 DESC,from_i3 DESC,from_i2 DESC,from_i1 DESC,prefix DESC LIMIT 5) WHERE to_i4 >= %u AND to_i3 >= %u AND to_i2 >= %u AND to_i1 >= %u LIMIT 1;";
	
		snprintf(sql_buf, 4096, sql, ULL_HI(addr_hi), ULL_LO(addr_hi), ULL_HI(addr_lo), ULL_LO(addr_lo), ULL_HI(addr_hi), ULL_LO(addr_hi), ULL_HI(addr_lo), ULL_LO(addr_lo));
	
		if (sqlite3_exec(asdb_handle, sql_buf, ip2as_lookup_cb, (void*) &sel_rv, &errmsg) != 0)
		{
			ERROR_MSG("Failed to look up IPv6 address in the database (%s) (%s)\n", errmsg, sql_buf);
	
			sqlite3_free(errmsg);
	
			return ERV_MDDB_ERROR;
		}	

		if (sel_rv.sel_count == 0)
		{
			sql =	"SELECT as_single,as_full,prefix FROM (SELECT * FROM IP6_TO_AS WHERE from_i4 <= %u AND from_i3 <= %u AND from_i2 <= %u AND from_i1 <= %u ORDER BY from_i4 DESC,from_i3 DESC,from_i2 DESC,from_i1 DESC,prefix DESC) WHERE to_i4 >= %u AND to_i3 >= %u AND to_i2 >= %u AND to_i1 >= %u LIMIT 1;";
		
			snprintf(sql_buf, 4096, sql, ULL_HI(addr_hi), ULL_LO(addr_hi), ULL_HI(addr_lo), ULL_LO(addr_lo), ULL_HI(addr_hi), ULL_LO(addr_hi), ULL_HI(addr_lo), ULL_LO(addr_lo));
		
			if (sqlite3_exec(asdb_handle, sql_buf, ip2as_lookup_cb, (void*) &sel_rv, &errmsg) != 0)
			{
				ERROR_MSG("Failed to look up IPv6 address in the database (%s) (%s)\n", errmsg, sql_buf);
		
				sqlite3_free(errmsg);
		
				return ERV_MDDB_ERROR;
			}	
		}
	}

	if (sel_rv.sel_count != 1)
	{
		DEBUG_MSG("Found an unexpected number of matches in the database (%d)\n", sel_rv.sel_count);
	}
#endif /* HAVE_SQLITE3 */

	return ERV_OK;
}

/* Look up Geo IP for an IPv4 address */
eemo_rv eemo_md_lookup_geoip_v4(struct in_addr* addr, char** country)
{
#ifdef HAVE_SQLITE3
	assert(addr != NULL);
	assert(country != NULL);

	char*		sql		= NULL;
	char*		errmsg		= NULL;
	char		sql_buf[4096]	= { 0 };
	geoip_cb_rv	sel_rv		= { country, 0 };
	unsigned int	addr_uint	= 0;

	/* Exit early if we have no open database */
	if (geoipdb_handle == NULL)
	{
		*country = NULL;

		return ERV_OK;
	}

	v4_to_uint(addr, &addr_uint);

	sql = "SELECT country FROM (SELECT * FROM IP4_TO_LOCATION WHERE from_ip <= %u ORDER BY from_ip DESC LIMIT 1) WHERE to_ip >= %u;";

	snprintf(sql_buf, 4096, sql, addr_uint, addr_uint);

	if (sqlite3_exec(geoipdb_handle, sql_buf, i2l_lookup_cb, (void*) &sel_rv, &errmsg) != 0)
	{
		ERROR_MSG("Failed to look up IPv4 address in the database (%s)\n", errmsg);

		sqlite3_free(errmsg);

		return ERV_MDDB_ERROR;
	}

	if (sel_rv.sel_count != 1)
	{
		DEBUG_MSG("Found an unexpected number of matches in the database (%d)\n", sel_rv.sel_count);
	}
#endif /* HAVE_SQLITE3 */

	return ERV_OK;
}

/* Look up Geo IP for an IPv6 address */
eemo_rv eemo_md_lookup_geoip_v6(struct in6_addr* addr, char** country)
{
#ifdef HAVE_SQLITE3
	assert(country != NULL);
	assert(addr != NULL);

	unsigned long long	addr_hi		= 0;
	unsigned long long	addr_lo		= 0;
	char*			sql		= NULL;
	char*			errmsg		= NULL;
	char			sql_buf[4096]	= { 0 };
	geoip_cb_rv		sel_rv		= { country, 0 };
	
	/* Exit early if we have no open database */
	if (geoipdb_handle == NULL)
	{
		return ERV_OK;
	}

	v6_to_ull(addr, &addr_hi, &addr_lo);

	sql =	"SELECT country FROM (SELECT * FROM IP6_TO_LOCATION WHERE from_i4 <= %u AND from_i3 <= %u AND from_i2 <= %u AND from_i1 <= %u ORDER BY from_i4 DESC,from_i3 DESC,from_i2 DESC,from_i1 DESC LIMIT 1) WHERE to_i4 >= %u AND to_i3 >= %u AND to_i2 >= %u AND to_i1 >= %u;";

	snprintf(sql_buf, 4096, sql, ULL_HI(addr_hi), ULL_LO(addr_hi), ULL_HI(addr_lo), ULL_LO(addr_lo), ULL_HI(addr_hi), ULL_LO(addr_hi), ULL_HI(addr_lo), ULL_LO(addr_lo));

	if (sqlite3_exec(geoipdb_handle, sql_buf, i2l_lookup_cb, (void*) &sel_rv, &errmsg) != 0)
	{
		ERROR_MSG("Failed to look up IPv6 address in the database (%s)\n", errmsg);

		sqlite3_free(errmsg);

		return ERV_MDDB_ERROR;
	}

	if (sel_rv.sel_count != 1)
	{
		DEBUG_MSG("Found an unexpected number of matches in the database (%d)\n", sel_rv.sel_count);

		return ERV_MDDB_ERROR;
	}
#endif /* HAVE_SQLITE3 */

	return ERV_OK;
}

