/*
 * Copyright (c) 2010-2016 SURFnet bv
 * Copyright (c) 2016 Roland van Rijswijk-Deij
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
 * Compatibility file for endianess functions
 */

#ifndef _ENDIAN_COMPAT_H
#define _ENDIAN_COMPAT_H

#define EEMO_LITTLE_ENDIAN	4321
#define EEMO_BIG_ENDIAN		1234

#ifdef __APPLE__

/* OS X does not provide the BSD/Linux endianess functions, redefine local equivalents */

#include <machine/endian.h>
#include <libkern/OSByteOrder.h>
 
#define htobe16(x) OSSwapHostToBigInt16(x)
#define htole16(x) OSSwapHostToLittleInt16(x)
#define be16toh(x) OSSwapBigToHostInt16(x)
#define le16toh(x) OSSwapLittleToHostInt16(x)
  
#define htobe32(x) OSSwapHostToBigInt32(x)
#define htole32(x) OSSwapHostToLittleInt32(x)
#define be32toh(x) OSSwapBigToHostInt32(x)
#define le32toh(x) OSSwapLittleToHostInt32(x)
   
#define htobe64(x) OSSwapHostToBigInt64(x)
#define htole64(x) OSSwapHostToLittleInt64(x)
#define be64toh(x) OSSwapBigToHostInt64(x)
#define le64toh(x) OSSwapLittleToHostInt64(x)

#if BYTE_ORDER == LITTLE_ENDIAN
#define EEMO_BYTE_ORDER	EEMO_LITTLE_ENDIAN
#else
#define EEMO_BYTE_ORDER EEMO_BIG_ENDIAN
#endif

#elif defined(__FreeBSD__) /* !__APPLE__ */

#include <sys/endian.h>

#if _BYTE_ORDER == _LITTLE_ENDIAN
#define EEMO_BYTE_ORDER EEMO_LITTLE_ENDIAN
#else
#define EEMO_BYTE_ORDER EEMO_BIG_ENDIAN
#endif

#else /* !__FreeBSD__ */

#include <endian.h>

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define EEMO_BYTE_ORDER EEMO_LITTLE_ENDIAN
#else
#define EEMO_BYTE_ORDER EEMO_BIG_ENDIAN
#endif

#endif

#endif /* !_ENDIAN_COMPAT_H */

