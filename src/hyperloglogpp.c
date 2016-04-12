/*
 * This code implements the HyperLogLog++ probabilistic distinct counting algorithm
 * as proposed in [1]. The code is based on work by Salvatore Sanfilippo, the original
 * BSD copyright for that code is reproduced below.
 *
 * This modified version of the code only implements the dense representation of
 * the HyperLogLog++ algorithm and does none of the bit-fiddling, but stores each
 * register in one byte. While this makes storage less efficient, we will not be
 * storing so many counters that this becomes an issue (storage now requires 16KB
 * for one counting vector, as opposed to 12KB for the original implementation).
 *
 * [1] Heule, S., Nunkesser, M., & Hall, A. (2013). HyperLogLog in practice. 
 * In Proceedings of the 16th International Conference on Extending Database 
 * Technology - EDBT ’13 (pp. 683–602). ACM Press. doi:10.1145/2452376.2452456
 */

/*
 * Original code:
 * Copyright (c) 2014, Salvatore Sanfilippo <antirez at gmail dot com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Redis nor the names of its contributors may be used
 *     to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"
#include <stdint.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "hyperloglogpp.h"
#include "endian_compat.h"

/* Endian-neutral MurmurHash2, 64-bit implementation */
static uint64_t murmur2_64(const void* key, const int len, const unsigned int seed) 
{
	const uint64_t	m	= 0xc6a4a7935bd1e995;
	const int	r	= 47;
	uint64_t	h	= seed ^ (len * m);
	const uint8_t*	data	= (const uint8_t*) key;
	const uint8_t*	end	= data + (len - (len & 7));

	while(data != end) 
	{
		uint64_t k;

#if (EEMO_BYTE_ORDER == EEMO_LITTLE_ENDIAN)
		k = *((uint64_t*)data);
#else
		k  = (uint64_t) data[0];
		k |= (uint64_t) data[1] << 8;
		k |= (uint64_t) data[2] << 16;
		k |= (uint64_t) data[3] << 24;
		k |= (uint64_t) data[4] << 32;
		k |= (uint64_t) data[5] << 40;
		k |= (uint64_t) data[6] << 48;
		k |= (uint64_t) data[7] << 56;
#endif /* !EEMO_LITTLE_ENDIAN */

		k *= m;
		k ^= k >> r;
		k *= m;
		h ^= k;
		h *= m;
		data += 8;
	}

	switch(len & 7) 
	{
	case 7: h ^= (uint64_t)data[6] << 48;
	case 6: h ^= (uint64_t)data[5] << 40;
	case 5: h ^= (uint64_t)data[4] << 32;
	case 4: h ^= (uint64_t)data[3] << 24;
	case 3: h ^= (uint64_t)data[2] << 16;
	case 2: h ^= (uint64_t)data[1] << 8;
	case 1: h ^= (uint64_t)data[0];
	        h *= m;
	};

	h ^= h >> r;
	h *= m;
	h ^= h >> r;

	return h;
}

/* 
 * Given an element to add to the HyperLogLog, returns the length
 * of the pattern 000..1 of the element hash. As a side effect 'regp' is
 * set to the register index this element hashes to. 
 */
static int hll_patlen(const unsigned char* elt, const size_t eltsize, long* regp) 
{
	uint64_t	hash	= 0;
	uint64_t	bit	= 0;
	uint64_t	index	= 0;
	int		count	= 0;

	/* 
	 * Count the number of zeroes starting from bit HLL_REGISTERS
	 * (that is a power of two corresponding to the first bit we don't use
	 * as index). The max run can be 64-P+1 bits.
	 *
	 * Note that the final "1" ending the sequence of zeroes must be
	 * included in the count, so if we find "001" the count is 3, and
	 * the smallest count possible is no zeroes at all, just a 1 bit
	 * at the first position, that is a count of 1.
	 *
	 * This may sound like it's inefficient, but actually in the average case
	 * there are high probabilities to find a 1 after a few iterations.
	 */
	hash = murmur2_64(elt, eltsize, 0xadc83b19ULL);

	index = hash & HLL_P_MASK;	/* Register index. */
	
	hash |= ((uint64_t)1<<63);	/* Make sure the loop terminates. */
	
	bit = HLL_REGISTERS;		/* First bit not used to address the register. */
	
	count = 1;			/* Initialized to 1 since we count the "00000...1" pattern. */
	
	while((hash & bit) == 0) 
	{
		count++;
		bit <<= 1;
	}

	*regp = (int) index;
	
	return count;
}

/*
 * Initialize the HyperLogLog++ counting structure
 */
void hll_init(hll_stor registers)
{
	/* Reset all registers to 0 */
	memset(registers, 0, sizeof(hll_stor));
}

/* 
 * 'Add' the specified element; returns 1 if the approximate cardinality
 * of the HyperLogLog++ set has changed.
 */
int hll_add(hll_stor registers, const void* elt, const size_t eltsize) 
{
	uint8_t	oldcount	= 0;
	uint8_t	count		= 0;
	long	index		= 0;

	/* Update the register if this element produced a longer run of zeroes. */
	count = hll_patlen(elt, eltsize, &index);

	assert(index < HLL_REGISTERS);

	oldcount = registers[index];
	
	if (count > oldcount) 
	{
		registers[index] = count;
		return 1;
	}
	else
	{
		return 0;
	}
}

/* 
 * Compute SUM(2^-reg).
 * 
 * PE is an array with a pre-computed table of values 2^-reg indexed by reg.
 * As a side effect the integer pointed by 'ezp' is set to the number
 * of zero registers. 
 */
static double hll_sum(uint8_t* registers, double* PE, int* ezp) 
{
	double	E	= 0.0f;
	int	j	= 0;
	int	ez	= 0;

	for (j = 0; j < HLL_REGISTERS; j++) 
	{
		if (registers[j] == 0) 
		{
			ez++;
			/* Increment E at the end of the loop. */
		} 
		else 
		{
			E += PE[registers[j] & 0x3f]; /* Precomputed 2^(-reg[j]). */
		}
	}

	E += ez; /* Add 2^0 'ez' times. */

	*ezp = ez;
	
	return E;
}

/* 
 * Return the approximated cardinality of the set based on the harmonic
 * mean of the registers values.
 */
uint64_t hll_count(hll_stor registers)
{
	double		m		= HLL_REGISTERS;
	double		E		= 0.0f;
	double		alpha		= 0.7213/(1+1.079/m);
	int		j		= 0;
	int		ez		= 0;			/* Number of registers equal to 0. */

	/* 
	 * Precompute 2^(-reg[j]) in a small table in order to
	 * speedup the computation of SUM(2^-register[0..i]). 
	 */
	static int	initialized	= 0;
	static double	PE[64]		= { 0.0f };

	if (!initialized) 
	{
		PE[0] = 1; /* 2^(-reg[j]) is 1 when m is 0. */

		for (j = 1; j < 64; j++) 
		{
			/* 2^(-reg[j]) is the same as 1/2^reg[j]. */
			PE[j] = 1.0/(1ULL << j);
		}

		initialized = 1;
	}

	/* Compute SUM(2^-register[0..i]). */
	E = hll_sum(registers, PE, &ez);

	/* Multiply the inverse of E for alpha_m * m^2 to have the raw estimate. */
	E = (1/E)*alpha*m*m;

	/*
	 * Use the LINEARCOUNTING algorithm for small cardinalities.
	 * For larger values but up to 72000 HyperLogLog raw approximation is
	 * used since linear counting errors starts to increase. However HyperLogLog
	 * shows a strong bias in the range 2.5*16384 - 72000, so we try to
	 * compensate for it. 
	 */
	if (E < m*2.5 && ez != 0) 
	{
		E = m*log(m/ez); /* LINEARCOUNTING() */
	} 
	else if (m == 16384 && E < 72000) 
	{
		/* We did polynomial regression of the bias for this range, this
		 * way we can compute the bias for a given cardinality and correct
		 * according to it. Only apply the correction for P=14 that's what
		 * we use and the value the correction was verified with. */
		double bias 	=	5.9119*1.0e-18*(E*E*E*E)
					-1.4253*1.0e-12*(E*E*E)+
					1.2940*1.0e-7*(E*E)
					-5.2921*1.0e-3*E+
					83.3216;
		E -= E*(bias/100);
	}

	return (uint64_t) E;
}

