/*
 * This code implements the HyperLogLog++ probabilistic distinct counting algorithm
 * as proposed in [1]. The code is based on work by Salvatore Sanfilippo, the original
 * BSD copyright for that code is reproduced below.
 *
 * This modified version of the code only implements the dense representation of
 * the HyperLogLog++ algorithm 
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
#include "hyperloglogpp.h"
#include "endian_compat.h"

/* Macros for low-level bit access */

/* Store the value of the register at position 'regnum' into variable 'target'.
 * 'p' is an array of unsigned bytes. */
#define HLL_DENSE_GET_REGISTER(target,p,regnum) do { \
	uint8_t *_p = (uint8_t*) p; \
	unsigned long _byte = regnum*HLL_BITS/8; \
	unsigned long _fb = regnum*HLL_BITS&7; \
	unsigned long _fb8 = 8 - _fb; \
	unsigned long b0 = _p[_byte]; \
	unsigned long b1 = _p[_byte+1]; \
	target = ((b0 >> _fb) | (b1 << _fb8)) & HLL_REGISTER_MAX; \
} while(0)

/* Set the value of the register at position 'regnum' to 'val'.
 * 'p' is an array of unsigned bytes. */
#define HLL_DENSE_SET_REGISTER(p,regnum,val) do { \
	uint8_t *_p = (uint8_t*) p; \
	unsigned long _byte = regnum*HLL_BITS/8; \
	unsigned long _fb = regnum*HLL_BITS&7; \
	unsigned long _fb8 = 8 - _fb; \
	unsigned long _v = val; \
	_p[_byte] &= ~(HLL_REGISTER_MAX << _fb); \
	_p[_byte] |= _v << _fb; \
	_p[_byte+1] &= ~(HLL_REGISTER_MAX >> _fb8); \
	_p[_byte+1] |= _v >> _fb8; \
} while(0)

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

	HLL_DENSE_GET_REGISTER(oldcount, registers, index);
	
	if (count > oldcount) 
	{
		HLL_DENSE_SET_REGISTER(registers, index, count);
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

	/* 
	 * If the default configuration is used (16384 registers with 6 bits each),
	 * the code below is faster because of unrolled loops.
	 */
	if ((HLL_REGISTERS == 16384) && (HLL_BITS == 6)) 
	{
		uint8_t*	r	= registers;
		unsigned long 	r0	= 0;
		unsigned long	r1	= 0;
		unsigned long	r2	= 0;
		unsigned long	r3	= 0;
		unsigned long	r4	= 0;
		unsigned long	r5	= 0;
		unsigned long	r6	= 0;
		unsigned long	r7	= 0;
		unsigned long	r8	= 0;
		unsigned long	r9	= 0;
		unsigned long	r10	= 0;
		unsigned long	r11	= 0;
		unsigned long	r12	= 0;
		unsigned long	r13	= 0;
		unsigned long	r14	= 0;
		unsigned long	r15	= 0;

		for (j = 0; j < 1024; j++)
		{
			/* Handle 16 registers per iteration. */
			r0 = r[0] & 63; if (r0 == 0) ez++;
			r1 = (r[0] >> 6 | r[1] << 2) & 63; if (r1 == 0) ez++;
			r2 = (r[1] >> 4 | r[2] << 4) & 63; if (r2 == 0) ez++;
			r3 = (r[2] >> 2) & 63; if (r3 == 0) ez++;
			r4 = r[3] & 63; if (r4 == 0) ez++;
			r5 = (r[3] >> 6 | r[4] << 2) & 63; if (r5 == 0) ez++;
			r6 = (r[4] >> 4 | r[5] << 4) & 63; if (r6 == 0) ez++;
			r7 = (r[5] >> 2) & 63; if (r7 == 0) ez++;
			r8 = r[6] & 63; if (r8 == 0) ez++;
			r9 = (r[6] >> 6 | r[7] << 2) & 63; if (r9 == 0) ez++;
			r10 = (r[7] >> 4 | r[8] << 4) & 63; if (r10 == 0) ez++;
			r11 = (r[8] >> 2) & 63; if (r11 == 0) ez++;
			r12 = r[9] & 63; if (r12 == 0) ez++;
			r13 = (r[9] >> 6 | r[10] << 2) & 63; if (r13 == 0) ez++;
			r14 = (r[10] >> 4 | r[11] << 4) & 63; if (r14 == 0) ez++;
			r15 = (r[11] >> 2) & 63; if (r15 == 0) ez++;

			E += (PE[r0] + PE[r1]) + (PE[r2] + PE[r3]) + (PE[r4] + PE[r5]) +
			     (PE[r6] + PE[r7]) + (PE[r8] + PE[r9]) + (PE[r10] + PE[r11]) +
			     (PE[r12] + PE[r13]) + (PE[r14] + PE[r15]);

			r += 12;
		}
	} 
	else 
	{
		for (j = 0; j < HLL_REGISTERS; j++) 
		{
			unsigned long	reg	= 0;

			HLL_DENSE_GET_REGISTER(reg, registers, j);

			if (reg == 0) 
			{
				ez++;
				/* Increment E at the end of the loop. */
			} 
			else 
			{
				E += PE[reg]; /* Precomputed 2^(-reg[j]). */
			}
		}

		E += ez; /* Add 2^0 'ez' times. */
	}

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

