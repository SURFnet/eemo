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

#ifndef _HYPERLOGLOGPP_H
#define _HYPERLOGLOGPP_H

#include "config.h"
#include <stdint.h>
#include <stdlib.h>

/* Definitions */
#define HLL_P			14				/* larger p-value implies smaller error */
#define HLL_REGISTERS		(1<<HLL_P)			/* #registers, for p=14 this is 16384 */
#define HLL_P_MASK		(HLL_REGISTERS-1)

typedef uint8_t hll_stor[HLL_REGISTERS];

/*
 * Initialize the HyperLogLog++ counting structure
 */
void hll_init(hll_stor registers);

typedef void (*hll_init_fn)(hll_stor);

/* 
 * 'Add' the specified element; returns 1 if the approximate cardinality
 * of the HyperLogLog++ set has changed.
 */
int hll_add(hll_stor registers, const void* elt, const size_t eltsize);

typedef int (*hll_add_fn)(hll_stor, const void*, const size_t);

/* 
 * Return the approximated cardinality of the set based on the harmonic
 * mean of the register values.
 */
uint64_t hll_count(hll_stor registers);

typedef uint64_t (*hll_count_fn)(hll_stor);

#endif /* !_HYPERLOGLOGPP_H */

