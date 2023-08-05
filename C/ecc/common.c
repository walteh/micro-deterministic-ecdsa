//
//  common.c
//
//  Created by walteh on 12/8/22.
//  Copyright © 2022 Walter Scott. All rights reserved.
// ---------------------------------------------------------------------
//  adapted from micro-ecc
//  Copyright © 2015, Kenneth MacKay. BSD 2-clause license
// ---------------------------------------------------------------------

#include "common.h"

void muladd(uECC_word_t a, uECC_word_t b, uECC_word_t *r0, uECC_word_t *r1, uECC_word_t *r2) {
	uECC_dword_t p	 = (uECC_dword_t)a * b;
	uECC_dword_t r01 = ((uECC_dword_t)(*r1) << uECC_WORD_BITS) | *r0;
	r01 += p;
	*r2 += (r01 < p);
	*r1 = r01 >> uECC_WORD_BITS;
	*r0 = (uECC_word_t)r01;
}
