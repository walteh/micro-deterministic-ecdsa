//
//  curve.h
//
//  Created by walteh on 12/8/22.
//  Copyright © 2022 Walter Scott. All rights reserved.
// ---------------------------------------------------------------------
//  adapted from micro-ecc
//  Copyright © 2015, Kenneth MacKay. BSD 2-clause license
// ---------------------------------------------------------------------

#ifndef curve_h
#define curve_h

#include "vli.h"

struct uECC_Curve_t {
	wordcount_t num_words;
	wordcount_t num_bytes;
	bitcount_t num_n_bits;
	uECC_word_t p[uECC_MAX_WORDS];
	uECC_word_t n[uECC_MAX_WORDS];
	uECC_word_t G[uECC_MAX_WORDS * 2];
	uECC_word_t b[uECC_MAX_WORDS];
	void (*double_jacobian)(uECC_word_t *X1, uECC_word_t *Y1, uECC_word_t *Z1, uECC_Curve curve);
	void (*mod_sqrt)(uECC_word_t *a, uECC_Curve curve);
	void (*x_side)(uECC_word_t *result, const uECC_word_t *x, uECC_Curve curve);
	void (*mmod_fast)(uECC_word_t *result, uECC_word_t *product);
};

/* Computes result = left^2 % curve->p. */
void uECC_vli_modSquare_fast(uECC_word_t *result, const uECC_word_t *left, uECC_Curve curve);

void mod_sqrt_default(uECC_word_t *a, uECC_Curve curve);

#endif /* curve_h */
