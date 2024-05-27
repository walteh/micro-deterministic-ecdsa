//
//  curve.c
//
//  Created by walteh on 12/8/22.
//  Copyright © 2022 Walter Scott. All rights reserved.
// ---------------------------------------------------------------------
//  adapted from micro-ecc
//  Copyright © 2015, Kenneth MacKay. BSD 2-clause license
// ---------------------------------------------------------------------

#include "curve.h"

void uECC_vli_modMult_fast(uECC_word_t *result, const uECC_word_t *left, const uECC_word_t *right, uECC_Curve curve) {
	uECC_word_t product[2 * uECC_MAX_WORDS];
	uECC_vli_mult(product, left, right, curve->num_words);
	curve->mmod_fast(result, product);
}

void uECC_vli_modSquare_fast(uECC_word_t *result, const uECC_word_t *left, uECC_Curve curve) {
	uECC_word_t product[2 * uECC_MAX_WORDS];
	uECC_vli_square(product, left, curve->num_words);
	curve->mmod_fast(result, product);
}

void uECC_vli_mod_sqrt(uECC_word_t *a, uECC_Curve curve) { curve->mod_sqrt(a, curve); }

void uECC_vli_mmod_fast(uECC_word_t *result, uECC_word_t *product, uECC_Curve curve) {
	curve->mmod_fast(result, product);
}

void mod_sqrt_default(uECC_word_t *a, uECC_Curve curve) {
	bitcount_t i;
	uECC_word_t p1[uECC_MAX_WORDS]		 = {1};
	uECC_word_t l_result[uECC_MAX_WORDS] = {1};
	wordcount_t num_words				 = curve->num_words;

	/* When curve->p == 3 (mod 4), we can compute
	   sqrt(a) = a^((curve->p + 1) / 4) (mod curve->p). */
	uECC_vli_add(p1, curve->p, p1, num_words); /* p1 = curve_p + 1 */
	for (i = uECC_vli_numBits(p1, num_words) - 1; i > 1; --i) {
		uECC_vli_modSquare_fast(l_result, l_result, curve);
		if (uECC_vli_testBit(p1, i)) {
			uECC_vli_modMult_fast(l_result, l_result, a, curve);
		}
	}
	uECC_vli_set(a, l_result, num_words);
}
