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
