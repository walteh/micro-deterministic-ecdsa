//
//  secp256k1.c
//
//  Created by walteh on 2023-08-04.
//  Copyright © 2023 Walter Scott. All rights reserved.
// ---------------------------------------------------------------------
//  adapted from micro-ecc
//  Copyright © 2015, Kenneth MacKay. BSD 2-clause license
// ---------------------------------------------------------------------

#if uECC_SUPPORTS_secp256k1

static const struct uECC_Curve_t curve_secp256k1 = {
	num_words_secp256k1,
	num_bytes_secp256k1,
	256, /* num_n_bits */
	{BYTES_TO_WORDS_8(2F, FC, FF, FF, FE, FF, FF, FF),
	 BYTES_TO_WORDS_8(FF, FF, FF, FF, FF, FF, FF, FF),
	 BYTES_TO_WORDS_8(FF, FF, FF, FF, FF, FF, FF, FF),
	 BYTES_TO_WORDS_8(FF, FF, FF, FF, FF, FF, FF, FF)},
	{BYTES_TO_WORDS_8(41, 41, 36, D0, 8C, 5E, D2, BF),
	 BYTES_TO_WORDS_8(3B, A0, 48, AF, E6, DC, AE, BA),
	 BYTES_TO_WORDS_8(FE, FF, FF, FF, FF, FF, FF, FF),
	 BYTES_TO_WORDS_8(FF, FF, FF, FF, FF, FF, FF, FF)},
	{BYTES_TO_WORDS_8(98, 17, F8, 16, 5B, 81, F2, 59),
	 BYTES_TO_WORDS_8(D9, 28, CE, 2D, DB, FC, 9B, 02),
	 BYTES_TO_WORDS_8(07, 0B, 87, CE, 95, 62, A0, 55),
	 BYTES_TO_WORDS_8(AC, BB, DC, F9, 7E, 66, BE, 79),

	 BYTES_TO_WORDS_8(B8, D4, 10, FB, 8F, D0, 47, 9C),
	 BYTES_TO_WORDS_8(19, 54, 85, A6, 48, B4, 17, FD),
	 BYTES_TO_WORDS_8(A8, 08, 11, 0E, FC, FB, A4, 5D),
	 BYTES_TO_WORDS_8(65, C4, A3, 26, 77, DA, 3A, 48)},
	{BYTES_TO_WORDS_8(07, 00, 00, 00, 00, 00, 00, 00),
	 BYTES_TO_WORDS_8(00, 00, 00, 00, 00, 00, 00, 00),
	 BYTES_TO_WORDS_8(00, 00, 00, 00, 00, 00, 00, 00),
	 BYTES_TO_WORDS_8(00, 00, 00, 00, 00, 00, 00, 00)},
	&double_jacobian_secp256k1,
	&mod_sqrt_default,
	&x_side_secp256k1,
	&vli_mmod_fast_secp256k1};

uECC_Curve uECC_secp256k1(void) { return &curve_secp256k1; }

/* Compute a = sqrt(a) (mod curve_p). */
static void mod_sqrt_default(uECC_word_t *a, uECC_Curve curve) {
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
#endif /* uECC_SUPPORTS_secp... */

#if uECC_SUPPORTS_secp256k1

static void double_jacobian_secp256k1(uECC_word_t *X1, uECC_word_t *Y1, uECC_word_t *Z1, uECC_Curve curve);
static void x_side_secp256k1(uECC_word_t *result, const uECC_word_t *x, uECC_Curve curve);
#if (uECC_OPTIMIZATION_LEVEL > 0)
static void vli_mmod_fast_secp256k1(uECC_word_t *result, uECC_word_t *product);
#endif

/* Double in place */
static void double_jacobian_secp256k1(uECC_word_t *X1, uECC_word_t *Y1, uECC_word_t *Z1, uECC_Curve curve) {
	/* t1 = X, t2 = Y, t3 = Z */
	uECC_word_t t4[num_words_secp256k1];
	uECC_word_t t5[num_words_secp256k1];

	if (uECC_vli_isZero(Z1, num_words_secp256k1)) {
		return;
	}

	uECC_vli_modSquare_fast(t5, Y1, curve);	  /* t5 = y1^2 */
	uECC_vli_modMult_fast(t4, X1, t5, curve); /* t4 = x1*y1^2 = A */
	uECC_vli_modSquare_fast(X1, X1, curve);	  /* t1 = x1^2 */
	uECC_vli_modSquare_fast(t5, t5, curve);	  /* t5 = y1^4 */
	uECC_vli_modMult_fast(Z1, Y1, Z1, curve); /* t3 = y1*z1 = z3 */

	uECC_vli_modAdd(Y1, X1, X1, curve->p, num_words_secp256k1); /* t2 = 2*x1^2 */
	uECC_vli_modAdd(Y1, Y1, X1, curve->p, num_words_secp256k1); /* t2 = 3*x1^2 */
	if (uECC_vli_testBit(Y1, 0)) {
		uECC_word_t carry = uECC_vli_add(Y1, Y1, curve->p, num_words_secp256k1);
		uECC_vli_rshift1(Y1, num_words_secp256k1);
		Y1[num_words_secp256k1 - 1] |= carry << (uECC_WORD_BITS - 1);
	} else {
		uECC_vli_rshift1(Y1, num_words_secp256k1);
	}
	/* t2 = 3/2*(x1^2) = B */

	uECC_vli_modSquare_fast(X1, Y1, curve);						/* t1 = B^2 */
	uECC_vli_modSub(X1, X1, t4, curve->p, num_words_secp256k1); /* t1 = B^2 - A */
	uECC_vli_modSub(X1, X1, t4, curve->p, num_words_secp256k1); /* t1 = B^2 - 2A = x3 */

	uECC_vli_modSub(t4, t4, X1, curve->p, num_words_secp256k1); /* t4 = A - x3 */
	uECC_vli_modMult_fast(Y1, Y1, t4, curve);					/* t2 = B * (A - x3) */
	uECC_vli_modSub(Y1, Y1, t5, curve->p, num_words_secp256k1); /* t2 = B * (A - x3) - y1^4 = y3 */
}

/* Computes result = x^3 + b. result must not overlap x. */
static void x_side_secp256k1(uECC_word_t *result, const uECC_word_t *x, uECC_Curve curve) {
	uECC_vli_modSquare_fast(result, x, curve);								  /* r = x^2 */
	uECC_vli_modMult_fast(result, result, x, curve);						  /* r = x^3 */
	uECC_vli_modAdd(result, result, curve->b, curve->p, num_words_secp256k1); /* r = x^3 + b */
}

#if (uECC_OPTIMIZATION_LEVEL > 0 && !asm_mmod_fast_secp256k1)
static void omega_mult_secp256k1(uECC_word_t *result, const uECC_word_t *right);
static void vli_mmod_fast_secp256k1(uECC_word_t *result, uECC_word_t *product) {
	uECC_word_t tmp[2 * num_words_secp256k1];
	uECC_word_t carry;

	uECC_vli_clear(tmp, num_words_secp256k1);
	uECC_vli_clear(tmp + num_words_secp256k1, num_words_secp256k1);

	omega_mult_secp256k1(tmp, product + num_words_secp256k1); /* (Rq, q) = q * c */

	carry = uECC_vli_add(result, product, tmp, num_words_secp256k1); /* (C, r) = r + q       */
	uECC_vli_clear(product, num_words_secp256k1);
	omega_mult_secp256k1(product, tmp + num_words_secp256k1);			 /* Rq*c */
	carry += uECC_vli_add(result, result, product, num_words_secp256k1); /* (C1, r) = r + Rq*c */

	while (carry > 0) {
		--carry;
		uECC_vli_sub(result, result, curve_secp256k1.p, num_words_secp256k1);
	}
	if (uECC_vli_cmp_unsafe(result, curve_secp256k1.p, num_words_secp256k1) > 0) {
		uECC_vli_sub(result, result, curve_secp256k1.p, num_words_secp256k1);
	}
}

static void omega_mult_secp256k1(uint64_t *result, const uint64_t *right) {
	uECC_word_t r0 = 0;
	uECC_word_t r1 = 0;
	uECC_word_t r2 = 0;
	wordcount_t k;

	/* Multiply by (2^32 + 2^9 + 2^8 + 2^7 + 2^6 + 2^4 + 1). */
	for (k = 0; k < num_words_secp256k1; ++k) {
		muladd(0x1000003D1ull, right[k], &r0, &r1, &r2);
		result[k] = r0;
		r0		  = r1;
		r1		  = r2;
		r2		  = 0;
	}
	result[num_words_secp256k1] = r0;
}

#endif /* (uECC_OPTIMIZATION_LEVEL > 0 &&  && !asm_mmod_fast_secp256k1) */

#endif /* uECC_SUPPORTS_secp256k1 */
// #endif /* curve_h */
