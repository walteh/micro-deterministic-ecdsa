//
//  point.h
//
//  Created by walteh on 12/8/22.
//  Copyright © 2022 Walter Scott. All rights reserved.
// ---------------------------------------------------------------------
//  adapted from micro-ecc
//  Copyright © 2015, Kenneth MacKay. BSD 2-clause license
// ---------------------------------------------------------------------

#ifndef point_h
#define point_h

#include "common.h"
#include "curve.h"

/* Returns 1 if 'point' is the point at infinity, 0 otherwise. */
#define EccPoint_isZero(point, curve) uECC_vli_isZero((point), (curve)->num_words * 2)

/* Modify (x1, y1) => (x1 * z^2, y1 * z^3) */
void apply_z(uECC_word_t *X1, uECC_word_t *Y1, const uECC_word_t *const Z, uECC_Curve curve);

/* P = (x1, y1) => 2P, (x2, y2) => P' */
void XYcZ_initial_double(
	uECC_word_t *X1,
	uECC_word_t *Y1,
	uECC_word_t *X2,
	uECC_word_t *Y2,
	const uECC_word_t *const initial_Z,
	uECC_Curve curve
);

/* Input P = (x1, y1, Z), Q = (x2, y2, Z)
 Output P' = (x1', y1', Z3), P + Q = (x3, y3, Z3)
 or P => P', Q => P + Q
 */
void XYcZ_add(uECC_word_t *X1, uECC_word_t *Y1, uECC_word_t *X2, uECC_word_t *Y2, uECC_Curve curve);

/* Input P = (x1, y1, Z), Q = (x2, y2, Z)
 Output P + Q = (x3, y3, Z3), P - Q = (x3', y3', Z3)
 or P => P - Q, Q => P + Q
 */
void XYcZ_addC(uECC_word_t *X1, uECC_word_t *Y1, uECC_word_t *X2, uECC_word_t *Y2, uECC_Curve curve);

/* result may overlap point. */
void EccPoint_mult(
	uECC_word_t *result,
	const uECC_word_t *point,
	const uECC_word_t *scalar,
	const uECC_word_t *initial_Z,
	bitcount_t num_bits,
	uECC_Curve curve
);

uECC_word_t regularize_k(const uECC_word_t *const k, uECC_word_t *k0, uECC_word_t *k1, uECC_Curve curve);

uECC_word_t EccPoint_compute_public_key(uECC_word_t *result, uECC_word_t *private_key, uECC_Curve curve);

void uECC_point_mult(uECC_word_t *result, const uECC_word_t *point, const uECC_word_t *scalar, uECC_Curve curve);

#endif /* point_h */
