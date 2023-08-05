//
//  secp256k1.h
//
//  Created by walteh on 2023-08-04.
//  Copyright © 2023 Walter Scott. All rights reserved.
// ---------------------------------------------------------------------
//  adapted from micro-ecc
//  Copyright © 2015, Kenneth MacKay. BSD 2-clause license
// ---------------------------------------------------------------------

#ifndef secp256k1_h
#define secp256k1_h

#include "common.h"
#include "curve.h"
#include "vli.h"

static void double_jacobian_secp256k1(uECC_word_t *X1, uECC_word_t *Y1, uECC_word_t *Z1, uECC_Curve curve);
static void x_side_secp256k1(uECC_word_t *result, const uECC_word_t *x, uECC_Curve curve);
static void vli_mmod_fast_secp256k1(uECC_word_t *result, uECC_word_t *product);
static void omega_mult_secp256k1(uECC_word_t *result, const uECC_word_t *right);

#endif /* secp256k1_h */
