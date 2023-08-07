//
//  scalar.h
//
//  Created by walteh on 12/6/22.
//  Copyright © 2022 Walter Scott. All rights reserved.
// ---------------------------------------------------------------------
//  adapted from bitcoin-core/secp256k1
//  Copyright © 2014 Pieter Wuille. MIT software license
// ---------------------------------------------------------------------

#ifndef scalar_h
#define scalar_h

#include <stdint.h>

#include "hash.h"
#include "int128.h"
#include "modinv.h"

#include <string.h>

#define VG_CHECK_VERIFY(x, y)

/** A scalar modulo the group order of the secp256k1 curve. */
typedef struct {
	uint64_t d[4];
} secp256k1_scalar;

#define SECP256K1_SCALAR_CONST(d7, d6, d5, d4, d3, d2, d1, d0)                                           \
	{                                                                                                    \
		{                                                                                                \
			((uint64_t)(d1)) << 32 | (d0), ((uint64_t)(d3)) << 32 | (d2), ((uint64_t)(d5)) << 32 | (d4), \
				((uint64_t)(d7)) << 32 | (d6)                                                            \
		}                                                                                                \
	}

/* Limbs of the secp256k1 order. */
#define SECP256K1_N_0 ((uint64_t)0xBFD25E8CD0364141ULL)
#define SECP256K1_N_1 ((uint64_t)0xBAAEDCE6AF48A03BULL)
#define SECP256K1_N_2 ((uint64_t)0xFFFFFFFFFFFFFFFEULL)
#define SECP256K1_N_3 ((uint64_t)0xFFFFFFFFFFFFFFFFULL)

/* Limbs of 2^256 minus the secp256k1 order. */
#define SECP256K1_N_C_0 (~SECP256K1_N_0 + 1)
#define SECP256K1_N_C_1 (~SECP256K1_N_1)
#define SECP256K1_N_C_2 (1)

/* Limbs of half the secp256k1 order. */
#define SECP256K1_N_H_0 ((uint64_t)0xDFE92F46681B20A0ULL)
#define SECP256K1_N_H_1 ((uint64_t)0x5D576E7357A4501DULL)
#define SECP256K1_N_H_2 ((uint64_t)0xFFFFFFFFFFFFFFFFULL)
#define SECP256K1_N_H_3 ((uint64_t)0x7FFFFFFFFFFFFFFFULL)

/** Clear a scalar to prevent the leak of sensitive data. */
void secp256k1_scalar_clear(secp256k1_scalar *r);

/** Set a scalar from a big endian byte array. The scalar will be reduced modulo group order `n`.
 * In:      bin:        pointer to a 32-byte array.
 * Out:     r:          scalar to be set.
 *          overflow:   non-zero if the scalar was bigger or equal to `n` before reduction, zero otherwise (can be
 * NULL).
 */
void secp256k1_scalar_set_b32(secp256k1_scalar *r, const unsigned char *bin, int *overflow);

/** Set a scalar from a big endian byte array and returns 1 if it is a valid
 *  seckey and 0 otherwise. */
int secp256k1_scalar_set_b32_seckey(secp256k1_scalar *r, const unsigned char *bin);

/** Convert a scalar to a byte array. */
void secp256k1_scalar_get_b32(unsigned char *bin, const secp256k1_scalar *a);

/** Add two scalars together (modulo the group order). Returns whether it overflowed. */
int secp256k1_scalar_add(secp256k1_scalar *r, const secp256k1_scalar *a, const secp256k1_scalar *b);

/** Conditionally add a power of two to a scalar. The result is not allowed to overflow. */
void secp256k1_scalar_cadd_bit(secp256k1_scalar *r, unsigned int bit, int flag);

/** Compute the complement of a scalar (modulo the group order). */
void secp256k1_scalar_negate(secp256k1_scalar *r, const secp256k1_scalar *a);

/** Check whether a scalar equals zero. */
int secp256k1_scalar_is_zero(const secp256k1_scalar *a);

/** Check whether a scalar, considered as an nonnegative integer, is even. */
int secp256k1_scalar_is_even(const secp256k1_scalar *a);

/** Check whether a scalar is higher than the group order divided by 2. */
int secp256k1_scalar_is_high(const secp256k1_scalar *a);

/** Conditionally negate a number, in constant time.
 * Returns -1 if the number was negated, 1 otherwise */
int secp256k1_scalar_cond_negate(secp256k1_scalar *a, int flag);

/** If flag is true, set *r equal to *a; otherwise leave it. Constant-time.  Both *r and *a must be initialized.*/
void secp256k1_scalar_cmov(secp256k1_scalar *r, const secp256k1_scalar *a, int flag);

/** Convert a scalar to a byte array. */
void secp256k1_scalar_get_b32(unsigned char *bin, const secp256k1_scalar *a);

/** Add two scalars together (modulo the group order). Returns whether it overflowed. */
int secp256k1_scalar_add(secp256k1_scalar *r, const secp256k1_scalar *a, const secp256k1_scalar *b);

/** Conditionally add a power of two to a scalar. The result is not allowed to overflow. */
void secp256k1_scalar_cadd_bit(secp256k1_scalar *r, unsigned int bit, int flag);

/** Conditionally negate a number, in constant time.
 * Returns -1 if the number was negated, 1 otherwise */
int secp256k1_scalar_cond_negate(secp256k1_scalar *a, int flag);

/** Check whether a scalar, considered as an nonnegative integer, is even. */
int secp256k1_scalar_is_even(const secp256k1_scalar *a);

/** Check whether a scalar is higher than the group order divided by 2. */
int secp256k1_scalar_is_high(const secp256k1_scalar *a);

void secp256k1_scalar_negate(secp256k1_scalar *r, const secp256k1_scalar *a);

static void secp256k1_scalar_mul(secp256k1_scalar *r, const secp256k1_scalar *a, const secp256k1_scalar *b);

static void secp256k1_scalar_to_signed62(secp256k1_modinv64_signed62 *r, const secp256k1_scalar *a);

/* Replace x with its modular inverse mod modinfo->modulus. x must be in range [0, modulus).
 * If x is zero, the result will be zero as well. If not, the inverse must exist (i.e., the gcd of
 * x and modulus must be 1). These rules are automatically satisfied if the modulus is prime.
 *
 * On output, all of x's limbs will be in [0, 2^62).
 */
static void secp256k1_modinv64_var(secp256k1_modinv64_signed62 *x, const secp256k1_modinv64_modinfo *modinfo);

static void secp256k1_scalar_inverse_var(secp256k1_scalar *r, const secp256k1_scalar *x);

/** Find r1 and r2 such that r1+r2*lambda = k, where r1 and r2 or their
 *  negations are maximum 128 bits long (see secp256k1_ge_mul_lambda). It is
 *  required that r1, r2, and k all point to different objects. */
static void secp256k1_scalar_split_lambda(
	secp256k1_scalar *restrict r1, secp256k1_scalar *restrict r2, const secp256k1_scalar *restrict k
);

/** Access bits from a scalar. All requested bits must belong to the same 32-bit limb. */
static unsigned int secp256k1_scalar_get_bits(const secp256k1_scalar *a, unsigned int offset, unsigned int count);

/** Access bits from a scalar. Not constant time. */
static unsigned int secp256k1_scalar_get_bits_var(const secp256k1_scalar *a, unsigned int offset, unsigned int count);

#endif /* scalar_h */
