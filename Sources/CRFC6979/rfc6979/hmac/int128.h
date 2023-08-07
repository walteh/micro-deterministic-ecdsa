//
//  int128.c
//
//  Created by walteh on 12/6/22.
//  Copyright © 2022 Walter Scott. All rights reserved.
// ---------------------------------------------------------------------
//  adapted from bitcoin-core/secp256k1
//  Copyright © 2014 Pieter Wuille. MIT software license
// ---------------------------------------------------------------------

#ifndef int128_h
#define int128_h

#include <stdint.h>

#if !defined(UINT128_MAX) && defined(__SIZEOF_INT128__)
typedef unsigned __int128 uint128_t;
typedef __int128 int128_t;
#define UINT128_MAX ((uint128_t)(-1))
#define INT128_MAX	((int128_t)(UINT128_MAX >> 1))
#define INT128_MIN	(-INT128_MAX - 1)
/* No (U)INT128_C macros because compilers providing __int128 do not support 128-bit literals.  */
#endif

typedef uint128_t secp256k1_uint128;
typedef int128_t secp256k1_int128;

/* Construct an unsigned 128-bit value from a high and a low 64-bit value. */
void secp256k1_u128_load(secp256k1_uint128 *r, uint64_t hi, uint64_t lo);

/* Multiply two unsigned 64-bit values a and b and write the result to r. */
void secp256k1_u128_mul(secp256k1_uint128 *r, uint64_t a, uint64_t b);

/* Multiply two unsigned 64-bit values a and b and add the result to r.
 * The final result is taken modulo 2^128.
 */
void secp256k1_u128_accum_mul(secp256k1_uint128 *r, uint64_t a, uint64_t b);

/* Add an unsigned 64-bit value a to r.
 * The final result is taken modulo 2^128.
 */
void secp256k1_u128_accum_u64(secp256k1_uint128 *r, uint64_t a);

/* Unsigned (logical) right shift.
 * Non-constant time in n.
 */
void secp256k1_u128_rshift(secp256k1_uint128 *r, unsigned int n);

/* Return the low 64-bits of a 128-bit value as an unsigned 64-bit value. */
uint64_t secp256k1_u128_to_u64(const secp256k1_uint128 *a);

/* Return the low 64-bits as an int value */
int secp256k1_u128_to_i(const secp256k1_uint128 *a);

/* Return the high 64-bits of a 128-bit value as an unsigned 64-bit value. */
uint64_t secp256k1_u128_hi_u64(const secp256k1_uint128 *a);

/* Write an unsigned 64-bit value to r. */
void secp256k1_u128_from_u64(secp256k1_uint128 *r, uint64_t a);

/* Tests if r is strictly less than to 2^n.
 * n must be strictly less than 128.
 */
int secp256k1_u128_check_bits(const secp256k1_uint128 *r, unsigned int n);

/* Construct an signed 128-bit value from a high and a low 64-bit value. */
void secp256k1_i128_load(secp256k1_int128 *r, int64_t hi, uint64_t lo);

/* Multiply two signed 64-bit values a and b and write the result to r. */
void secp256k1_i128_mul(secp256k1_int128 *r, int64_t a, int64_t b);

/* Multiply two signed 64-bit values a and b and add the result to r.
 * Overflow or underflow from the addition is undefined behaviour.
 */
void secp256k1_i128_accum_mul(secp256k1_int128 *r, int64_t a, int64_t b);

/* Compute a*d - b*c from signed 64-bit values and write the result to r. */
void secp256k1_i128_det(secp256k1_int128 *r, int64_t a, int64_t b, int64_t c, int64_t d);

/* Signed (arithmetic) right shift.
 * Non-constant time in b.
 */
void secp256k1_i128_rshift(secp256k1_int128 *r, unsigned int b);

/* Return the low 64-bits of a 128-bit value interpreted as an signed 64-bit value. */
int64_t secp256k1_i128_to_i64(const secp256k1_int128 *a);

/* Write a signed 64-bit value to r. */
void secp256k1_i128_from_i64(secp256k1_int128 *r, int64_t a);

/* Compare two 128-bit values for equality. */
int secp256k1_i128_eq_var(const secp256k1_int128 *a, const secp256k1_int128 *b);

/* Tests if r is equal to 2^n.
 * n must be strictly less than 127.
 */
int secp256k1_i128_check_pow2(const secp256k1_int128 *r, unsigned int n);

static inline uint64_t secp256k1_i128_to_u64(const secp256k1_int128 *a);

#endif /* nonce_h */
