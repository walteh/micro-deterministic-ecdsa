//
//  hash.h
//
//  Created by walteh on 12/6/22.
//  Copyright © 2022 Walter Scott. All rights reserved.
// ---------------------------------------------------------------------
//  adapted from bitcoin-core/secp256k1
//  Copyright © 2014 Pieter Wuille. MIT software license
// ---------------------------------------------------------------------

#ifndef hash_h
#define hash_h

#include <stdint.h>
#include <stdlib.h>

#define ARG_CHECK(cond) \
	do {                \
		(void)(cond);   \
	} while (0)

#define VERIFY_CHECK(cond) \
	do {                   \
		(void)(cond);      \
	} while (0)

/** Assert statically that expr is an integer constant expression, and run stmt.
 *
 * Useful for example to enforce that magnitude arguments are constant.
 */
#define ASSERT_INT_CONST_AND_DO(expr, stmt)                          \
	do {                                                             \
		switch (42) {                                                \
			case /* ERROR: integer argument is not constant */ expr: \
				break;                                               \
			default:;                                                \
		}                                                            \
		stmt;                                                        \
	} while (0)

/* Determine the number of trailing zero bits in a (non-zero) 64-bit x.
 * This function is only intended to be used as fallback for
 * secp256k1_ctz64_var, but permits it to be tested separately.
 *adapted from: secp256k1_ctz64_var_debruijn - bitcoin-core/secp256k1/src/util.h
 */
static inline int secp256k1_ctz64_var(uint64_t x) {
	static const uint8_t debruijn[64] = {0,	 1,	 2,	 53, 3,	 7,	 54, 27, 4,	 38, 41, 8,	 34, 55, 48, 28,
										 62, 5,	 39, 46, 44, 42, 22, 9,	 24, 35, 59, 56, 49, 18, 29, 11,
										 63, 52, 6,	 26, 37, 40, 33, 47, 61, 45, 43, 21, 23, 58, 17, 10,
										 51, 25, 36, 32, 60, 20, 57, 16, 50, 31, 19, 15, 30, 14, 13, 12};
	return debruijn[(uint64_t)((x & -x) * 0x022FDD63CC95386DU) >> 58];
}

#define Ch(x, y, z)	 ((z) ^ ((x) & ((y) ^ (z))))
#define Maj(x, y, z) (((x) & (y)) | ((z) & ((x) | (y))))
#define Sigma0(x)	 (((x) >> 2 | (x) << 30) ^ ((x) >> 13 | (x) << 19) ^ ((x) >> 22 | (x) << 10))
#define Sigma1(x)	 (((x) >> 6 | (x) << 26) ^ ((x) >> 11 | (x) << 21) ^ ((x) >> 25 | (x) << 7))
#define sigma0(x)	 (((x) >> 7 | (x) << 25) ^ ((x) >> 18 | (x) << 14) ^ ((x) >> 3))
#define sigma1(x)	 (((x) >> 17 | (x) << 15) ^ ((x) >> 19 | (x) << 13) ^ ((x) >> 10))

#define Round(a, b, c, d, e, f, g, h, k, w)                            \
	do {                                                               \
		uint32_t t1 = (h) + Sigma1(e) + Ch((e), (f), (g)) + (k) + (w); \
		uint32_t t2 = Sigma0(a) + Maj((a), (b), (c));                  \
		(d) += t1;                                                     \
		(h) = t1 + t2;                                                 \
	} while (0)

typedef struct {
	uint32_t s[8];
	unsigned char buf[64];
	uint64_t bytes;
} secp256k1_sha256;

typedef struct {
	secp256k1_sha256 inner, outer;
} secp256k1_hmac_sha256;

typedef struct {
	unsigned char v[32];
	unsigned char k[32];
	int retry;
} secp256k1_rfc6979_hmac_sha256;

void secp256k1_rfc6979_hmac_sha256_initialize(
	secp256k1_rfc6979_hmac_sha256 *rng, const unsigned char *key, size_t keylen
);
void secp256k1_rfc6979_hmac_sha256_generate(secp256k1_rfc6979_hmac_sha256 *rng, unsigned char *out, size_t outlen);
void secp256k1_rfc6979_hmac_sha256_finalize(secp256k1_rfc6979_hmac_sha256 *rng);

void secp256k1_int_cmov(int *r, const int *a, int flag);

#endif /* hash_h */
