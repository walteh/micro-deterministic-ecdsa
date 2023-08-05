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

#define VERIFY_CHECK(cond) \
	do {                   \
		(void)(cond);      \
	} while (0)

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
