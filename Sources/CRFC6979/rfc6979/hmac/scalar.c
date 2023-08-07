//
//  scalar.c
//
//  Created by walteh on 12/6/22.
//  Copyright © 2022 Walter Scott. All rights reserved.
// ---------------------------------------------------------------------
//  adapted from bitcoin-core/secp256k1
//  Copyright © 2014 Pieter Wuille. MIT software license
// ---------------------------------------------------------------------

#include "scalar.h"

int secp256k1_scalar_check_overflow(const secp256k1_scalar *a) {
	int yes = 0;
	int no	= 0;
	no |= (a->d[3] < SECP256K1_N_3); /* No need for a > check. */
	no |= (a->d[2] < SECP256K1_N_2);
	yes |= (a->d[2] > SECP256K1_N_2) & ~no;
	no |= (a->d[1] < SECP256K1_N_1);
	yes |= (a->d[1] > SECP256K1_N_1) & ~no;
	yes |= (a->d[0] >= SECP256K1_N_0) & ~no;
	return yes;
}

int secp256k1_scalar_reduce(secp256k1_scalar *r, unsigned int overflow) {
	secp256k1_uint128 t;
	VERIFY_CHECK(overflow <= 1);
	secp256k1_u128_from_u64(&t, r->d[0]);
	secp256k1_u128_accum_u64(&t, overflow * SECP256K1_N_C_0);
	r->d[0] = secp256k1_u128_to_u64(&t);
	secp256k1_u128_rshift(&t, 64);
	secp256k1_u128_accum_u64(&t, r->d[1]);
	secp256k1_u128_accum_u64(&t, overflow * SECP256K1_N_C_1);
	r->d[1] = secp256k1_u128_to_u64(&t);
	secp256k1_u128_rshift(&t, 64);
	secp256k1_u128_accum_u64(&t, r->d[2]);
	secp256k1_u128_accum_u64(&t, overflow * SECP256K1_N_C_2);
	r->d[2] = secp256k1_u128_to_u64(&t);
	secp256k1_u128_rshift(&t, 64);
	secp256k1_u128_accum_u64(&t, r->d[3]);
	r->d[3] = secp256k1_u128_to_u64(&t);
	return overflow;
}

void secp256k1_scalar_set_b32(secp256k1_scalar *r, const unsigned char *b32, int *overflow) {
	int over;
	r->d[0] = (uint64_t)b32[31] | (uint64_t)b32[30] << 8 | (uint64_t)b32[29] << 16 | (uint64_t)b32[28] << 24 |
			  (uint64_t)b32[27] << 32 | (uint64_t)b32[26] << 40 | (uint64_t)b32[25] << 48 | (uint64_t)b32[24] << 56;
	r->d[1] = (uint64_t)b32[23] | (uint64_t)b32[22] << 8 | (uint64_t)b32[21] << 16 | (uint64_t)b32[20] << 24 |
			  (uint64_t)b32[19] << 32 | (uint64_t)b32[18] << 40 | (uint64_t)b32[17] << 48 | (uint64_t)b32[16] << 56;
	r->d[2] = (uint64_t)b32[15] | (uint64_t)b32[14] << 8 | (uint64_t)b32[13] << 16 | (uint64_t)b32[12] << 24 |
			  (uint64_t)b32[11] << 32 | (uint64_t)b32[10] << 40 | (uint64_t)b32[9] << 48 | (uint64_t)b32[8] << 56;
	r->d[3] = (uint64_t)b32[7] | (uint64_t)b32[6] << 8 | (uint64_t)b32[5] << 16 | (uint64_t)b32[4] << 24 |
			  (uint64_t)b32[3] << 32 | (uint64_t)b32[2] << 40 | (uint64_t)b32[1] << 48 | (uint64_t)b32[0] << 56;
	over = secp256k1_scalar_reduce(r, secp256k1_scalar_check_overflow(r));
	if (overflow) {
		*overflow = over;
	}
}

void secp256k1_scalar_get_b32(unsigned char *bin, const secp256k1_scalar *a) {
	bin[0]	= a->d[3] >> 56;
	bin[1]	= a->d[3] >> 48;
	bin[2]	= a->d[3] >> 40;
	bin[3]	= a->d[3] >> 32;
	bin[4]	= a->d[3] >> 24;
	bin[5]	= a->d[3] >> 16;
	bin[6]	= a->d[3] >> 8;
	bin[7]	= a->d[3];
	bin[8]	= a->d[2] >> 56;
	bin[9]	= a->d[2] >> 48;
	bin[10] = a->d[2] >> 40;
	bin[11] = a->d[2] >> 32;
	bin[12] = a->d[2] >> 24;
	bin[13] = a->d[2] >> 16;
	bin[14] = a->d[2] >> 8;
	bin[15] = a->d[2];
	bin[16] = a->d[1] >> 56;
	bin[17] = a->d[1] >> 48;
	bin[18] = a->d[1] >> 40;
	bin[19] = a->d[1] >> 32;
	bin[20] = a->d[1] >> 24;
	bin[21] = a->d[1] >> 16;
	bin[22] = a->d[1] >> 8;
	bin[23] = a->d[1];
	bin[24] = a->d[0] >> 56;
	bin[25] = a->d[0] >> 48;
	bin[26] = a->d[0] >> 40;
	bin[27] = a->d[0] >> 32;
	bin[28] = a->d[0] >> 24;
	bin[29] = a->d[0] >> 16;
	bin[30] = a->d[0] >> 8;
	bin[31] = a->d[0];
}

void secp256k1_scalar_cmov(secp256k1_scalar *r, const secp256k1_scalar *a, int flag) {
	uint64_t mask0, mask1;
	VG_CHECK_VERIFY(r->d, sizeof(r->d));
	mask0	= flag + ~((uint64_t)0);
	mask1	= ~mask0;
	r->d[0] = (r->d[0] & mask0) | (a->d[0] & mask1);
	r->d[1] = (r->d[1] & mask0) | (a->d[1] & mask1);
	r->d[2] = (r->d[2] & mask0) | (a->d[2] & mask1);
	r->d[3] = (r->d[3] & mask0) | (a->d[3] & mask1);
}

void secp256k1_scalar_clear(secp256k1_scalar *r) {
	r->d[0] = 0;
	r->d[1] = 0;
	r->d[2] = 0;
	r->d[3] = 0;
}

int secp256k1_scalar_is_zero(const secp256k1_scalar *a) { return (a->d[0] | a->d[1] | a->d[2] | a->d[3]) == 0; }

int secp256k1_scalar_set_b32_seckey(secp256k1_scalar *r, const unsigned char *bin) {
	int overflow;
	secp256k1_scalar_set_b32(r, bin, &overflow);
	return (!overflow) & (!secp256k1_scalar_is_zero(r));
}

int secp256k1_scalar_add(secp256k1_scalar *r, const secp256k1_scalar *a, const secp256k1_scalar *b) {
	int overflow;
	secp256k1_uint128 t;
	secp256k1_u128_from_u64(&t, a->d[0]);
	secp256k1_u128_accum_u64(&t, b->d[0]);
	r->d[0] = secp256k1_u128_to_u64(&t);
	secp256k1_u128_rshift(&t, 64);
	secp256k1_u128_accum_u64(&t, a->d[1]);
	secp256k1_u128_accum_u64(&t, b->d[1]);
	r->d[1] = secp256k1_u128_to_u64(&t);
	secp256k1_u128_rshift(&t, 64);
	secp256k1_u128_accum_u64(&t, a->d[2]);
	secp256k1_u128_accum_u64(&t, b->d[2]);
	r->d[2] = secp256k1_u128_to_u64(&t);
	secp256k1_u128_rshift(&t, 64);
	secp256k1_u128_accum_u64(&t, a->d[3]);
	secp256k1_u128_accum_u64(&t, b->d[3]);
	r->d[3] = secp256k1_u128_to_u64(&t);
	secp256k1_u128_rshift(&t, 64);
	overflow = secp256k1_u128_to_i(&t) + secp256k1_scalar_check_overflow(r);
	VERIFY_CHECK(overflow == 0 || overflow == 1);
	secp256k1_scalar_reduce(r, overflow);
	return overflow;
}

void secp256k1_scalar_cadd_bit(secp256k1_scalar *r, unsigned int bit, int flag) {
	secp256k1_uint128 t;
	VERIFY_CHECK(bit < 256);
	bit += ((uint32_t)flag - 1) & 0x100; /* forcing (bit >> 6) > 3 makes this a noop */
	secp256k1_u128_from_u64(&t, r->d[0]);
	secp256k1_u128_accum_u64(&t, ((uint64_t)((bit >> 6) == 0)) << (bit & 0x3F));
	r->d[0] = secp256k1_u128_to_u64(&t);
	secp256k1_u128_rshift(&t, 64);
	secp256k1_u128_accum_u64(&t, r->d[1]);
	secp256k1_u128_accum_u64(&t, ((uint64_t)((bit >> 6) == 1)) << (bit & 0x3F));
	r->d[1] = secp256k1_u128_to_u64(&t);
	secp256k1_u128_rshift(&t, 64);
	secp256k1_u128_accum_u64(&t, r->d[2]);
	secp256k1_u128_accum_u64(&t, ((uint64_t)((bit >> 6) == 2)) << (bit & 0x3F));
	r->d[2] = secp256k1_u128_to_u64(&t);
	secp256k1_u128_rshift(&t, 64);
	secp256k1_u128_accum_u64(&t, r->d[3]);
	secp256k1_u128_accum_u64(&t, ((uint64_t)((bit >> 6) == 3)) << (bit & 0x3F));
	r->d[3] = secp256k1_u128_to_u64(&t);
#ifdef VERIFY
	VERIFY_CHECK(secp256k1_u128_hi_u64(&t) == 0);
#endif
}

int secp256k1_scalar_cond_negate(secp256k1_scalar *r, int flag) {
	/* If we are flag = 0, mask = 00...00 and this is a no-op;
	 * if we are flag = 1, mask = 11...11 and this is identical to secp256k1_scalar_negate */
	uint64_t mask	 = !flag - 1;
	uint64_t nonzero = (secp256k1_scalar_is_zero(r) != 0) - 1;
	secp256k1_uint128 t;
	secp256k1_u128_from_u64(&t, r->d[0] ^ mask);
	secp256k1_u128_accum_u64(&t, (SECP256K1_N_0 + 1) & mask);
	r->d[0] = secp256k1_u128_to_u64(&t) & nonzero;
	secp256k1_u128_rshift(&t, 64);
	secp256k1_u128_accum_u64(&t, r->d[1] ^ mask);
	secp256k1_u128_accum_u64(&t, SECP256K1_N_1 & mask);
	r->d[1] = secp256k1_u128_to_u64(&t) & nonzero;
	secp256k1_u128_rshift(&t, 64);
	secp256k1_u128_accum_u64(&t, r->d[2] ^ mask);
	secp256k1_u128_accum_u64(&t, SECP256K1_N_2 & mask);
	r->d[2] = secp256k1_u128_to_u64(&t) & nonzero;
	secp256k1_u128_rshift(&t, 64);
	secp256k1_u128_accum_u64(&t, r->d[3] ^ mask);
	secp256k1_u128_accum_u64(&t, SECP256K1_N_3 & mask);
	r->d[3] = secp256k1_u128_to_u64(&t) & nonzero;
	return 2 * (mask == 0) - 1;
}

int secp256k1_scalar_is_even(const secp256k1_scalar *a) { return !(a->d[0] & 1); }

int secp256k1_scalar_is_high(const secp256k1_scalar *a) {
	int yes = 0;
	int no	= 0;
	no |= (a->d[3] < SECP256K1_N_H_3);
	yes |= (a->d[3] > SECP256K1_N_H_3) & ~no;
	no |= (a->d[2] < SECP256K1_N_H_2) & ~yes; /* No need for a > check. */
	no |= (a->d[1] < SECP256K1_N_H_1) & ~yes;
	yes |= (a->d[1] > SECP256K1_N_H_1) & ~no;
	yes |= (a->d[0] > SECP256K1_N_H_0) & ~no;
	return yes;
}

void secp256k1_scalar_negate(secp256k1_scalar *r, const secp256k1_scalar *a) {
	uint64_t nonzero = 0xFFFFFFFFFFFFFFFFULL * (secp256k1_scalar_is_zero(a) == 0);
	secp256k1_uint128 t;
	secp256k1_u128_from_u64(&t, ~a->d[0]);
	secp256k1_u128_accum_u64(&t, SECP256K1_N_0 + 1);
	r->d[0] = secp256k1_u128_to_u64(&t) & nonzero;
	secp256k1_u128_rshift(&t, 64);
	secp256k1_u128_accum_u64(&t, ~a->d[1]);
	secp256k1_u128_accum_u64(&t, SECP256K1_N_1);
	r->d[1] = secp256k1_u128_to_u64(&t) & nonzero;
	secp256k1_u128_rshift(&t, 64);
	secp256k1_u128_accum_u64(&t, ~a->d[2]);
	secp256k1_u128_accum_u64(&t, SECP256K1_N_2);
	r->d[2] = secp256k1_u128_to_u64(&t) & nonzero;
	secp256k1_u128_rshift(&t, 64);
	secp256k1_u128_accum_u64(&t, ~a->d[3]);
	secp256k1_u128_accum_u64(&t, SECP256K1_N_3);
	r->d[3] = secp256k1_u128_to_u64(&t) & nonzero;
}

/** Add a*b to the number defined by (c0,c1,c2). c2 must never overflow. */
#define muladd(a, b)                                                                   \
	{                                                                                  \
		uint64_t tl, th;                                                               \
		{                                                                              \
			secp256k1_uint128 t;                                                       \
			secp256k1_u128_mul(&t, a, b);                                              \
			th = secp256k1_u128_hi_u64(&t); /* at most 0xFFFFFFFFFFFFFFFE */           \
			tl = secp256k1_u128_to_u64(&t);                                            \
		}                                                                              \
		c0 += tl;		 /* overflow is handled on the next line */                    \
		th += (c0 < tl); /* at most 0xFFFFFFFFFFFFFFFF */                              \
		c1 += th;		 /* overflow is handled on the next line */                    \
		c2 += (c1 < th); /* never overflows by contract (verified in the next line) */ \
		VERIFY_CHECK((c1 >= th) || (c2 != 0));                                         \
	}

/** Add a*b to the number defined by (c0,c1). c1 must never overflow. */
#define muladd_fast(a, b)                                                              \
	{                                                                                  \
		uint64_t tl, th;                                                               \
		{                                                                              \
			secp256k1_uint128 t;                                                       \
			secp256k1_u128_mul(&t, a, b);                                              \
			th = secp256k1_u128_hi_u64(&t); /* at most 0xFFFFFFFFFFFFFFFE */           \
			tl = secp256k1_u128_to_u64(&t);                                            \
		}                                                                              \
		c0 += tl;		 /* overflow is handled on the next line */                    \
		th += (c0 < tl); /* at most 0xFFFFFFFFFFFFFFFF */                              \
		c1 += th;		 /* never overflows by contract (verified in the next line) */ \
		VERIFY_CHECK(c1 >= th);                                                        \
	}

/** Add a to the number defined by (c0,c1,c2). c2 must never overflow. */
#define sumadd(a)                                                     \
	{                                                                 \
		unsigned int over;                                            \
		c0 += (a); /* overflow is handled on the next line */         \
		over = (c0 < (a));                                            \
		c1 += over;		   /* overflow is handled on the next line */ \
		c2 += (c1 < over); /* never overflows by contract */          \
	}

/** Add a to the number defined by (c0,c1). c1 must never overflow, c2 must be zero. */
#define sumadd_fast(a)                                                               \
	{                                                                                \
		c0 += (a);		  /* overflow is handled on the next line */                 \
		c1 += (c0 < (a)); /* never overflows by contract (verified the next line) */ \
		VERIFY_CHECK((c1 != 0) | (c0 >= (a)));                                       \
		VERIFY_CHECK(c2 == 0);                                                       \
	}

/** Extract the lowest 64 bits of (c0,c1,c2) into n, and left shift the number 64 bits. */
#define extract(n) \
	{              \
		(n) = c0;  \
		c0	= c1;  \
		c1	= c2;  \
		c2	= 0;   \
	}

/** Extract the lowest 64 bits of (c0,c1,c2) into n, and left shift the number 64 bits. c2 is required to be zero. */
#define extract_fast(n)        \
	{                          \
		(n) = c0;              \
		c0	= c1;              \
		c1	= 0;               \
		VERIFY_CHECK(c2 == 0); \
	}

static void secp256k1_scalar_mul_512(uint64_t l[8], const secp256k1_scalar *a, const secp256k1_scalar *b) {
	/* 160 bit accumulator. */
	uint64_t c0 = 0, c1 = 0;
	uint32_t c2 = 0;

	/* l[0..7] = a[0..3] * b[0..3]. */
	muladd_fast(a->d[0], b->d[0]);
	extract_fast(l[0]);
	muladd(a->d[0], b->d[1]);
	muladd(a->d[1], b->d[0]);
	extract(l[1]);
	muladd(a->d[0], b->d[2]);
	muladd(a->d[1], b->d[1]);
	muladd(a->d[2], b->d[0]);
	extract(l[2]);
	muladd(a->d[0], b->d[3]);
	muladd(a->d[1], b->d[2]);
	muladd(a->d[2], b->d[1]);
	muladd(a->d[3], b->d[0]);
	extract(l[3]);
	muladd(a->d[1], b->d[3]);
	muladd(a->d[2], b->d[2]);
	muladd(a->d[3], b->d[1]);
	extract(l[4]);
	muladd(a->d[2], b->d[3]);
	muladd(a->d[3], b->d[2]);
	extract(l[5]);
	muladd_fast(a->d[3], b->d[3]);
	extract_fast(l[6]);
	VERIFY_CHECK(c1 == 0);
	l[7] = c0;
}

static void secp256k1_scalar_from_signed62(secp256k1_scalar *r, const secp256k1_modinv64_signed62 *a) {
	const uint64_t a0 = a->v[0], a1 = a->v[1], a2 = a->v[2], a3 = a->v[3], a4 = a->v[4];

	/* The output from secp256k1_modinv64{_var} should be normalized to range [0,modulus), and
	 * have limbs in [0,2^62). The modulus is < 2^256, so the top limb must be below 2^(256-62*4).
	 */
	VERIFY_CHECK(a0 >> 62 == 0);
	VERIFY_CHECK(a1 >> 62 == 0);
	VERIFY_CHECK(a2 >> 62 == 0);
	VERIFY_CHECK(a3 >> 62 == 0);
	VERIFY_CHECK(a4 >> 8 == 0);

	r->d[0] = a0 | a1 << 62;
	r->d[1] = a1 >> 2 | a2 << 60;
	r->d[2] = a2 >> 4 | a3 << 58;
	r->d[3] = a3 >> 6 | a4 << 56;

#ifdef VERIFY
	VERIFY_CHECK(secp256k1_scalar_check_overflow(r) == 0);
#endif
}

static void secp256k1_scalar_to_signed62(secp256k1_modinv64_signed62 *r, const secp256k1_scalar *a) {
	const uint64_t M62 = UINT64_MAX >> 2;
	const uint64_t a0 = a->d[0], a1 = a->d[1], a2 = a->d[2], a3 = a->d[3];

#ifdef VERIFY
	VERIFY_CHECK(secp256k1_scalar_check_overflow(a) == 0);
#endif

	r->v[0] = a0 & M62;
	r->v[1] = (a0 >> 62 | a1 << 2) & M62;
	r->v[2] = (a1 >> 60 | a2 << 4) & M62;
	r->v[3] = (a2 >> 58 | a3 << 6) & M62;
	r->v[4] = a3 >> 56;
}

static const secp256k1_modinv64_modinfo secp256k1_const_modinfo_scalar = {
	{{0x3FD25E8CD0364141LL, 0x2ABB739ABD2280EELL, -0x15LL, 0, 256}}, 0x34F20099AA774EC1LL};

static void secp256k1_scalar_inverse(secp256k1_scalar *r, const secp256k1_scalar *x) {
	secp256k1_modinv64_signed62 s;
#ifdef VERIFY
	int zero_in = secp256k1_scalar_is_zero(x);
#endif
	secp256k1_scalar_to_signed62(&s, x);
	secp256k1_modinv64(&s, &secp256k1_const_modinfo_scalar);
	secp256k1_scalar_from_signed62(r, &s);

#ifdef VERIFY
	VERIFY_CHECK(secp256k1_scalar_is_zero(r) == zero_in);
#endif
}

static void secp256k1_scalar_reduce_512(secp256k1_scalar *r, const uint64_t *l) {
	secp256k1_uint128 c128;
	uint64_t c, c0, c1, c2;
	uint64_t n0 = l[4], n1 = l[5], n2 = l[6], n3 = l[7];
	uint64_t m0, m1, m2, m3, m4, m5;
	uint32_t m6;
	uint64_t p0, p1, p2, p3;
	uint32_t p4;

	/* Reduce 512 bits into 385. */
	/* m[0..6] = l[0..3] + n[0..3] * SECP256K1_N_C. */
	c0 = l[0];
	c1 = 0;
	c2 = 0;
	muladd_fast(n0, SECP256K1_N_C_0);
	extract_fast(m0);
	sumadd_fast(l[1]);
	muladd(n1, SECP256K1_N_C_0);
	muladd(n0, SECP256K1_N_C_1);
	extract(m1);
	sumadd(l[2]);
	muladd(n2, SECP256K1_N_C_0);
	muladd(n1, SECP256K1_N_C_1);
	sumadd(n0);
	extract(m2);
	sumadd(l[3]);
	muladd(n3, SECP256K1_N_C_0);
	muladd(n2, SECP256K1_N_C_1);
	sumadd(n1);
	extract(m3);
	muladd(n3, SECP256K1_N_C_1);
	sumadd(n2);
	extract(m4);
	sumadd_fast(n3);
	extract_fast(m5);
	VERIFY_CHECK(c0 <= 1);
	m6 = c0;

	/* Reduce 385 bits into 258. */
	/* p[0..4] = m[0..3] + m[4..6] * SECP256K1_N_C. */
	c0 = m0;
	c1 = 0;
	c2 = 0;
	muladd_fast(m4, SECP256K1_N_C_0);
	extract_fast(p0);
	sumadd_fast(m1);
	muladd(m5, SECP256K1_N_C_0);
	muladd(m4, SECP256K1_N_C_1);
	extract(p1);
	sumadd(m2);
	muladd(m6, SECP256K1_N_C_0);
	muladd(m5, SECP256K1_N_C_1);
	sumadd(m4);
	extract(p2);
	sumadd_fast(m3);
	muladd_fast(m6, SECP256K1_N_C_1);
	sumadd_fast(m5);
	extract_fast(p3);
	p4 = c0 + m6;
	VERIFY_CHECK(p4 <= 2);

	/* Reduce 258 bits into 256. */
	/* r[0..3] = p[0..3] + p[4] * SECP256K1_N_C. */
	secp256k1_u128_from_u64(&c128, p0);
	secp256k1_u128_accum_mul(&c128, SECP256K1_N_C_0, p4);
	r->d[0] = secp256k1_u128_to_u64(&c128);
	secp256k1_u128_rshift(&c128, 64);
	secp256k1_u128_accum_u64(&c128, p1);
	secp256k1_u128_accum_mul(&c128, SECP256K1_N_C_1, p4);
	r->d[1] = secp256k1_u128_to_u64(&c128);
	secp256k1_u128_rshift(&c128, 64);
	secp256k1_u128_accum_u64(&c128, p2);
	secp256k1_u128_accum_u64(&c128, p4);
	r->d[2] = secp256k1_u128_to_u64(&c128);
	secp256k1_u128_rshift(&c128, 64);
	secp256k1_u128_accum_u64(&c128, p3);
	r->d[3] = secp256k1_u128_to_u64(&c128);
	c		= secp256k1_u128_hi_u64(&c128);

	/* Final reduction of r. */
	secp256k1_scalar_reduce(r, c + secp256k1_scalar_check_overflow(r));
}

static void secp256k1_scalar_mul(secp256k1_scalar *r, const secp256k1_scalar *a, const secp256k1_scalar *b) {
	uint64_t l[8];
	secp256k1_scalar_mul_512(l, a, b);
	secp256k1_scalar_reduce_512(r, l);
}

static void secp256k1_scalar_inverse_var(secp256k1_scalar *r, const secp256k1_scalar *x) {
	secp256k1_modinv64_signed62 s;
#ifdef VERIFY
	int zero_in = secp256k1_scalar_is_zero(x);
#endif
	secp256k1_scalar_to_signed62(&s, x);
	secp256k1_modinv64_var(&s, &secp256k1_const_modinfo_scalar);
	secp256k1_scalar_from_signed62(r, &s);

#ifdef VERIFY
	VERIFY_CHECK(secp256k1_scalar_is_zero(r) == zero_in);
#endif
}

inline static void secp256k1_scalar_mul_shift_var(
	secp256k1_scalar *r, const secp256k1_scalar *a, const secp256k1_scalar *b, unsigned int shift
) {
	uint64_t l[8];
	unsigned int shiftlimbs;
	unsigned int shiftlow;
	unsigned int shifthigh;
	VERIFY_CHECK(shift >= 256);
	secp256k1_scalar_mul_512(l, a, b);
	shiftlimbs = shift >> 6;
	shiftlow   = shift & 0x3F;
	shifthigh  = 64 - shiftlow;
	r->d[0]	   = shift < 512
					 ? (l[0 + shiftlimbs] >> shiftlow | (shift < 448 && shiftlow ? (l[1 + shiftlimbs] << shifthigh) : 0))
					 : 0;
	r->d[1]	   = shift < 448
					 ? (l[1 + shiftlimbs] >> shiftlow | (shift < 384 && shiftlow ? (l[2 + shiftlimbs] << shifthigh) : 0))
					 : 0;
	r->d[2]	   = shift < 384
					 ? (l[2 + shiftlimbs] >> shiftlow | (shift < 320 && shiftlow ? (l[3 + shiftlimbs] << shifthigh) : 0))
					 : 0;
	r->d[3]	   = shift < 320 ? (l[3 + shiftlimbs] >> shiftlow) : 0;
	secp256k1_scalar_cadd_bit(r, 0, (l[(shift - 1) >> 6] >> ((shift - 1) & 0x3f)) & 1);
}

/**
 * The Secp256k1 curve has an endomorphism, where lambda * (x, y) = (beta * x, y), where
 * lambda is: */
static const secp256k1_scalar secp256k1_const_lambda = SECP256K1_SCALAR_CONST(
	0x5363AD4CUL, 0xC05C30E0UL, 0xA5261C02UL, 0x8812645AUL, 0x122E22EAUL, 0x20816678UL, 0xDF02967CUL, 0x1B23BD72UL
);

#ifdef VERIFY
static void secp256k1_scalar_split_lambda_verify(
	const secp256k1_scalar *r1, const secp256k1_scalar *r2, const secp256k1_scalar *k
);
#endif

/*
 * Both lambda and beta are primitive cube roots of unity.  That is lamba^3 == 1 mod n and
 * beta^3 == 1 mod p, where n is the curve order and p is the field order.
 *
 * Furthermore, because (X^3 - 1) = (X - 1)(X^2 + X + 1), the primitive cube roots of unity are
 * roots of X^2 + X + 1.  Therefore lambda^2 + lamba == -1 mod n and beta^2 + beta == -1 mod p.
 * (The other primitive cube roots of unity are lambda^2 and beta^2 respectively.)
 *
 * Let l = -1/2 + i*sqrt(3)/2, the complex root of X^2 + X + 1. We can define a ring
 * homomorphism phi : Z[l] -> Z_n where phi(a + b*l) == a + b*lambda mod n. The kernel of phi
 * is a lattice over Z[l] (considering Z[l] as a Z-module). This lattice is generated by a
 * reduced basis {a1 + b1*l, a2 + b2*l} where
 *
 * - a1 =      {0x30,0x86,0xd2,0x21,0xa7,0xd4,0x6b,0xcd,0xe8,0x6c,0x90,0xe4,0x92,0x84,0xeb,0x15}
 * - b1 =     -{0xe4,0x43,0x7e,0xd6,0x01,0x0e,0x88,0x28,0x6f,0x54,0x7f,0xa9,0x0a,0xbf,0xe4,0xc3}
 * - a2 = {0x01,0x14,0xca,0x50,0xf7,0xa8,0xe2,0xf3,0xf6,0x57,0xc1,0x10,0x8d,0x9d,0x44,0xcf,0xd8}
 * - b2 =      {0x30,0x86,0xd2,0x21,0xa7,0xd4,0x6b,0xcd,0xe8,0x6c,0x90,0xe4,0x92,0x84,0xeb,0x15}
 *
 * "Guide to Elliptic Curve Cryptography" (Hankerson, Menezes, Vanstone) gives an algorithm
 * (algorithm 3.74) to find k1 and k2 given k, such that k1 + k2 * lambda == k mod n, and k1
 * and k2 are small in absolute value.
 *
 * The algorithm computes c1 = round(b2 * k / n) and c2 = round((-b1) * k / n), and gives
 * k1 = k - (c1*a1 + c2*a2) and k2 = -(c1*b1 + c2*b2). Instead, we use modular arithmetic, and
 * compute r2 = k2 mod n, and r1 = k1 mod n = (k - r2 * lambda) mod n, avoiding the need for
 * the constants a1 and a2.
 *
 * g1, g2 are precomputed constants used to replace division with a rounded multiplication
 * when decomposing the scalar for an endomorphism-based point multiplication.
 *
 * The possibility of using precomputed estimates is mentioned in "Guide to Elliptic Curve
 * Cryptography" (Hankerson, Menezes, Vanstone) in section 3.5.
 *
 * The derivation is described in the paper "Efficient Software Implementation of Public-Key
 * Cryptography on Sensor Networks Using the MSP430X Microcontroller" (Gouvea, Oliveira, Lopez),
 * Section 4.3 (here we use a somewhat higher-precision estimate):
 * d = a1*b2 - b1*a2
 * g1 = round(2^384 * b2/d)
 * g2 = round(2^384 * (-b1)/d)
 *
 * (Note that d is also equal to the curve order, n, here because [a1,b1] and [a2,b2]
 * can be found as outputs of the Extended Euclidean Algorithm on inputs n and lambda).
 *
 * The function below splits k into r1 and r2, such that
 * - r1 + lambda * r2 == k (mod n)
 * - either r1 < 2^128 or -r1 mod n < 2^128
 * - either r2 < 2^128 or -r2 mod n < 2^128
 *
 * See proof below.
 */
static void secp256k1_scalar_split_lambda(
	secp256k1_scalar *restrict r1, secp256k1_scalar *restrict r2, const secp256k1_scalar *restrict k
) {
	secp256k1_scalar c1, c2;
	static const secp256k1_scalar minus_b1 = SECP256K1_SCALAR_CONST(
		0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0xE4437ED6UL, 0x010E8828UL, 0x6F547FA9UL, 0x0ABFE4C3UL
	);
	static const secp256k1_scalar minus_b2 = SECP256K1_SCALAR_CONST(
		0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFEUL, 0x8A280AC5UL, 0x0774346DUL, 0xD765CDA8UL, 0x3DB1562CUL
	);
	static const secp256k1_scalar g1 = SECP256K1_SCALAR_CONST(
		0x3086D221UL, 0xA7D46BCDUL, 0xE86C90E4UL, 0x9284EB15UL, 0x3DAA8A14UL, 0x71E8CA7FUL, 0xE893209AUL, 0x45DBB031UL
	);
	static const secp256k1_scalar g2 = SECP256K1_SCALAR_CONST(
		0xE4437ED6UL, 0x010E8828UL, 0x6F547FA9UL, 0x0ABFE4C4UL, 0x221208ACUL, 0x9DF506C6UL, 0x1571B4AEUL, 0x8AC47F71UL
	);
	VERIFY_CHECK(r1 != k);
	VERIFY_CHECK(r2 != k);
	VERIFY_CHECK(r1 != r2);
	/* these _var calls are constant time since the shift amount is constant */
	secp256k1_scalar_mul_shift_var(&c1, k, &g1, 384);
	secp256k1_scalar_mul_shift_var(&c2, k, &g2, 384);
	secp256k1_scalar_mul(&c1, &c1, &minus_b1);
	secp256k1_scalar_mul(&c2, &c2, &minus_b2);
	secp256k1_scalar_add(r2, &c1, &c2);
	secp256k1_scalar_mul(r1, r2, &secp256k1_const_lambda);
	secp256k1_scalar_negate(r1, r1);
	secp256k1_scalar_add(r1, r1, k);

#ifdef VERIFY
	secp256k1_scalar_split_lambda_verify(r1, r2, k);
#endif
}

#ifdef VERIFY
/*
 * Proof for secp256k1_scalar_split_lambda's bounds.
 *
 * Let
 *  - epsilon1 = 2^256 * |g1/2^384 - b2/d|
 *  - epsilon2 = 2^256 * |g2/2^384 - (-b1)/d|
 *  - c1 = round(k*g1/2^384)
 *  - c2 = round(k*g2/2^384)
 *
 * Lemma 1: |c1 - k*b2/d| < 2^-1 + epsilon1
 *
 *    |c1 - k*b2/d|
 *  =
 *    |c1 - k*g1/2^384 + k*g1/2^384 - k*b2/d|
 * <=   {triangle inequality}
 *    |c1 - k*g1/2^384| + |k*g1/2^384 - k*b2/d|
 *  =
 *    |c1 - k*g1/2^384| + k*|g1/2^384 - b2/d|
 * <    {rounding in c1 and 0 <= k < 2^256}
 *    2^-1 + 2^256 * |g1/2^384 - b2/d|
 *  =   {definition of epsilon1}
 *    2^-1 + epsilon1
 *
 * Lemma 2: |c2 - k*(-b1)/d| < 2^-1 + epsilon2
 *
 *    |c2 - k*(-b1)/d|
 *  =
 *    |c2 - k*g2/2^384 + k*g2/2^384 - k*(-b1)/d|
 * <=   {triangle inequality}
 *    |c2 - k*g2/2^384| + |k*g2/2^384 - k*(-b1)/d|
 *  =
 *    |c2 - k*g2/2^384| + k*|g2/2^384 - (-b1)/d|
 * <    {rounding in c2 and 0 <= k < 2^256}
 *    2^-1 + 2^256 * |g2/2^384 - (-b1)/d|
 *  =   {definition of epsilon2}
 *    2^-1 + epsilon2
 *
 * Let
 *  - k1 = k - c1*a1 - c2*a2
 *  - k2 = - c1*b1 - c2*b2
 *
 * Lemma 3: |k1| < (a1 + a2 + 1)/2 < 2^128
 *
 *    |k1|
 *  =   {definition of k1}
 *    |k - c1*a1 - c2*a2|
 *  =   {(a1*b2 - b1*a2)/n = 1}
 *    |k*(a1*b2 - b1*a2)/n - c1*a1 - c2*a2|
 *  =
 *    |a1*(k*b2/n - c1) + a2*(k*(-b1)/n - c2)|
 * <=   {triangle inequality}
 *    a1*|k*b2/n - c1| + a2*|k*(-b1)/n - c2|
 * <    {Lemma 1 and Lemma 2}
 *    a1*(2^-1 + epslion1) + a2*(2^-1 + epsilon2)
 * <    {rounding up to an integer}
 *    (a1 + a2 + 1)/2
 * <    {rounding up to a power of 2}
 *    2^128
 *
 * Lemma 4: |k2| < (-b1 + b2)/2 + 1 < 2^128
 *
 *    |k2|
 *  =   {definition of k2}
 *    |- c1*a1 - c2*a2|
 *  =   {(b1*b2 - b1*b2)/n = 0}
 *    |k*(b1*b2 - b1*b2)/n - c1*b1 - c2*b2|
 *  =
 *    |b1*(k*b2/n - c1) + b2*(k*(-b1)/n - c2)|
 * <=   {triangle inequality}
 *    (-b1)*|k*b2/n - c1| + b2*|k*(-b1)/n - c2|
 * <    {Lemma 1 and Lemma 2}
 *    (-b1)*(2^-1 + epslion1) + b2*(2^-1 + epsilon2)
 * <    {rounding up to an integer}
 *    (-b1 + b2)/2 + 1
 * <    {rounding up to a power of 2}
 *    2^128
 *
 * Let
 *  - r2 = k2 mod n
 *  - r1 = k - r2*lambda mod n.
 *
 * Notice that r1 is defined such that r1 + r2 * lambda == k (mod n).
 *
 * Lemma 5: r1 == k1 mod n.
 *
 *    r1
 * ==   {definition of r1 and r2}
 *    k - k2*lambda
 * ==   {definition of k2}
 *    k - (- c1*b1 - c2*b2)*lambda
 * ==
 *    k + c1*b1*lambda + c2*b2*lambda
 * ==  {a1 + b1*lambda == 0 mod n and a2 + b2*lambda == 0 mod n}
 *    k - c1*a1 - c2*a2
 * ==  {definition of k1}
 *    k1
 *
 * From Lemma 3, Lemma 4, Lemma 5 and the definition of r2, we can conclude that
 *
 *  - either r1 < 2^128 or -r1 mod n < 2^128
 *  - either r2 < 2^128 or -r2 mod n < 2^128.
 *
 * Q.E.D.
 */
static void secp256k1_scalar_split_lambda_verify(
	const secp256k1_scalar *r1, const secp256k1_scalar *r2, const secp256k1_scalar *k
) {
	secp256k1_scalar s;
	unsigned char buf1[32];
	unsigned char buf2[32];

	/* (a1 + a2 + 1)/2 is 0xa2a8918ca85bafe22016d0b917e4dd77 */
	static const unsigned char k1_bound[32] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
											   0x00, 0x00, 0x00, 0x00, 0x00, 0xa2, 0xa8, 0x91, 0x8c, 0xa8, 0x5b,
											   0xaf, 0xe2, 0x20, 0x16, 0xd0, 0xb9, 0x17, 0xe4, 0xdd, 0x77};

	/* (-b1 + b2)/2 + 1 is 0x8a65287bd47179fb2be08846cea267ed */
	static const unsigned char k2_bound[32] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
											   0x00, 0x00, 0x00, 0x00, 0x00, 0x8a, 0x65, 0x28, 0x7b, 0xd4, 0x71,
											   0x79, 0xfb, 0x2b, 0xe0, 0x88, 0x46, 0xce, 0xa2, 0x67, 0xed};

	secp256k1_scalar_mul(&s, &secp256k1_const_lambda, r2);
	secp256k1_scalar_add(&s, &s, r1);
	VERIFY_CHECK(secp256k1_scalar_eq(&s, k));

	secp256k1_scalar_negate(&s, r1);
	secp256k1_scalar_get_b32(buf1, r1);
	secp256k1_scalar_get_b32(buf2, &s);
	VERIFY_CHECK(secp256k1_memcmp_var(buf1, k1_bound, 32) < 0 || secp256k1_memcmp_var(buf2, k1_bound, 32) < 0);

	secp256k1_scalar_negate(&s, r2);
	secp256k1_scalar_get_b32(buf1, r2);
	secp256k1_scalar_get_b32(buf2, &s);
	VERIFY_CHECK(secp256k1_memcmp_var(buf1, k2_bound, 32) < 0 || secp256k1_memcmp_var(buf2, k2_bound, 32) < 0);
}

#endif

inline static unsigned int
	secp256k1_scalar_get_bits(const secp256k1_scalar *a, unsigned int offset, unsigned int count) {
	VERIFY_CHECK((offset + count - 1) >> 6 == offset >> 6);
	return (a->d[offset >> 6] >> (offset & 0x3F)) & ((((uint64_t)1) << count) - 1);
}

inline static unsigned int
	secp256k1_scalar_get_bits_var(const secp256k1_scalar *a, unsigned int offset, unsigned int count) {
	VERIFY_CHECK(count < 32);
	VERIFY_CHECK(offset + count <= 256);
	if ((offset + count - 1) >> 6 == offset >> 6) {
		return secp256k1_scalar_get_bits(a, offset, count);
	} else {
		VERIFY_CHECK((offset >> 6) + 1 < 4);
		return ((a->d[offset >> 6] >> (offset & 0x3F)) | (a->d[(offset >> 6) + 1] << (64 - (offset & 0x3F)))) &
			   ((((uint64_t)1) << count) - 1);
	}
}
