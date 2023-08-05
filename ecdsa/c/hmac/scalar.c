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
#include "hash.h"
#include "int128.h"

#include <string.h>

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
