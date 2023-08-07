//
//  core.c
//
//  Created by walteh on 12/8/22.
//  Copyright © 2022 Walter Scott. All rights reserved.
// ---------------------------------------------------------------------
//  adapted from micro-ecc
//  Copyright © 2015, Kenneth MacKay. BSD 2-clause license
// ---------------------------------------------------------------------

#include "core.h"
#include "common.h"
#include <stdint.h>

int uECC_curve_private_key_size(uECC_Curve curve) { return BITS_TO_BYTES(curve->num_n_bits); }

int uECC_curve_public_key_size(uECC_Curve curve) { return 2 * curve->num_bytes; }

void uECC_vli_nativeToBytes(uint8_t *bytes, int num_bytes, const uECC_word_t *native) {
	int i;
	for (i = 0; i < num_bytes; ++i) {
		unsigned b = num_bytes - 1 - i;
		bytes[i]   = native[b / uECC_WORD_SIZE] >> (8 * (b % uECC_WORD_SIZE));
	}
}

void uECC_vli_bytesToNative(uECC_word_t *native, const uint8_t *bytes, int num_bytes) {
	int i;
	uECC_vli_clear(native, (num_bytes + (uECC_WORD_SIZE - 1)) / uECC_WORD_SIZE);
	for (i = 0; i < num_bytes; ++i) {
		unsigned b = num_bytes - 1 - i;
		native[b / uECC_WORD_SIZE] |= (uECC_word_t)bytes[i] << (8 * (b % uECC_WORD_SIZE));
	}
}

int uECC_shared_secret(const uint8_t *public_key, const uint8_t *private_key, uint8_t *secret, uECC_Curve curve) {
	uECC_word_t _public[uECC_MAX_WORDS * 2];
	uECC_word_t _private[uECC_MAX_WORDS];

	uECC_word_t tmp[uECC_MAX_WORDS];
	uECC_word_t *p2[2]	   = {_private, tmp};
	uECC_word_t *initial_Z = 0;
	uECC_word_t carry;
	wordcount_t num_words = curve->num_words;
	wordcount_t num_bytes = curve->num_bytes;

	uECC_vli_bytesToNative(_private, private_key, BITS_TO_BYTES(curve->num_n_bits));
	uECC_vli_bytesToNative(_public, public_key, num_bytes);
	uECC_vli_bytesToNative(_public + num_words, public_key + num_bytes, num_bytes);

	/* Regularize the bitcount for the private key so that attackers cannot use a side channel
	   attack to learn the number of leading zeros. */
	carry = regularize_k(_private, _private, tmp, curve);

	EccPoint_mult(_public, _public, p2[!carry], initial_Z, curve->num_n_bits + 1, curve);

	uECC_vli_nativeToBytes(secret, num_bytes, _public);

	return !EccPoint_isZero(_public, curve);
}

void uECC_compress(const uint8_t *public_key, uint8_t *compressed, uECC_Curve curve) {
	wordcount_t i;
	for (i = 0; i < curve->num_bytes; ++i) {
		compressed[i + 1] = public_key[i];
	}

	compressed[0] = 2 + (public_key[curve->num_bytes * 2 - 1] & 0x01);
}

void uECC_decompress(const uint8_t *compressed, uint8_t *public_key, uECC_Curve curve) {
	uECC_word_t point[uECC_MAX_WORDS * 2];
	uECC_word_t *y = point + curve->num_words;

	uECC_vli_bytesToNative(point, compressed + 1, curve->num_bytes);

	curve->x_side(y, point, curve);
	curve->mod_sqrt(y, curve);

	if ((y[0] & 0x01) != (compressed[0] & 0x01)) {
		uECC_vli_sub(y, curve->p, y, curve->num_words);
	}
}

int uECC_valid_point(const uECC_word_t *point, uECC_Curve curve) {
	uECC_word_t tmp1[uECC_MAX_WORDS];
	uECC_word_t tmp2[uECC_MAX_WORDS];
	wordcount_t num_words = curve->num_words;

	/* The point at infinity is invalid. */
	if (EccPoint_isZero(point, curve)) {
		return 0;
	}

	/* x and y must be smaller than p. */
	if (uECC_vli_cmp_unsafe(curve->p, point, num_words) != 1 ||
		uECC_vli_cmp_unsafe(curve->p, point + num_words, num_words) != 1) {
		return 0;
	}

	uECC_vli_modSquare_fast(tmp1, point + num_words, curve);
	curve->x_side(tmp2, point, curve); /* tmp2 = x^3 + ax + b */

	/* Make sure that y^2 == x^3 + ax + b */
	return (int)(uECC_vli_equal(tmp1, tmp2, num_words));
}

int uECC_valid_public_key(const uint8_t *public_key, uECC_Curve curve) {
	uECC_word_t _public[uECC_MAX_WORDS * 2];

#if uECC_VLI_NATIVE_LITTLE_ENDIAN == 0
	uECC_vli_bytesToNative(_public, public_key, curve->num_bytes);
	uECC_vli_bytesToNative(_public + curve->num_words, public_key + curve->num_bytes, curve->num_bytes);
#endif
	return uECC_valid_point(_public, curve);
}

int uECC_compute_public_key(const uint8_t *private_key, uint8_t *public_key, uECC_Curve curve) {
	uECC_word_t _private[uECC_MAX_WORDS];
	uECC_word_t _public[uECC_MAX_WORDS * 2];

#if uECC_VLI_NATIVE_LITTLE_ENDIAN == 0
	uECC_vli_bytesToNative(_private, private_key, BITS_TO_BYTES(curve->num_n_bits));
#endif

	/* Make sure the private key is in the range [1, n-1]. */
	if (uECC_vli_isZero(_private, BITS_TO_WORDS(curve->num_n_bits))) {
		return 0;
	}

	if (uECC_vli_cmp(curve->n, _private, BITS_TO_WORDS(curve->num_n_bits)) != 1) {
		return 0;
	}

	/* Compute public key. */
	if (!EccPoint_compute_public_key(_public, _private, curve)) {
		return 0;
	}

#if uECC_VLI_NATIVE_LITTLE_ENDIAN == 0
	uECC_vli_nativeToBytes(public_key, curve->num_bytes, _public);
	uECC_vli_nativeToBytes(public_key + curve->num_bytes, curve->num_bytes, _public + curve->num_words);
#endif
	return 1;
}

/* -------- ECDSA code -------- */

static void bits2int(uECC_word_t *native, const uint8_t *bits, unsigned bits_size, uECC_Curve curve) {
	unsigned num_n_bytes = BITS_TO_BYTES(curve->num_n_bits);
	unsigned num_n_words = BITS_TO_WORDS(curve->num_n_bits);
	int shift;
	uECC_word_t carry;
	uECC_word_t *ptr;

	if (bits_size > num_n_bytes) {
		bits_size = num_n_bytes;
	}

	uECC_vli_clear(native, num_n_words);

	uECC_vli_bytesToNative(native, bits, bits_size);

	if (bits_size * 8 <= (unsigned)curve->num_n_bits) {
		return;
	}
	shift = bits_size * 8 - curve->num_n_bits;
	carry = 0;
	ptr	  = native + num_n_words;
	while (ptr-- > native) {
		uECC_word_t temp = *ptr;
		*ptr			 = (temp >> shift) | carry;
		carry			 = temp << (uECC_WORD_BITS - shift);
	}

	/* Reduce mod curve_n */
	if (uECC_vli_cmp_unsafe(curve->n, native, num_n_words) != 1) {
		uECC_vli_sub(native, native, curve->n, num_n_words);
	}
}

int uECC_sign_with_k(
	const uint8_t *private_key,
	const uint8_t *message_hash,
	unsigned hash_size,
	uECC_word_t *k,
	uint8_t *recid,
	uint8_t *signature,
	uECC_Curve curve
) {
	int high;
	uECC_word_t tmp[uECC_MAX_WORDS];
	uECC_word_t s[uECC_MAX_WORDS];
	uECC_word_t *k2[2]	   = {tmp, s};
	uECC_word_t *initial_Z = 0;

	uECC_word_t p[uECC_MAX_WORDS * 2];

	uECC_word_t carry;
	const wordcount_t num_words	  = curve->num_words;
	const wordcount_t num_n_words = BITS_TO_WORDS(curve->num_n_bits);
	const bitcount_t num_n_bits	  = curve->num_n_bits;

	/* Make sure 0 < k < curve_n */
	if (uECC_vli_isZero(k, num_words) || uECC_vli_cmp(curve->n, k, num_n_words) != 1) {
		return 0;
	}

	carry = regularize_k(k, tmp, s, curve);

	EccPoint_mult(p, curve->G, k2[!carry], initial_Z, num_n_bits + 1, curve);
	if (uECC_vli_isZero(p, num_words)) {
		return 0;
	}

	if (recid) {
		*recid = uECC_vli_testBit(p + num_words, 0);
	}

	/* Prevent side channel analysis of uECC_vli_modInv() to determine
	   bits of k / the private key by premultiplying by a random number */
	uECC_vli_modMult(k, k, tmp, curve->n, num_n_words); /* k' = rand * k */
	uECC_vli_modInv(k, k, curve->n, num_n_words);		/* k = 1 / k' */
	uECC_vli_modMult(k, k, tmp, curve->n, num_n_words); /* k = 1 / k */

	uECC_vli_nativeToBytes(signature, curve->num_bytes, p); /* store r = p.x */

	uECC_vli_bytesToNative(tmp, private_key, BITS_TO_BYTES(curve->num_n_bits)); /* tmp = d */

	s[num_n_words - 1] = 0;
	uECC_vli_set(s, p, num_words);
	uECC_vli_modMult(s, tmp, s, curve->n, num_n_words); /* s = r*d */

	bits2int(tmp, message_hash, hash_size, curve);
	uECC_vli_modAdd(s, tmp, s, curve->n, num_n_words); /* s = e + r*d */
	uECC_vli_modMult(s, s, k, curve->n, num_n_words);  /* s = (e + r*d) / k */
	if (uECC_vli_numBits(s, num_n_words) > (bitcount_t)curve->num_bytes * 8) {
		return 0;
	}

	high = uECC_vli_is_high(s);

	uECC_vli_negate(s);

	uECC_vli_nativeToBytes(signature + curve->num_bytes, curve->num_bytes, s);

	if (recid) {
		*recid ^= high;
	}

	return 1;
}

static bitcount_t smax(bitcount_t a, bitcount_t b) { return (a > b ? a : b); }

int uECC_verify(
	const uint8_t *public_key,
	const uint8_t *message_hash,
	unsigned hash_size,
	const uint8_t *signature,
	uECC_Curve curve
) {
	uECC_word_t u1[uECC_MAX_WORDS], u2[uECC_MAX_WORDS];
	uECC_word_t z[uECC_MAX_WORDS];
	uECC_word_t sum[uECC_MAX_WORDS * 2];
	uECC_word_t rx[uECC_MAX_WORDS];
	uECC_word_t ry[uECC_MAX_WORDS];
	uECC_word_t tx[uECC_MAX_WORDS];
	uECC_word_t ty[uECC_MAX_WORDS];
	uECC_word_t tz[uECC_MAX_WORDS];
	const uECC_word_t *points[4];
	const uECC_word_t *point;
	bitcount_t num_bits;
	bitcount_t i;
	uECC_word_t _public[uECC_MAX_WORDS * 2];
	uECC_word_t r[uECC_MAX_WORDS], s[uECC_MAX_WORDS];
	wordcount_t num_words	= curve->num_words;
	wordcount_t num_n_words = BITS_TO_WORDS(curve->num_n_bits);

	rx[num_n_words - 1] = 0;
	r[num_n_words - 1]	= 0;
	s[num_n_words - 1]	= 0;

	uECC_vli_bytesToNative(_public, public_key, curve->num_bytes);
	uECC_vli_bytesToNative(_public + num_words, public_key + curve->num_bytes, curve->num_bytes);
	uECC_vli_bytesToNative(r, signature, curve->num_bytes);
	uECC_vli_bytesToNative(s, signature + curve->num_bytes, curve->num_bytes);

	/* r, s must not be 0. */
	if (uECC_vli_isZero(r, num_words) || uECC_vli_isZero(s, num_words)) {
		return 0;
	}

	/* r, s must be < n. */
	if (uECC_vli_cmp_unsafe(curve->n, r, num_n_words) != 1 || uECC_vli_cmp_unsafe(curve->n, s, num_n_words) != 1) {
		return 0;
	}

	/* Calculate u1 and u2. */
	uECC_vli_modInv(z, s, curve->n, num_n_words); /* z = 1/s */
	u1[num_n_words - 1] = 0;
	bits2int(u1, message_hash, hash_size, curve);
	uECC_vli_modMult(u1, u1, z, curve->n, num_n_words); /* u1 = e/s */
	uECC_vli_modMult(u2, r, z, curve->n, num_n_words);	/* u2 = r/s */

	/* Calculate sum = G + Q. */
	uECC_vli_set(sum, _public, num_words);
	uECC_vli_set(sum + num_words, _public + num_words, num_words);
	uECC_vli_set(tx, curve->G, num_words);
	uECC_vli_set(ty, curve->G + num_words, num_words);
	uECC_vli_modSub(z, sum, tx, curve->p, num_words); /* z = x2 - x1 */
	XYcZ_add(tx, ty, sum, sum + num_words, curve);
	uECC_vli_modInv(z, z, curve->p, num_words); /* z = 1/z */
	apply_z(sum, sum + num_words, z, curve);

	/* Use Shamir's trick to calculate u1*G + u2*Q */
	points[0] = 0;
	points[1] = curve->G;
	points[2] = _public;
	points[3] = sum;
	num_bits  = smax(uECC_vli_numBits(u1, num_n_words), uECC_vli_numBits(u2, num_n_words));

	point = points[(!!uECC_vli_testBit(u1, num_bits - 1)) | ((!!uECC_vli_testBit(u2, num_bits - 1)) << 1)];
	uECC_vli_set(rx, point, num_words);
	uECC_vli_set(ry, point + num_words, num_words);
	uECC_vli_clear(z, num_words);
	z[0] = 1;

	for (i = num_bits - 2; i >= 0; --i) {
		uECC_word_t index;
		curve->double_jacobian(rx, ry, z, curve);

		index = (!!uECC_vli_testBit(u1, i)) | ((!!uECC_vli_testBit(u2, i)) << 1);
		point = points[index];
		if (point) {
			uECC_vli_set(tx, point, num_words);
			uECC_vli_set(ty, point + num_words, num_words);
			apply_z(tx, ty, z, curve);
			uECC_vli_modSub(tz, rx, tx, curve->p, num_words); /* Z = x2 - x1 */
			XYcZ_add(tx, ty, rx, ry, curve);
			uECC_vli_modMult_fast(z, z, tz, curve);
		}
	}

	uECC_vli_modInv(z, z, curve->p, num_words); /* Z = 1/Z */
	apply_z(rx, ry, z, curve);

	/* v = x1 (mod n) */
	if (uECC_vli_cmp_unsafe(curve->n, rx, num_n_words) != 1) {
		uECC_vli_sub(rx, rx, curve->n, num_n_words);
	}

	/* Accept only if v == r. */
	return (int)(uECC_vli_equal(rx, r, num_words));
}

/* ECC Point Addition R = P + Q*/
static void uECC_point_add(const uECC_word_t *R, const uECC_word_t *P, const uECC_word_t *Q, uECC_Curve curve) {}

static void uECC_vli_rshift(uECC_word_t *result, const uECC_word_t *vli, unsigned int shift) {}

static int uECC_point_cmp(const uECC_word_t *P, const uECC_word_t *Q, uECC_Curve curve) { return 0; }

int uECC_recover(
	const uint8_t *signature,
	const uint8_t *message_hash,
	unsigned hash_size,
	int recid,
	uint8_t *public_key_recovered,
	uECC_Curve curve
) {
	uECC_word_t r[uECC_MAX_WORDS], s[uECC_MAX_WORDS];
	uECC_word_t e[uECC_MAX_WORDS], z[uECC_MAX_WORDS];
	uECC_word_t u1[uECC_MAX_WORDS], u2[uECC_MAX_WORDS];
	uECC_word_t R[uECC_MAX_WORDS * 2], G[uECC_MAX_WORDS * 2], Q_A[uECC_MAX_WORDS * 2];
	const wordcount_t num_words	  = curve->num_words;
	const wordcount_t num_n_words = BITS_TO_WORDS(curve->num_n_bits);

	uECC_vli_bytesToNative(r, signature, curve->num_bytes);
	uECC_vli_bytesToNative(s, signature + curve->num_bytes, curve->num_bytes);

	/* Check if r and s are in the interval [1, n-1] */
	if (uECC_vli_isZero(r, num_words) || uECC_vli_isZero(s, num_words) || uECC_vli_cmp(curve->n, r, num_n_words) != 1 ||
		uECC_vli_cmp(curve->n, s, num_n_words) != 1) {
		return 0;
	}

	/* Calculate e */
	bits2int(e, message_hash, hash_size, curve);

	/* Get Ln leftmost bits of e */
	uECC_vli_rshift(z, e, BITS_TO_WORDS(curve->num_n_bits));

	/* Calculate u1 and u2 */
	uECC_vli_modMult(u1, z, r, curve->n, num_n_words);
	uECC_vli_modInv(u1, u1, curve->n, num_n_words);
	uECC_vli_modMult(u2, s, r, curve->n, num_n_words);
	uECC_vli_modInv(u2, u2, curve->n, num_n_words);

	/* Compute the curve point R */
	uECC_vli_set(R, r, num_words);
	for (int j = 0; j < recid / 2; j++) {
		uECC_vli_add(R, R, curve->n, num_words);
	}

	/* Try all possible curve points R */
	for (int i = 0; i < 2; i++) {
		if (!uECC_valid_point(R, curve)) {
			return 0;
		}

		/* Calculate Q_A = u1*G + u2*R */
		uECC_vli_set(G, curve->G, num_words);
		uECC_vli_set(G + num_words, curve->G + num_words, num_words);
		EccPoint_mult(R, G, u1, 0, num_n_words + 1, curve);
		EccPoint_mult(Q_A, R, u2, 0, num_n_words + 1, curve);
		uECC_point_add(Q_A, Q_A, R, curve);

		if (uECC_point_cmp(Q_A, public_key_recovered, curve)) {
			return 1;
		}

		/* If the first y coordinate (j=0) didn't work, try the second one (j=1). */
		if (i == 0) {
			// to adjust
			// uECC_vli_modSub(R + num_words, curve->p, R + num_words, i, num_words);
		}
	}

	return 0;
}
