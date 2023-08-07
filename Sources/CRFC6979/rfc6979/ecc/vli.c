//
//  vli.c
//
//  Created by walteh on 12/8/22.
//  Copyright © 2022 Walter Scott. All rights reserved.
// ---------------------------------------------------------------------
//  adapted from micro-ecc
//  Copyright © 2015, Kenneth MacKay. BSD 2-clause license
// ---------------------------------------------------------------------

#include "vli.h"

void uECC_vli_clear(uECC_word_t *vli, wordcount_t num_words) {
	wordcount_t i;
	for (i = 0; i < num_words; ++i) {
		vli[i] = 0;
	}
}

/* Constant-time comparison to zero - secure way to compare long integers */
/* Returns 1 if vli == 0, 0 otherwise. */
uECC_word_t uECC_vli_isZero(const uECC_word_t *vli, wordcount_t num_words) {
	uECC_word_t bits = 0;
	wordcount_t i;
	for (i = 0; i < num_words; ++i) {
		bits |= vli[i];
	}
	return (bits == 0);
}

/* Returns nonzero if bit 'bit' of vli is set. */
uECC_word_t uECC_vli_testBit(const uECC_word_t *vli, bitcount_t bit) {
	return (vli[bit >> uECC_WORD_BITS_SHIFT] & ((uECC_word_t)1 << (bit & uECC_WORD_BITS_MASK)));
}

/* Counts the number of words in vli. */
static wordcount_t vli_numDigits(const uECC_word_t *vli, const wordcount_t max_words) {
	wordcount_t i;
	/* Search from the end until we find a non-zero digit.
	   We do it in reverse because we expect that most digits will be nonzero. */
	for (i = max_words - 1; i >= 0 && vli[i] == 0; --i) {
	}

	return (i + 1);
}

/* Counts the number of bits required to represent vli. */
bitcount_t uECC_vli_numBits(const uECC_word_t *vli, const wordcount_t max_words) {
	uECC_word_t i;
	uECC_word_t digit;

	wordcount_t num_digits = vli_numDigits(vli, max_words);
	if (num_digits == 0) {
		return 0;
	}

	digit = vli[num_digits - 1];
	for (i = 0; digit; ++i) {
		digit >>= 1;
	}

	return (((bitcount_t)(num_digits - 1) << uECC_WORD_BITS_SHIFT) + i);
}

/* Sets dest = src. */
void uECC_vli_set(uECC_word_t *dest, const uECC_word_t *src, wordcount_t num_words) {
	wordcount_t i;
	for (i = 0; i < num_words; ++i) {
		dest[i] = src[i];
	}
}

/* Returns sign of left - right. */
cmpresult_t uECC_vli_cmp_unsafe(const uECC_word_t *left, const uECC_word_t *right, wordcount_t num_words) {
	wordcount_t i;
	for (i = num_words - 1; i >= 0; --i) {
		if (left[i] > right[i]) {
			return 1;
		} else if (left[i] < right[i]) {
			return -1;
		}
	}
	return 0;
}

/* Constant-time comparison function - secure way to compare long integers */
/* Returns one if left == right, zero otherwise. */
uECC_word_t uECC_vli_equal(const uECC_word_t *left, const uECC_word_t *right, wordcount_t num_words) {
	uECC_word_t diff = 0;
	wordcount_t i;
	for (i = num_words - 1; i >= 0; --i) {
		diff |= (left[i] ^ right[i]);
	}
	return (diff == 0);
}

/* Returns sign of left - right, in constant time. */
cmpresult_t uECC_vli_cmp(const uECC_word_t *left, const uECC_word_t *right, wordcount_t num_words) {
	uECC_word_t tmp[uECC_MAX_WORDS];
	uECC_word_t neg	  = !!uECC_vli_sub(tmp, left, right, num_words);
	uECC_word_t equal = uECC_vli_isZero(tmp, num_words);
	return (!equal - 2 * neg);
}

/* Computes vli = vli >> 1. */
void uECC_vli_rshift1(uECC_word_t *vli, wordcount_t num_words) {
	uECC_word_t *end  = vli;
	uECC_word_t carry = 0;

	vli += num_words;
	while (vli-- > end) {
		uECC_word_t temp = *vli;
		*vli			 = (temp >> 1) | carry;
		carry			 = temp << (uECC_WORD_BITS - 1);
	}
}

/* Computes result = left + right, returning carry. Can modify in place. */
uECC_word_t
	uECC_vli_add(uECC_word_t *result, const uECC_word_t *left, const uECC_word_t *right, wordcount_t num_words) {
	uECC_word_t carry = 0;
	wordcount_t i;
	for (i = 0; i < num_words; ++i) {
		uECC_word_t sum = left[i] + right[i] + carry;
		if (sum != left[i]) {
			carry = (sum < left[i]);
		}
		result[i] = sum;
	}
	return carry;
}

/* Computes result = left - right, returning borrow. Can modify in place. */
uECC_word_t
	uECC_vli_sub(uECC_word_t *result, const uECC_word_t *left, const uECC_word_t *right, wordcount_t num_words) {
	uECC_word_t borrow = 0;
	wordcount_t i;
	for (i = 0; i < num_words; ++i) {
		uECC_word_t diff = left[i] - right[i] - borrow;
		if (diff != left[i]) {
			borrow = (diff > left[i]);
		}
		result[i] = diff;
	}
	return borrow;
}

void uECC_vli_mult(uECC_word_t *result, const uECC_word_t *left, const uECC_word_t *right, wordcount_t num_words) {
	uECC_word_t r0 = 0;
	uECC_word_t r1 = 0;
	uECC_word_t r2 = 0;
	wordcount_t i, k;

	/* Compute each digit of result in sequence, maintaining the carries. */
	for (k = 0; k < num_words; ++k) {
		for (i = 0; i <= k; ++i) {
			muladd(left[i], right[k - i], &r0, &r1, &r2);
		}
		result[k] = r0;
		r0		  = r1;
		r1		  = r2;
		r2		  = 0;
	}
	for (k = num_words; k < num_words * 2 - 1; ++k) {
		for (i = (k + 1) - num_words; i < num_words; ++i) {
			muladd(left[i], right[k - i], &r0, &r1, &r2);
		}
		result[k] = r0;
		r0		  = r1;
		r1		  = r2;
		r2		  = 0;
	}
	result[num_words * 2 - 1] = r0;
}

/* Computes result = (left + right) % mod.
   Assumes that left < mod and right < mod, and that result does not overlap mod. */
void uECC_vli_modAdd(
	uECC_word_t *result,
	const uECC_word_t *left,
	const uECC_word_t *right,
	const uECC_word_t *mod,
	wordcount_t num_words
) {
	//	uECC_word_t me = *mod;
	uECC_word_t carry = uECC_vli_add(result, left, right, num_words);
	if (carry || uECC_vli_cmp_unsafe(mod, result, num_words) != 1) {
		/* result > mod (result = mod + remainder), so subtract mod to get remainder. */
		uECC_vli_sub(result, result, mod, num_words);
	}
}

/* Computes result = (left - right) % mod.
   Assumes that left < mod and right < mod, and that result does not overlap mod. */
void uECC_vli_modSub(
	uECC_word_t *result,
	const uECC_word_t *left,
	const uECC_word_t *right,
	const uECC_word_t *mod,
	wordcount_t num_words
) {
	uECC_word_t l_borrow = uECC_vli_sub(result, left, right, num_words);
	if (l_borrow) {
		/* In this case, result == -diff == (max int) - diff. Since -x % d == d - x,
		   we can get the correct result from result + mod (with overflow). */
		uECC_vli_add(result, result, mod, num_words);
	}
}

/* Computes result = product % mod, where product is 2N words long. */
/* Currently only designed to work for curve_p or curve_n. */
void uECC_vli_mmod(uECC_word_t *result, uECC_word_t *product, const uECC_word_t *mod, wordcount_t num_words) {
	uECC_word_t mod_multiple[2 * uECC_MAX_WORDS];
	uECC_word_t tmp[2 * uECC_MAX_WORDS];
	uECC_word_t *v[2] = {tmp, product};
	uECC_word_t index;

	/* Shift mod so its highest set bit is at the maximum position. */
	bitcount_t shift	   = (num_words * 2 * uECC_WORD_BITS) - uECC_vli_numBits(mod, num_words);
	wordcount_t word_shift = shift / uECC_WORD_BITS;
	wordcount_t bit_shift  = shift % uECC_WORD_BITS;
	uECC_word_t carry	   = 0;
	uECC_vli_clear(mod_multiple, word_shift);
	if (bit_shift > 0) {
		for (index = 0; index < (uECC_word_t)num_words; ++index) {
			mod_multiple[word_shift + index] = (mod[index] << bit_shift) | carry;
			carry							 = mod[index] >> (uECC_WORD_BITS - bit_shift);
		}
	} else {
		uECC_vli_set(mod_multiple + word_shift, mod, num_words);
	}

	for (index = 1; shift >= 0; --shift) {
		uECC_word_t borrow = 0;
		wordcount_t i;
		for (i = 0; i < num_words * 2; ++i) {
			uECC_word_t diff = v[index][i] - mod_multiple[i] - borrow;
			if (diff != v[index][i]) {
				borrow = (diff > v[index][i]);
			}
			v[1 - index][i] = diff;
		}
		index = !(index ^ borrow); /* Swap the index if there was no borrow */
		uECC_vli_rshift1(mod_multiple, num_words);
		mod_multiple[num_words - 1] |= mod_multiple[num_words] << (uECC_WORD_BITS - 1);
		uECC_vli_rshift1(mod_multiple + num_words, num_words);
	}
	uECC_vli_set(result, v[index], num_words);
}

/* Computes result = (left * right) % mod. */
void uECC_vli_modMult(
	uECC_word_t *result,
	const uECC_word_t *left,
	const uECC_word_t *right,
	const uECC_word_t *mod,
	wordcount_t num_words
) {
	uECC_word_t product[2 * uECC_MAX_WORDS];
	uECC_vli_mult(product, left, right, num_words);
	uECC_vli_mmod(result, product, mod, num_words);
}

/* Computes result = left^2 % mod. */
void uECC_vli_modSquare(uECC_word_t *result, const uECC_word_t *left, const uECC_word_t *mod, wordcount_t num_words) {
	uECC_word_t product[2 * uECC_MAX_WORDS];
	uECC_vli_square(product, left, num_words);
	uECC_vli_mmod(result, product, mod, num_words);
}

#define EVEN(vli) (!(vli[0] & 1))
static void vli_modInv_update(uECC_word_t *uv, const uECC_word_t *mod, wordcount_t num_words) {
	uECC_word_t carry = 0;
	if (!EVEN(uv)) {
		carry = uECC_vli_add(uv, uv, mod, num_words);
	}
	uECC_vli_rshift1(uv, num_words);
	if (carry) {
		uv[num_words - 1] |= HIGH_BIT_SET;
	}
}

/* Computes result = (1 / input) % mod. All VLIs are the same size.
   See "From Euclid's GCD to Montgomery Multiplication to the Great Divide" */
void uECC_vli_modInv(uECC_word_t *result, const uECC_word_t *input, const uECC_word_t *mod, wordcount_t num_words) {
	uECC_word_t a[uECC_MAX_WORDS], b[uECC_MAX_WORDS], u[uECC_MAX_WORDS], v[uECC_MAX_WORDS];
	cmpresult_t cmpResult;

	if (uECC_vli_isZero(input, num_words)) {
		uECC_vli_clear(result, num_words);
		return;
	}

	uECC_vli_set(a, input, num_words);
	uECC_vli_set(b, mod, num_words);
	uECC_vli_clear(u, num_words);
	u[0] = 1;
	uECC_vli_clear(v, num_words);
	while ((cmpResult = uECC_vli_cmp_unsafe(a, b, num_words)) != 0) {
		if (EVEN(a)) {
			uECC_vli_rshift1(a, num_words);
			vli_modInv_update(u, mod, num_words);
		} else if (EVEN(b)) {
			uECC_vli_rshift1(b, num_words);
			vli_modInv_update(v, mod, num_words);
		} else if (cmpResult > 0) {
			uECC_vli_sub(a, a, b, num_words);
			uECC_vli_rshift1(a, num_words);
			if (uECC_vli_cmp_unsafe(u, v, num_words) < 0) {
				uECC_vli_add(u, u, mod, num_words);
			}
			uECC_vli_sub(u, u, v, num_words);
			vli_modInv_update(u, mod, num_words);
		} else {
			uECC_vli_sub(b, b, a, num_words);
			uECC_vli_rshift1(b, num_words);
			if (uECC_vli_cmp_unsafe(v, u, num_words) < 0) {
				uECC_vli_add(v, v, mod, num_words);
			}
			uECC_vli_sub(v, v, u, num_words);
			vli_modInv_update(v, mod, num_words);
		}
	}
	uECC_vli_set(result, u, num_words);
}

static void mul2add(uECC_word_t a, uECC_word_t b, uECC_word_t *r0, uECC_word_t *r1, uECC_word_t *r2) {
	uECC_dword_t p	 = (uECC_dword_t)a * b;
	uECC_dword_t r01 = ((uECC_dword_t)(*r1) << uECC_WORD_BITS) | *r0;
	*r2 += (p >> (uECC_WORD_BITS * 2 - 1));
	p *= 2;
	r01 += p;
	*r2 += (r01 < p);
	*r1 = r01 >> uECC_WORD_BITS;
	*r0 = (uECC_word_t)r01;
}

void uECC_vli_square(uECC_word_t *result, const uECC_word_t *left, wordcount_t num_words) {
	uECC_word_t r0 = 0;
	uECC_word_t r1 = 0;
	uECC_word_t r2 = 0;

	wordcount_t i, k;

	for (k = 0; k < num_words * 2 - 1; ++k) {
		uECC_word_t min = (k < num_words ? 0 : (k + 1) - num_words);
		for (i = min; i <= k && i <= k - i; ++i) {
			if (i < k - i) {
				mul2add(left[i], left[k - i], &r0, &r1, &r2);
			} else {
				muladd(left[i], left[k - i], &r0, &r1, &r2);
			}
		}
		result[k] = r0;
		r0		  = r1;
		r1		  = r2;
		r2		  = 0;
	}

	result[num_words * 2 - 1] = r0;
}

#include "../hmac/scalar.h"

void uECC_vli_negate(uECC_word_t *vli) { secp256k1_scalar_negate((secp256k1_scalar *)vli, (secp256k1_scalar *)vli); }

int uECC_vli_is_high(uECC_word_t *vli) { return secp256k1_scalar_is_high((secp256k1_scalar *)vli); }
