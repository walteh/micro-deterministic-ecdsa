/***********************************************************************
 * Copyright (c) 2013-2015 Pieter Wuille                               *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#include "recover.h"
#include "ecc/vli.h"

// static void secp256k1_ecdsa_recoverable_signature_load(
// 	const secp256k1_context *ctx,
// 	secp256k1_scalar *r,
// 	secp256k1_scalar *s,
// 	int *recid,
// 	const secp256k1_ecdsa_recoverable_signature *sig
// ) {
// 	(void)ctx;
// 	if (sizeof(secp256k1_scalar) == 32) {
// 		/* When the secp256k1_scalar type is exactly 32 byte, use its
// 		 * representation inside secp256k1_ecdsa_signature, as conversion is very fast.
// 		 * Note that secp256k1_ecdsa_signature_save must use the same representation. */
// 		memcpy(r, &sig->data[0], 32);
// 		memcpy(s, &sig->data[32], 32);
// 	} else {
// 		secp256k1_scalar_set_b32(r, &sig->data[0], NULL);
// 		secp256k1_scalar_set_b32(s, &sig->data[32], NULL);
// 	}
// 	*recid = sig->data[64];
// }

// static void secp256k1_ecdsa_recoverable_signature_save(
// 	secp256k1_ecdsa_recoverable_signature *sig, const secp256k1_scalar *r, const secp256k1_scalar *s, int recid
// ) {
// 	if (sizeof(secp256k1_scalar) == 32) {
// 		memcpy(&sig->data[0], r, 32);
// 		memcpy(&sig->data[32], s, 32);
// 	} else {
// 		secp256k1_scalar_get_b32(&sig->data[0], r);
// 		secp256k1_scalar_get_b32(&sig->data[32], s);
// 	}
// 	sig->data[64] = recid;
// }

// int secp256k1_ecdsa_recoverable_signature_parse_compact(
// 	const secp256k1_context *ctx, secp256k1_ecdsa_recoverable_signature *sig, const unsigned char *input64, int recid
// ) {
// 	secp256k1_scalar r, s;
// 	int ret		 = 1;
// 	int overflow = 0;

// 	VERIFY_CHECK(ctx != NULL);
// 	ARG_CHECK(sig != NULL);
// 	ARG_CHECK(input64 != NULL);
// 	ARG_CHECK(recid >= 0 && recid <= 3);

// 	secp256k1_scalar_set_b32(&r, &input64[0], &overflow);
// 	ret &= !overflow;
// 	secp256k1_scalar_set_b32(&s, &input64[32], &overflow);
// 	ret &= !overflow;
// 	if (ret) {
// 		secp256k1_ecdsa_recoverable_signature_save(sig, &r, &s, recid);
// 	} else {
// 		memset(sig, 0, sizeof(*sig));
// 	}
// 	return ret;
// }

// int secp256k1_ecdsa_recoverable_signature_serialize_compact(
// 	const secp256k1_context *ctx, unsigned char *output64, int *recid, const secp256k1_ecdsa_recoverable_signature *sig
// ) {
// 	secp256k1_scalar r, s;

// 	VERIFY_CHECK(ctx != NULL);
// 	ARG_CHECK(output64 != NULL);
// 	ARG_CHECK(sig != NULL);
// 	ARG_CHECK(recid != NULL);

// 	secp256k1_ecdsa_recoverable_signature_load(ctx, &r, &s, recid, sig);
// 	secp256k1_scalar_get_b32(&output64[0], &r);
// 	secp256k1_scalar_get_b32(&output64[32], &s);
// 	return 1;
// }

// int secp256k1_ecdsa_recoverable_signature_convert(
// 	const secp256k1_context *ctx, secp256k1_ecdsa_signature *sig, const secp256k1_ecdsa_recoverable_signature *sigin
// ) {
// 	secp256k1_scalar r, s;
// 	int recid;

// 	VERIFY_CHECK(ctx != NULL);
// 	ARG_CHECK(sig != NULL);
// 	ARG_CHECK(sigin != NULL);

// 	secp256k1_ecdsa_recoverable_signature_load(ctx, &r, &s, &recid, sigin);
// 	secp256k1_ecdsa_signature_save(sig, &r, &s);
// 	return 1;
// }

// static int secp256k1_ecdsa_sig_recover(
// 	const secp256k1_scalar *sigr,
// 	const secp256k1_scalar *sigs,
// 	secp256k1_ge *pubkey,
// 	const secp256k1_scalar *message,
// 	int recid
// ) {
// 	unsigned char brx[32];
// 	secp256k1_fe fx;
// 	secp256k1_ge x;
// 	secp256k1_gej xj;
// 	secp256k1_scalar rn, u1, u2;
// 	secp256k1_gej qj;
// 	int r;

// 	if (secp256k1_scalar_is_zero(sigr) || secp256k1_scalar_is_zero(sigs)) {
// 		return 0;
// 	}

// 	secp256k1_scalar_get_b32(brx, sigr);
// 	r = secp256k1_fe_set_b32_limit(&fx, brx);
// 	(void)r;
// 	VERIFY_CHECK(r); /* brx comes from a scalar, so is less than the order; certainly less than p */
// 	if (recid & 2) {
// 		if (secp256k1_fe_cmp_var(&fx, &secp256k1_ecdsa_const_p_minus_order) >= 0) {
// 			return 0;
// 		}
// 		secp256k1_fe_add(&fx, &secp256k1_ecdsa_const_order_as_fe);
// 	}
// 	if (!secp256k1_ge_set_xo_var(&x, &fx, recid & 1)) {
// 		return 0;
// 	}
// 	secp256k1_gej_set_ge(&xj, &x);
// 	secp256k1_scalar_inverse_var(&rn, sigr);
// 	secp256k1_scalar_mul(&u1, &rn, message);
// 	secp256k1_scalar_negate(&u1, &u1);
// 	secp256k1_scalar_mul(&u2, &rn, sigs);
// 	secp256k1_ecmult(&qj, &xj, &u2, &u1);
// 	secp256k1_ge_set_gej_var(pubkey, &qj);
// 	return !secp256k1_gej_is_infinity(&qj);
// }

static void uECC_word_t_set_b32_mod(uECC_word_t *r, const unsigned char *a) {
	r[0] = (uint64_t)a[31] | ((uint64_t)a[30] << 8) | ((uint64_t)a[29] << 16) | ((uint64_t)a[28] << 24) |
		   ((uint64_t)a[27] << 32) | ((uint64_t)a[26] << 40) | ((uint64_t)(a[25] & 0xF) << 48);
	r[1] = (uint64_t)((a[25] >> 4) & 0xF) | ((uint64_t)a[24] << 4) | ((uint64_t)a[23] << 12) | ((uint64_t)a[22] << 20) |
		   ((uint64_t)a[21] << 28) | ((uint64_t)a[20] << 36) | ((uint64_t)a[19] << 44);
	r[2] = (uint64_t)a[18] | ((uint64_t)a[17] << 8) | ((uint64_t)a[16] << 16) | ((uint64_t)a[15] << 24) |
		   ((uint64_t)a[14] << 32) | ((uint64_t)a[13] << 40) | ((uint64_t)(a[12] & 0xF) << 48);
	r[3] = (uint64_t)((a[12] >> 4) & 0xF) | ((uint64_t)a[11] << 4) | ((uint64_t)a[10] << 12) | ((uint64_t)a[9] << 20) |
		   ((uint64_t)a[8] << 28) | ((uint64_t)a[7] << 36) | ((uint64_t)a[6] << 44);
	r[4] = (uint64_t)a[5] | ((uint64_t)a[4] << 8) | ((uint64_t)a[3] << 16) | ((uint64_t)a[2] << 24) |
		   ((uint64_t)a[1] << 32) | ((uint64_t)a[0] << 40);
}

static int uECC_word_t_set_b32_limit(uECC_word_t *r, const unsigned char *a) {
	uECC_word_t_set_b32_mod(r, a);
	return !(
		(r[4] == 0x0FFFFFFFFFFFFULL) & ((r[3] & r[2] & r[1]) == 0xFFFFFFFFFFFFFULL) & (r[0] >= 0xFFFFEFFFFFC2FULL)
	);
}

void uECC_word_t_to_secp256k1_scalar(const uECC_word_t *val, secp256k1_scalar *scalar, int bits) {
	// Convert the uECC_word_t to bytes.
	uint8_t bytes[bits];
	uECC_vli_nativeToBytes(bytes, bits, val);

	// Set the secp256k1_scalar object.
	secp256k1_scalar_set_b32(scalar, bytes, NULL);
}

void uECC_decompress_words(const uECC_word_t *compressed_words, uECC_word_t *public_key_words, uECC_Curve curve) {
	// Convert the compressed uECC_word_t to bytes.
	uint8_t compressed_bytes[curve->num_bytes];
	uECC_vli_nativeToBytes(compressed_bytes, curve->num_bytes, compressed_words);

	// Convert the public_key uECC_word_t to bytes.
	uint8_t public_key_bytes[curve->num_bytes * 2];
	uECC_vli_nativeToBytes(public_key_bytes, curve->num_bytes * 2, public_key_words);

	// Call the original uECC_decompress function.
	uECC_decompress(compressed_bytes, public_key_bytes, curve);

	// Convert the result back to uECC_word_t.
	uECC_vli_bytesToNative(public_key_words, public_key_bytes, curve->num_bytes * 2);
}

// static int recover_public_key_rfc6979(
// 	const uint8_t *sigr, const uint8_t *sigs, uint8_t *pubkey, const uint8_t *message, int recid, uECC_Curve curve
// ) {}

// static int recover_public_key_rfc6979(
// 	const uECC_word_t *sigr,
// 	const uECC_word_t *sigs,
// 	uECC_word_t *pubkey,
// 	const uECC_word_t *message,
// 	int recid,
// 	uECC_Curve curve
// ) {
// 	// Translations of the secp256k1 functions to their micro-ecc equivalents
// 	// would go here.

// 	uECC_word_t fx;
// 	uECC_word_t x;
// 	uECC_word_t xj;
// 	uECC_word_t rn, u1, u2;
// 	// uECC_word_t qj;
// 	int r;
// 	unsigned char brx[32];

// 	if (uECC_vli_isZero(sigr, uECC_MAX_WORDS) || uECC_vli_isZero(sigs, uECC_MAX_WORDS)) {
// 		return 0;
// 	}

// 	uECC_word_t_set_b32_limit(&fx, brx);

// 	// recid handling - this would need to be implemented in a custom way
// 	// as it's specific to public key recovery.

// 	// secp256k1_ge_set_xo_var translation
// 	// You need to write a custom function for this

// 	// secp256k1_scalar_inverse_var translation
// 	// micro-ecc has uECC_vli_modInv
// 	uECC_vli_modInv(&rn, sigr, curve->n, uECC_MAX_WORDS);

// 	// secp256k1_scalar_mul translation
// 	// micro-ecc has uECC_vli_modMult
// 	uECC_vli_modMult(&u1, &rn, message, curve->n, uECC_MAX_WORDS);

// 	// secp256k1_ecmult translation
// 	EccPoint_mult(pubkey, &xj, &u2, &u1, uECC_MAX_WORDS * 2, curve);
// 	uECC_point_mult(pubkey, &qj, &u2, curve);

// 	// secp256k1_ge_set_gej_var translation
// 	// micro-ecc has EccPoint_decompress
// 	uECC_decompress_words(pubkey, &xj, curve);

// 	// return !uECC_point_isZero(&qj, curve);
// 	return 1;
// }

// int secp256k1_ecdsa_sign_recoverable(
// 	const secp256k1_context *ctx,
// 	secp256k1_ecdsa_recoverable_signature *signature,
// 	const unsigned char *msghash32,
// 	const unsigned char *seckey,
// 	secp256k1_nonce_function noncefp,
// 	const void *noncedata
// ) {
// 	secp256k1_scalar r, s;
// 	int ret, recid;
// 	VERIFY_CHECK(ctx != NULL);
// 	ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
// 	ARG_CHECK(msghash32 != NULL);
// 	ARG_CHECK(signature != NULL);
// 	ARG_CHECK(seckey != NULL);

// 	ret = secp256k1_ecdsa_sign_inner(ctx, &r, &s, &recid, msghash32, seckey, noncefp, noncedata);
// 	secp256k1_ecdsa_recoverable_signature_save(signature, &r, &s, recid);
// 	return ret;
// }

// // int uECC_sign_with_k(
// // 	const uint8_t *private_key,
// // 	const uint8_t *message_hash,
// // 	unsigned hash_size,
// // 	uECC_word_t *k,
// // 	uint8_t *recid,
// // 	uint8_t *signature,
// // 	uECC_Curve curve
// // );
// int secp256k1_ecdsa_recover(
// 	const secp256k1_context *ctx,
// 	secp256k1_pubkey *pubkey,
// 	const secp256k1_ecdsa_recoverable_signature *signature,
// 	const unsigned char *msghash32
// ) {
// 	secp256k1_ge q;
// 	secp256k1_scalar r, s;
// 	secp256k1_scalar m;
// 	int recid;
// 	VERIFY_CHECK(ctx != NULL);
// 	ARG_CHECK(msghash32 != NULL);
// 	ARG_CHECK(signature != NULL);
// 	ARG_CHECK(pubkey != NULL);

// 	secp256k1_ecdsa_recoverable_signature_load(ctx, &r, &s, &recid, signature);
// 	VERIFY_CHECK(recid >= 0 && recid < 4); /* should have been caught in parse_compact */
// 	secp256k1_scalar_set_b32(&m, msghash32, NULL);
// 	if (secp256k1_ecdsa_sig_recover(&r, &s, &q, &m, recid)) {
// 		secp256k1_pubkey_save(pubkey, &q);
// 		return 1;
// 	} else {
// 		memset(pubkey, 0, sizeof(*pubkey));
// 		return 0;
// 	}
// }

// #endif /* SECP256K1_MODULE_RECOVERY_MAIN_H */
