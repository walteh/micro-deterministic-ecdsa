//
//  sign.c
//
//  Created by walteh on 12/8/22.
//  Copyright © 2022 Walter Scott. All rights reserved.
// ---------------------------------------------------------------------
//  adapted from micro-ecc
//  Copyright © 2015, Kenneth MacKay. BSD 2-clause license
// ---------------------------------------------------------------------
//  adapted from bitcoin-core/secp256k1
//  Copyright © 2014 Pieter Wuille. MIT software license
// ---------------------------------------------------------------------

#include "sign.h"

int sign_rfc6979(
	const uint8_t *private_key,
	const uint8_t *message_hash,
	unsigned hash_size,
	uint8_t *recid,
	uint8_t *signature,
	uECC_Curve curve
) {
	secp256k1_scalar sec, non, msg;
	int ret = 0;
	int is_sec_valid;
	unsigned char nonce32[32];
	unsigned int count = 0;
	/* Default initialization here is important so we won't pass uninit values to the cmov in the end */
	// *r = secp256k1_scalar_zero;
	// *s = secp256k1_scalar_zero;
	if (recid) {
		*recid = 0;
	}

	/* Fail if the secret key is invalid. */
	is_sec_valid = secp256k1_scalar_set_b32_seckey(&sec, private_key);
	secp256k1_scalar_cmov(&sec, &secp256k1_scalar_one, !is_sec_valid);
	secp256k1_scalar_set_b32(&msg, message_hash, NULL);
	while (1) {
		int is_nonce_valid;
		ret = !!nonce_function_rfc6979(nonce32, message_hash, private_key, NULL, NULL, count);
		if (!ret) {
			break;
		}
		is_nonce_valid = secp256k1_scalar_set_b32_seckey(&non, nonce32);
		/* The nonce is still secret here, but it being invalid is is less likely than 1:2^255. */
		// secp256k1_declassify(ctx, &is_nonce_valid, sizeof(is_nonce_valid));
		if (is_nonce_valid) {
			// uECC_word_t *a = (uECC_word_t *)non.d;
			//			uECC_vli_bytesToNative(a, nonce32, 32);
			//			secp256k1_scalar_get_b32(a, &non);
			// ret = secp256k1_ecdsa_sig_sign(&ctx->ecmult_gen_ctx, r, s, &sec, &msg, &non, recid);

			//			(uECC_word_t *)non.d
			ret = uECC_sign_with_k(private_key, message_hash, hash_size, non.d, recid, signature, curve);
			/* The final signature is no longer a secret, nor is the fact that we were successful or not. */
			// secp256k1_declassify(ctx, &ret, sizeof(ret));
			if (ret) {
				break;
			}
		}
		count++;
	}
	/* We don't want to declassify is_sec_valid and therefore the range of
	 * seckey. As a result is_sec_valid is included in ret only after ret was
	 * used as a branching variable. */
	ret &= is_sec_valid;
	memset(nonce32, 0, 32);
	secp256k1_scalar_clear(&msg);
	secp256k1_scalar_clear(&non);
	secp256k1_scalar_clear(&sec);
	//	 secp256k1_scalar_cmov(r, &secp256k1_scalar_zero, !ret);
	//	 secp256k1_scalar_cmov(s, &secp256k1_scalar_zero, !ret);
	// if (recid) {
	// 	const int zero = 0;
	// 	secp256k1_int_cmov(recid, &zero, !ret);
	// }
	return ret;
}
