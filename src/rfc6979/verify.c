//
//  verify.c
//
//  Created by walteh on 2023-08-05.
//  Copyright © 2023 Walter Scott. All rights reserved.
// ---------------------------------------------------------------------
//  adapted from micro-ecc
//  Copyright © 2015, Kenneth MacKay. BSD 2-clause license
// ---------------------------------------------------------------------
//  adapted from bitcoin-core/secp256k1
//  Copyright © 2014 Pieter Wuille. MIT software license
// ---------------------------------------------------------------------

#include "verify.h"

int verify_rfc6979(
	const uint8_t *public_key,
	const uint8_t *message_hash,
	unsigned hash_size,
	const uint8_t *signature,
	uECC_Curve curve
) {
	return uECC_verify(public_key, message_hash, hash_size, signature, curve);
}

int compute_public_key_rfc6979(const uint8_t *private_key, uint8_t *public_key, uECC_Curve curve) {
	return uECC_compute_public_key(private_key, public_key, curve);
}
