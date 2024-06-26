//
//  verify.h
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

#ifndef verify_h
#define verify_h

#include "../ecc/core.h"

#include <stdint.h>
#include <stdlib.h>
#include <strings.h>

int verify_rfc6979(
	const uint8_t *public_key,
	const uint8_t *message_hash,
	unsigned hash_size,
	const uint8_t *signature,
	uECC_Curve curve
);

int compute_public_key_rfc6979(const uint8_t *private_key, uint8_t *public_key, uECC_Curve curve);

#endif /* verify_h */
