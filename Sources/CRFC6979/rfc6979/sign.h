//
//  sign.h
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

#ifndef sign_h
#define sign_h

#include "./ecc/core.h"
#include "./hmac/nonce.h"

#include <stdint.h>
#include <stdlib.h>
#include <strings.h>

int sign_rfc6979(
	const uint8_t *private_key,
	const uint8_t *message_hash,
	unsigned hash_size,
	uint8_t *recid,
	uint8_t *signature,
	uECC_Curve curve
);

#endif /* sign_h */
