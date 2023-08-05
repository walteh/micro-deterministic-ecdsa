//
//  sign.h
//
//  Created by walteh on 12/6/22.
//  Copyright © 2022 Walter Scott. All rights reserved.
// ---------------------------------------------------------------------
//  adapted from bitcoin-core/secp256k1
//  Copyright © 2014 Pieter Wuille. MIT software license
// ---------------------------------------------------------------------

#ifndef nonce_h
#define nonce_h

#include "scalar.h"

const secp256k1_scalar secp256k1_scalar_one	 = SECP256K1_SCALAR_CONST(0, 0, 0, 0, 0, 0, 0, 1);
const secp256k1_scalar secp256k1_scalar_zero = SECP256K1_SCALAR_CONST(0, 0, 0, 0, 0, 0, 0, 0);

int nonce_function_rfc6979(
	unsigned char *nonce32,
	const unsigned char *msg32,
	const unsigned char *key32,
	const unsigned char *algo16,
	void *data,
	unsigned int counter
);

#endif /* nonce_h */
