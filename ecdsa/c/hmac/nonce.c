//
//  sign.h
//
//  Created by walteh on 12/8/22.
//  Copyright © 2022 Walter Scott. All rights reserved.
// ---------------------------------------------------------------------
//  adapted from bitcoin-core/secp256k1
//  Copyright © 2014 Pieter Wuille. MIT software license
// ---------------------------------------------------------------------

#include "hash.h"
#include "int128.h"
#include "scalar.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static void buffer_append(unsigned char *buf, unsigned int *offset, const void *data, unsigned int len) {
	memcpy(buf + *offset, data, len);
	*offset += len;
}

int nonce_function_rfc6979(
	unsigned char *nonce32,
	const unsigned char *msg32,
	const unsigned char *key32,
	const unsigned char *algo16,
	void *data,
	unsigned int counter
) {
	unsigned char keydata[112];
	unsigned int offset = 0;
	secp256k1_rfc6979_hmac_sha256 rng;
	unsigned int i;
	secp256k1_scalar msg;
	unsigned char msgmod32[32];
	secp256k1_scalar_set_b32(&msg, msg32, NULL);
	secp256k1_scalar_get_b32(msgmod32, &msg);
	/* We feed a byte array to the PRNG as input, consisting of:
	 * - the private key (32 bytes) and reduced message (32 bytes), see RFC 6979 3.2d.
	 * - optionally 32 extra bytes of data, see RFC 6979 3.6 Additional Data.
	 * - optionally 16 extra bytes with the algorithm name.
	 * Because the arguments have distinct fixed lengths it is not possible for
	 *  different argument mixtures to emulate each other and result in the same
	 *  nonces.
	 */
	buffer_append(keydata, &offset, key32, 32);
	buffer_append(keydata, &offset, msgmod32, 32);
	if (data != NULL) {
		buffer_append(keydata, &offset, data, 32);
	}
	if (algo16 != NULL) {
		buffer_append(keydata, &offset, algo16, 16);
	}
	secp256k1_rfc6979_hmac_sha256_initialize(&rng, keydata, offset);
	memset(keydata, 0, sizeof(keydata));
	for (i = 0; i <= counter; i++) {
		secp256k1_rfc6979_hmac_sha256_generate(&rng, nonce32, 32);
	}
	secp256k1_rfc6979_hmac_sha256_finalize(&rng);
	return 1;
}
