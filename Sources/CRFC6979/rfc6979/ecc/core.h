//
//  core.h
//
//  Created by walteh on 12/8/22.
//  Copyright © 2022 Walter Scott. All rights reserved.
// ---------------------------------------------------------------------
//  adapted from micro-ecc
//  Copyright © 2015, Kenneth MacKay. BSD 2-clause license
// ---------------------------------------------------------------------

#ifndef core_h
#define core_h

#include "curve.h"
#include "point.h"
#include "vli.h"

/* uECC_curve_private_key_size() function.

Returns the size of a private key for the curve in bytes.
*/
int uECC_curve_private_key_size(uECC_Curve curve);

/* uECC_curve_public_key_size() function.

Returns the size of a public key for the curve in bytes.
*/
int uECC_curve_public_key_size(uECC_Curve curve);

/* uECC_shared_secret() function.
Compute a shared secret given your secret key and someone else's public key. If the public key
is not from a trusted source and has not been previously verified, you should verify it first
using uECC_valid_public_key().
Note: It is recommended that you hash the result of uECC_shared_secret() before using it for
symmetric encryption or HMAC.

Inputs:
	public_key  - The public key of the remote party.
	private_key - Your private key.

Outputs:
	secret - Will be filled in with the shared secret value. Must be the same size as the
			 curve size; for example, if the curve is secp256r1, secret must be 32 bytes long.

Returns 1 if the shared secret was generated successfully, 0 if an error occurred.
*/
int uECC_shared_secret(const uint8_t *public_key, const uint8_t *private_key, uint8_t *secret, uECC_Curve curve);

/* uECC_compress() function.
Compress a public key.

Inputs:
	public_key - The public key to compress.

Outputs:
	compressed - Will be filled in with the compressed public key. Must be at least
				 (curve size + 1) bytes long; for example, if the curve is secp256r1,
				 compressed must be 33 bytes long.
*/
void uECC_compress(const uint8_t *public_key, uint8_t *compressed, uECC_Curve curve);

/* uECC_decompress() function.
Decompress a compressed public key.

Inputs:
	compressed - The compressed public key.

Outputs:
	public_key - Will be filled in with the decompressed public key.
*/
void uECC_decompress(const uint8_t *compressed, uint8_t *public_key, uECC_Curve curve);

/* uECC_valid_public_key() function.
Check to see if a public key is valid.

Note that you are not required to check for a valid public key before using any other uECC
functions. However, you may wish to avoid spending CPU time computing a shared secret or
verifying a signature using an invalid public key.

Inputs:
	public_key - The public key to check.

Returns 1 if the public key is valid, 0 if it is invalid.
*/
int uECC_valid_public_key(const uint8_t *public_key, uECC_Curve curve);

/* uECC_compute_public_key() function.
Compute the corresponding public key for a private key.

Inputs:
	private_key - The private key to compute the public key for

Outputs:
	public_key - Will be filled in with the corresponding public key

Returns 1 if the key was computed successfully, 0 if an error occurred.
*/
int uECC_compute_public_key(const uint8_t *private_key, uint8_t *public_key, uECC_Curve curve);

/* uECC_sign_with_k() function.
Generate an ECDSA signature for a given hash value.

Usage: Compute a hash of the data you wish to sign (SHA-2 is recommended) and pass it in to
this function along with your private key.

Inputs:
	private_key  - Your private key.
	message_hash - The hash of the message to sign.
	hash_size    - The size of message_hash in bytes.

Outputs:
	signature - Will be filled in with the signature value. Must be at least 2 * curve size long.
				For example, if the curve is secp256r1, signature must be 64 bytes long.

Returns 1 if the signature generated successfully, 0 if an error occurred.
*/
int uECC_sign_with_k(
	const uint8_t *private_key,
	const uint8_t *message_hash,
	unsigned hash_size,
	uECC_word_t *k,
	uint8_t *recid,
	uint8_t *signature,
	uECC_Curve curve
);

/* uECC_verify() function.
Verify an ECDSA signature.

Usage: Compute the hash of the signed data using the same hash as the signer and
pass it to this function along with the signer's public key and the signature values (r and s).

Inputs:
	public_key   - The signer's public key.
	message_hash - The hash of the signed data.
	hash_size    - The size of message_hash in bytes.
	signature    - The signature value.

Returns 1 if the signature is valid, 0 if it is invalid.
*/
int uECC_verify(
	const uint8_t *public_key,
	const uint8_t *message_hash,
	unsigned hash_size,
	const uint8_t *signature,
	uECC_Curve curve
);

int uECC_recover(
	const uint8_t *signature,
	const uint8_t *hash,
	unsigned hash_size,
	int recid,
	uint8_t *recovered_pub,
	uECC_Curve curve
);

#endif /* micro_h */
