#include "./hmac/hash.h"
#include "./hmac/int128.h"
#include "./hmac/scalar.h"

#include "./ecc/core.h"
#include "./ecc/point.h"

#include "./ecc/vli.h"
#include "./hmac/field.h"
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

static int recover_public_key_rfc6979(
	const uECC_word_t *sigr,
	const uECC_word_t *sigs,
	uECC_word_t *pubkey,
	const uECC_word_t *message,
	int recid,
	uECC_Curve curve
);

// #if defined(__GNUC__)
// #define SECP256K1_WARN_UNUSED_RESULT __attribute__((__warn_unused_result__))
// #define SECP256K1_ARG_NONNULL(_x)	 __attribute__((__nonnull__(_x)))
// #define SECP256K1_API				 extern __attribute__((visibility("default")))
// #else
// #define SECP256K1_WARN_UNUSED_RESULT
// #define SECP256K1_ARG_NONNULL(_x)
// #define SECP256K1_API extern
// #endif

// /** Opaque data structure that holds rewritable "scratch space"
//  *
//  *  The purpose of this structure is to replace dynamic memory allocations,
//  *  because we target architectures where this may not be available. It is
//  *  essentially a resizable (within specified parameters) block of bytes,
//  *  which is initially created either by memory allocation or TODO as a pointer
//  *  into some fixed rewritable space.
//  *
//  *  Unlike the context object, this cannot safely be shared between threads
//  *  without additional synchronization logic.
//  */
// typedef struct secp256k1_scratch_space_struct secp256k1_scratch_space;

// /** Opaque data structure that holds context information
//  *
//  *  The primary purpose of context objects is to store randomization data for
//  *  enhanced protection against side-channel leakage. This protection is only
//  *  effective if the context is randomized after its creation. See
//  *  secp256k1_context_create for creation of contexts and
//  *  secp256k1_context_randomize for randomization.
//  *
//  *  A secondary purpose of context objects is to store pointers to callback
//  *  functions that the library will call when certain error states arise. See
//  *  secp256k1_context_set_error_callback as well as
//  *  secp256k1_context_set_illegal_callback for details. Future library versions
//  *  may use context objects for additional purposes.
//  *
//  *  A constructed context can safely be used from multiple threads
//  *  simultaneously, but API calls that take a non-const pointer to a context
//  *  need exclusive access to it. In particular this is the case for
//  *  secp256k1_context_destroy, secp256k1_context_preallocated_destroy,
//  *  and secp256k1_context_randomize.
//  *
//  *  Regarding randomization, either do it once at creation time (in which case
//  *  you do not need any locking for the other calls), or use a read-write lock.
//  */
// typedef struct secp256k1_context_struct secp256k1_context;

// /** Opaque data structure that holds a parsed and valid public key.
//  *
//  *  The exact representation of data inside is implementation defined and not
//  *  guaranteed to be portable between different platforms or versions. It is
//  *  however guaranteed to be 64 bytes in size, and can be safely copied/moved.
//  *  If you need to convert to a format suitable for storage or transmission,
//  *  use secp256k1_ec_pubkey_serialize and secp256k1_ec_pubkey_parse. To
//  *  compare keys, use secp256k1_ec_pubkey_cmp.
//  */
// typedef struct {
// 	unsigned char data[64];
// } secp256k1_pubkey;

// /** Opaque data structured that holds a parsed ECDSA signature.
//  *
//  *  The exact representation of data inside is implementation defined and not
//  *  guaranteed to be portable between different platforms or versions. It is
//  *  however guaranteed to be 64 bytes in size, and can be safely copied/moved.
//  *  If you need to convert to a format suitable for storage, transmission, or
//  *  comparison, use the secp256k1_ecdsa_signature_serialize_* and
//  *  secp256k1_ecdsa_signature_parse_* functions.
//  */
// typedef struct {
// 	unsigned char data[64];
// } secp256k1_ecdsa_signature;

// /** Opaque data structured that holds a parsed ECDSA signature,
//  *  supporting pubkey recovery.
//  *
//  *  The exact representation of data inside is implementation defined and not
//  *  guaranteed to be portable between different platforms or versions. It is
//  *  however guaranteed to be 65 bytes in size, and can be safely copied/moved.
//  *  If you need to convert to a format suitable for storage or transmission, use
//  *  the secp256k1_ecdsa_signature_serialize_* and
//  *  secp256k1_ecdsa_signature_parse_* functions.
//  *
//  *  Furthermore, it is guaranteed that identical signatures (including their
//  *  recoverability) will have identical representation, so they can be
//  *  memcmp'ed.
//  */
// typedef struct {
// 	unsigned char data[65];
// } secp256k1_ecdsa_recoverable_signature;

// /** Parse a compact ECDSA signature (64 bytes + recovery id).
//  *
//  *  Returns: 1 when the signature could be parsed, 0 otherwise
//  *  Args: ctx:     a secp256k1 context object
//  *  Out:  sig:     a pointer to a signature object
//  *  In:   input64: a pointer to a 64-byte compact signature
//  *        recid:   the recovery id (0, 1, 2 or 3)
//  */
// SECP256K1_API int secp256k1_ecdsa_recoverable_signature_parse_compact(
// 	const secp256k1_context *ctx, secp256k1_ecdsa_recoverable_signature *sig, const unsigned char *input64, int recid
// ) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

// /** Convert a recoverable signature into a normal signature.
//  *
//  *  Returns: 1
//  *  Args: ctx:    a secp256k1 context object.
//  *  Out:  sig:    a pointer to a normal signature.
//  *  In:   sigin:  a pointer to a recoverable signature.
//  */
// SECP256K1_API int secp256k1_ecdsa_recoverable_signature_convert(
// 	const secp256k1_context *ctx, secp256k1_ecdsa_signature *sig, const secp256k1_ecdsa_recoverable_signature *sigin
// ) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

// /** Serialize an ECDSA signature in compact format (64 bytes + recovery id).
//  *
//  *  Returns: 1
//  *  Args: ctx:      a secp256k1 context object.
//  *  Out:  output64: a pointer to a 64-byte array of the compact signature.
//  *        recid:    a pointer to an integer to hold the recovery id.
//  *  In:   sig:      a pointer to an initialized signature object.
//  */
// SECP256K1_API int secp256k1_ecdsa_recoverable_signature_serialize_compact(
// 	const secp256k1_context *ctx, unsigned char *output64, int *recid, const secp256k1_ecdsa_recoverable_signature *sig
// ) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

// /** Create a recoverable ECDSA signature.
//  *
//  *  Returns: 1: signature created
//  *           0: the nonce generation function failed, or the secret key was invalid.
//  *  Args:    ctx:       pointer to a context object (not secp256k1_context_static).
//  *  Out:     sig:       pointer to an array where the signature will be placed.
//  *  In:      msghash32: the 32-byte message hash being signed.
//  *           seckey:    pointer to a 32-byte secret key.
//  *           noncefp:   pointer to a nonce generation function. If NULL,
//  *                      secp256k1_nonce_function_default is used.
//  *           ndata:     pointer to arbitrary data used by the nonce generation function
//  *                      (can be NULL for secp256k1_nonce_function_default).
//  */
// SECP256K1_API int secp256k1_ecdsa_sign_recoverable(
// 	const secp256k1_context *ctx,
// 	secp256k1_ecdsa_recoverable_signature *sig,
// 	const unsigned char *msghash32,
// 	const unsigned char *seckey,
// 	// secp256k1_nonce_function noncefp,
// 	const void *ndata
// ) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

// /** Recover an ECDSA public key from a signature.
//  *
//  *  Returns: 1: public key successfully recovered (which guarantees a correct signature).
//  *           0: otherwise.
//  *  Args:    ctx:       pointer to a context object.
//  *  Out:     pubkey:    pointer to the recovered public key.
//  *  In:      sig:       pointer to initialized signature that supports pubkey recovery.
//  *           msghash32: the 32-byte message hash assumed to be signed.
//  */
// SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_ecdsa_recover(
// 	const secp256k1_context *ctx,
// 	secp256k1_pubkey *pubkey,
// 	const secp256k1_ecdsa_recoverable_signature *sig,
// 	const unsigned char *msghash32
// ) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);
