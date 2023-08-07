

#include <stdint.h>

#include "hash.h"
#include "int128.h"

/* A signed 62-bit limb representation of integers.
 *
 * Its value is sum(v[i] * 2^(62*i), i=0..4). */
typedef struct {
	int64_t v[5];
} secp256k1_modinv64_signed62;

typedef struct {
	/* The modulus in signed62 notation, must be odd and in [3, 2^256]. */
	secp256k1_modinv64_signed62 modulus;

	/* modulus^{-1} mod 2^62 */
	uint64_t modulus_inv62;
} secp256k1_modinv64_modinfo;

typedef struct {
	int64_t u, v, q, r;
} secp256k1_modinv64_trans2x2;

/* Compute (t/2^62) * [d, e] mod modulus, where t is a transition matrix scaled by 2^62.
 *
 * On input and output, d and e are in range (-2*modulus,modulus). All output limbs will be in range
 * (-2^62,2^62).
 *
 * This implements the update_de function from the explanation.
 */
static void secp256k1_modinv64_update_de_62(
	secp256k1_modinv64_signed62 *d,
	secp256k1_modinv64_signed62 *e,
	const secp256k1_modinv64_trans2x2 *t,
	const secp256k1_modinv64_modinfo *modinfo
);

static void secp256k1_modinv64_var(secp256k1_modinv64_signed62 *x, const secp256k1_modinv64_modinfo *modinfo);

static void secp256k1_modinv64(secp256k1_modinv64_signed62 *x, const secp256k1_modinv64_modinfo *modinfo);
