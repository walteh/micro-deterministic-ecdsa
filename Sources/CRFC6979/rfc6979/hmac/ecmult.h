#include "field.h"
#include "scalar.h"

#include <string.h>

/* optimal for 128-bit and 256-bit exponents. */
#define WINDOW_A 5
/** Larger values for ECMULT_WINDOW_SIZE result in possibly better
 *  performance at the cost of an exponentially larger precomputed
 *  table. The exact table size is
 *      (1 << (WINDOW_G - 2)) * sizeof(secp256k1_ge_storage)  bytes,
 *  where sizeof(secp256k1_ge_storage) is typically 64 bytes but can
 *  be larger due to platform-specific padding and alignment.
 *  Two tables of this size are used (due to the endomorphism
 *  optimization).
 */

#define WNAF_BITS				128
#define WNAF_SIZE_BITS(bits, w) (((bits) + (w)-1) / (w))
#define WNAF_SIZE(w)			WNAF_SIZE_BITS(WNAF_BITS, w)
#define ECMULT_TABLE_SIZE(w)	(1L << ((w)-2))
#define ECMULT_WINDOW_SIZE		15

#define WINDOW_G ECMULT_WINDOW_SIZE
// extern const secp256k1_ge_storage secp256k1_pre_g[ECMULT_TABLE_SIZE(WINDOW_G)];
// extern const secp256k1_ge_storage secp256k1_pre_g_128[ECMULT_TABLE_SIZE(WINDOW_G)];
