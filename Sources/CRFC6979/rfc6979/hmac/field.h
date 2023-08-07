#include "hash.h"
#include "int128.h"
#include "scalar.h"

#include <stdint.h>

/** This field implementation represents the value as 5 uint64_t limbs in base
 *  2^52. */
typedef struct {
	/* A field element f represents the sum(i=0..4, f.n[i] << (i*52)) mod p,
	 * where p is the field modulus, 2^256 - 2^32 - 977.
	 *
	 * The individual limbs f.n[i] can exceed 2^52; the field's magnitude roughly
	 * corresponds to how much excess is allowed. The value
	 * sum(i=0..4, f.n[i] << (i*52)) may exceed p, unless the field element is
	 * normalized. */
	uint64_t n[5];
	/*
	 * Magnitude m requires:
	 *     n[i] <= 2 * m * (2^52 - 1) for i=0..3
	 *     n[4] <= 2 * m * (2^48 - 1)
	 *
	 * Normalized requires:
	 *     n[i] <= (2^52 - 1) for i=0..3
	 *     sum(i=0..4, n[i] << (i*52)) < p
	 *     (together these imply n[4] <= 2^48 - 1)
	 */
	// SECP256K1_FE_VERIFY_FIELDS
} secp256k1_fe;

/** A group element in affine coordinates on the secp256k1 curve,
 *  or occasionally on an isomorphic curve of the form y^2 = x^3 + 7*t^6.
 *  Note: For exhaustive test mode, secp256k1 is replaced by a small subgroup of a different curve.
 */
typedef struct {
	secp256k1_fe x;
	secp256k1_fe y;
	int infinity; /* whether this represents the point at infinity */
} secp256k1_ge;

/** A group element of the secp256k1 curve, in jacobian coordinates.
 *  Note: For exhastive test mode, secp256k1 is replaced by a small subgroup of a different curve.
 */
typedef struct {
	secp256k1_fe x; /* actual X: x/z^2 */
	secp256k1_fe y; /* actual Y: y/z^3 */
	secp256k1_fe z;
	int infinity; /* whether this represents the point at infinity */
} secp256k1_gej;

/* Unpacks a constant into a overlapping multi-limbed FE element. */
#define SECP256K1_FE_CONST_INNER(d7, d6, d5, d4, d3, d2, d1, d0)                                  \
	{                                                                                             \
		(d0) | (((uint64_t)(d1)&0xFFFFFUL) << 32),                                                \
			((uint64_t)(d1) >> 20) | (((uint64_t)(d2)) << 12) | (((uint64_t)(d3)&0xFFUL) << 44),  \
			((uint64_t)(d3) >> 8) | (((uint64_t)(d4)&0xFFFFFFFUL) << 24),                         \
			((uint64_t)(d4) >> 28) | (((uint64_t)(d5)) << 4) | (((uint64_t)(d6)&0xFFFFUL) << 36), \
			((uint64_t)(d6) >> 16) | (((uint64_t)(d7)) << 16)                                     \
	}

#ifdef VERIFY
/* Magnitude and normalized value for constants. */
#define SECP256K1_FE_VERIFY_CONST(d7, d6, d5, d4, d3, d2, d1, d0)                         \
	/* Magnitude is 0 for constant 0; 1 otherwise. */                                     \
	,                                                                                     \
		(((d7) | (d6) | (d5) | (d4) | (d3) | (d2) | (d1) | (d0)) != 0                     \
		) /* Normalized is 1 unless sum(d_i<<(32*i) for i=0..7) exceeds field modulus. */ \
		,                                                                                 \
		(!(((d7) & (d6) & (d5) & (d4) & (d3) & (d2)) == 0xfffffffful &&                   \
		   ((d1) == 0xfffffffful || ((d1) == 0xfffffffe && (d0 >= 0xfffffc2f)))))
#else
#define SECP256K1_FE_VERIFY_CONST(d7, d6, d5, d4, d3, d2, d1, d0)
#endif

#define SECP256K1_FE_CONST(d7, d6, d5, d4, d3, d2, d1, d0)                        \
	{                                                                             \
		SECP256K1_FE_CONST_INNER((d7), (d6), (d5), (d4), (d3), (d2), (d1), (d0))  \
		SECP256K1_FE_VERIFY_CONST((d7), (d6), (d5), (d4), (d3), (d2), (d1), (d0)) \
	}

/** Group order for secp256k1 defined as 'n' in "Standards for Efficient Cryptography" (SEC2) 2.7.1
 *  $ sage -c 'load("secp256k1_params.sage"); print(hex(N))'
 *  0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
 */
static const secp256k1_fe secp256k1_ecdsa_const_order_as_fe = SECP256K1_FE_CONST(
	0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFEUL, 0xBAAEDCE6UL, 0xAF48A03BUL, 0xBFD25E8CUL, 0xD0364141UL
);

/** Difference between field and order, values 'p' and 'n' values defined in
 *  "Standards for Efficient Cryptography" (SEC2) 2.7.1.
 *  $ sage -c 'load("secp256k1_params.sage"); print(hex(P-N))'
 *  0x14551231950b75fc4402da1722fc9baee
 */
static const secp256k1_fe secp256k1_ecdsa_const_p_minus_order =
	SECP256K1_FE_CONST(0, 0, 0, 1, 0x45512319UL, 0x50B75FC4UL, 0x402DA172UL, 0x2FC9BAEEUL);

static int secp256k1_fe_set_b32_limit(secp256k1_fe *r, const unsigned char *a);

static int secp256k1_fe_cmp_var(const secp256k1_fe *a, const secp256k1_fe *b);

inline static void secp256k1_fe_add(secp256k1_fe *r, const secp256k1_fe *a);

/** Set a group element (affine) equal to the point with the given X coordinate, and given oddness
 *  for Y. Return value indicates whether the result is valid. */
static int secp256k1_ge_set_xo_var(secp256k1_ge *r, const secp256k1_fe *x, int odd);

static void secp256k1_gej_set_ge(secp256k1_gej *r, const secp256k1_ge *a);

/** Square a field element.
 *
 * On input, a must be a valid field element; r does not need to be initialized. The magnitude
 * of a must not exceed 8.
 * Performs {r = a**2}
 * On output, r will have magnitude 1, but won't be normalized.
 */
static void secp256k1_fe_sqr(secp256k1_fe *r, const secp256k1_fe *a);

/** Compute a square root of a field element.
 *
 * On input, a must be a valid field element with magnitude<=8; r need not be initialized.
 * If sqrt(a) exists, performs {r = sqrt(a)} and returns 1.
 * Otherwise, sqrt(-a) exists. The function performs {r = sqrt(-a)} and returns 0.
 * The resulting value represented by r will be a square itself.
 * Variables r and a must not point to the same object.
 * On output, r will have magnitude 1 but will not be normalized.
 */
static int secp256k1_fe_sqrt(secp256k1_fe *restrict r, const secp256k1_fe *restrict a);

/** Multiply two field elements.
 *
 * On input, a and b must be valid field elements; r does not need to be initialized.
 * r and a may point to the same object, but neither can be equal to b. The magnitudes
 * of a and b must not exceed 8.
 * Performs {r = a * b}
 * On output, r will have magnitude 1, but won't be normalized.
 */
static void secp256k1_fe_mul(secp256k1_fe *r, const secp256k1_fe *a, const secp256k1_fe *restrict b);

/** Negate a field element.
 *
 * On input, r does not need to be initialized. a must be a valid field element with
 * magnitude not exceeding m. m must be an integer constant expression in [0,31].
 * Performs {r = -a}.
 * On output, r will not be normalized, and will have magnitude m+1.
 */
#define secp256k1_fe_negate(r, a, m) ASSERT_INT_CONST_AND_DO(m, secp256k1_fe_negate_unchecked(r, a, m))

/** Like secp256k1_fe_negate_unchecked but m is not checked to be an integer constant expression.
 *
 * Should not be called directly outside of tests.
 */
static void secp256k1_fe_negate_unchecked(secp256k1_fe *r, const secp256k1_fe *a, int m);

// static const secp256k1_ge secp256k1_ge_const_g = SECP256K1_G;
#define SECP256K1_B 7

#ifdef VERIFY
#define VERIFY_BITS(x, n)	  VERIFY_CHECK(((x) >> (n)) == 0)
#define VERIFY_BITS_128(x, n) VERIFY_CHECK(secp256k1_u128_check_bits((x), (n)))
#else
#define VERIFY_BITS(x, n) \
	do {                  \
	} while (0)
#define VERIFY_BITS_128(x, n) \
	do {                      \
	} while (0)
#endif

static void secp256k1_fe_set_int(secp256k1_fe *r, int a);

/** Check whether a group element is the point at infinity. */
static int secp256k1_gej_is_infinity(const secp256k1_gej *a);

/** Give a field element magnitude 1.
 *
 * On input, r must be a valid field element.
 * On output, r represents the same value but has magnitude=1. Normalized is unchanged.
 */
static void secp256k1_fe_normalize_weak(secp256k1_fe *r);

/** Bring a batch of inputs to the same global z "denominator", based on ratios between
 *  (omitted) z coordinates of adjacent elements.
 *
 *  Although the elements a[i] are _ge rather than _gej, they actually represent elements
 *  in Jacobian coordinates with their z coordinates omitted.
 *
 *  Using the notation z(b) to represent the omitted z coordinate of b, the array zr of
 *  z coordinate ratios must satisfy zr[i] == z(a[i]) / z(a[i-1]) for 0 < 'i' < len.
 *  The zr[0] value is unused.
 *
 *  This function adjusts the coordinates of 'a' in place so that for all 'i', z(a[i]) == z(a[len-1]).
 *  In other words, the initial value of z(a[len-1]) becomes the global z "denominator". Only the
 *  a[i].x and a[i].y coordinates are explicitly modified; the adjustment of the omitted z coordinate is
 *  implicit.
 *
 *  The coordinates of the final element a[len-1] are not changed.
 */
static void secp256k1_ge_table_set_globalz(size_t len, secp256k1_ge *a, const secp256k1_fe *zr);

/** Rescale a jacobian point by b which must be non-zero. Constant-time. */
static void secp256k1_gej_rescale(secp256k1_gej *r, const secp256k1_fe *b);
