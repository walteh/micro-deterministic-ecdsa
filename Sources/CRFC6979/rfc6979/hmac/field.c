#include "field.h"

#define SECP256K1_RESTRICT restrict

static void secp256k1_fe_set_b32_mod(secp256k1_fe *r, const unsigned char *a) {
	r->n[0] = (uint64_t)a[31] | ((uint64_t)a[30] << 8) | ((uint64_t)a[29] << 16) | ((uint64_t)a[28] << 24) |
			  ((uint64_t)a[27] << 32) | ((uint64_t)a[26] << 40) | ((uint64_t)(a[25] & 0xF) << 48);
	r->n[1] = (uint64_t)((a[25] >> 4) & 0xF) | ((uint64_t)a[24] << 4) | ((uint64_t)a[23] << 12) |
			  ((uint64_t)a[22] << 20) | ((uint64_t)a[21] << 28) | ((uint64_t)a[20] << 36) | ((uint64_t)a[19] << 44);
	r->n[2] = (uint64_t)a[18] | ((uint64_t)a[17] << 8) | ((uint64_t)a[16] << 16) | ((uint64_t)a[15] << 24) |
			  ((uint64_t)a[14] << 32) | ((uint64_t)a[13] << 40) | ((uint64_t)(a[12] & 0xF) << 48);
	r->n[3] = (uint64_t)((a[12] >> 4) & 0xF) | ((uint64_t)a[11] << 4) | ((uint64_t)a[10] << 12) |
			  ((uint64_t)a[9] << 20) | ((uint64_t)a[8] << 28) | ((uint64_t)a[7] << 36) | ((uint64_t)a[6] << 44);
	r->n[4] = (uint64_t)a[5] | ((uint64_t)a[4] << 8) | ((uint64_t)a[3] << 16) | ((uint64_t)a[2] << 24) |
			  ((uint64_t)a[1] << 32) | ((uint64_t)a[0] << 40);
}

static int secp256k1_fe_set_b32_limit(secp256k1_fe *r, const unsigned char *a) {
	secp256k1_fe_set_b32_mod(r, a);
	return !(
		(r->n[4] == 0x0FFFFFFFFFFFFULL) & ((r->n[3] & r->n[2] & r->n[1]) == 0xFFFFFFFFFFFFFULL) &
		(r->n[0] >= 0xFFFFEFFFFFC2FULL)
	);
}

static int secp256k1_fe_cmp_var(const secp256k1_fe *a, const secp256k1_fe *b) {
	int i;
	for (i = 4; i >= 0; i--) {
		if (a->n[i] > b->n[i]) {
			return 1;
		}
		if (a->n[i] < b->n[i]) {
			return -1;
		}
	}
	return 0;
}

inline static void secp256k1_fe_add(secp256k1_fe *r, const secp256k1_fe *a) {
	r->n[0] += a->n[0];
	r->n[1] += a->n[1];
	r->n[2] += a->n[2];
	r->n[3] += a->n[3];
	r->n[4] += a->n[4];
}

inline static void secp256k1_fe_sqr_inner(uint64_t *r, const uint64_t *a) {
	secp256k1_uint128 c, d;
	uint64_t a0 = a[0], a1 = a[1], a2 = a[2], a3 = a[3], a4 = a[4];
	int64_t t3, t4, tx, u0;
	const uint64_t M = 0xFFFFFFFFFFFFFULL, R = 0x1000003D10ULL;

	VERIFY_BITS(a[0], 56);
	VERIFY_BITS(a[1], 56);
	VERIFY_BITS(a[2], 56);
	VERIFY_BITS(a[3], 56);
	VERIFY_BITS(a[4], 52);

	/**  [... a b c] is a shorthand for ... + a<<104 + b<<52 + c<<0 mod n.
	 *  px is a shorthand for sum(a[i]*a[x-i], i=0..x).
	 *  Note that [x 0 0 0 0 0] = [x*R].
	 */

	secp256k1_u128_mul(&d, a0 * 2, a3);
	secp256k1_u128_accum_mul(&d, a1 * 2, a2);
	VERIFY_BITS_128(&d, 114);
	/* [d 0 0 0] = [p3 0 0 0] */
	secp256k1_u128_mul(&c, a4, a4);
	VERIFY_BITS_128(&c, 112);
	/* [c 0 0 0 0 d 0 0 0] = [p8 0 0 0 0 p3 0 0 0] */
	secp256k1_u128_accum_mul(&d, R, secp256k1_u128_to_u64(&c));
	secp256k1_u128_rshift(&c, 64);
	VERIFY_BITS_128(&d, 115);
	VERIFY_BITS_128(&c, 48);
	/* [(c<<12) 0 0 0 0 0 d 0 0 0] = [p8 0 0 0 0 p3 0 0 0] */
	t3 = secp256k1_u128_to_u64(&d) & M;
	secp256k1_u128_rshift(&d, 52);
	VERIFY_BITS(t3, 52);
	VERIFY_BITS_128(&d, 63);
	/* [(c<<12) 0 0 0 0 d t3 0 0 0] = [p8 0 0 0 0 p3 0 0 0] */

	a4 *= 2;
	secp256k1_u128_accum_mul(&d, a0, a4);
	secp256k1_u128_accum_mul(&d, a1 * 2, a3);
	secp256k1_u128_accum_mul(&d, a2, a2);
	VERIFY_BITS_128(&d, 115);
	/* [(c<<12) 0 0 0 0 d t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */
	secp256k1_u128_accum_mul(&d, R << 12, secp256k1_u128_to_u64(&c));
	VERIFY_BITS_128(&d, 116);
	/* [d t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */
	t4 = secp256k1_u128_to_u64(&d) & M;
	secp256k1_u128_rshift(&d, 52);
	VERIFY_BITS(t4, 52);
	VERIFY_BITS_128(&d, 64);
	/* [d t4 t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */
	tx = (t4 >> 48);
	t4 &= (M >> 4);
	VERIFY_BITS(tx, 4);
	VERIFY_BITS(t4, 48);
	/* [d t4+(tx<<48) t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */

	secp256k1_u128_mul(&c, a0, a0);
	VERIFY_BITS_128(&c, 112);
	/* [d t4+(tx<<48) t3 0 0 c] = [p8 0 0 0 p4 p3 0 0 p0] */
	secp256k1_u128_accum_mul(&d, a1, a4);
	secp256k1_u128_accum_mul(&d, a2 * 2, a3);
	VERIFY_BITS_128(&d, 114);
	/* [d t4+(tx<<48) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
	u0 = secp256k1_u128_to_u64(&d) & M;
	secp256k1_u128_rshift(&d, 52);
	VERIFY_BITS(u0, 52);
	VERIFY_BITS_128(&d, 62);
	/* [d u0 t4+(tx<<48) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
	/* [d 0 t4+(tx<<48)+(u0<<52) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
	u0 = (u0 << 4) | tx;
	VERIFY_BITS(u0, 56);
	/* [d 0 t4+(u0<<48) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
	secp256k1_u128_accum_mul(&c, u0, R >> 4);
	VERIFY_BITS_128(&c, 113);
	/* [d 0 t4 t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
	r[0] = secp256k1_u128_to_u64(&c) & M;
	secp256k1_u128_rshift(&c, 52);
	VERIFY_BITS(r[0], 52);
	VERIFY_BITS_128(&c, 61);
	/* [d 0 t4 t3 0 c r0] = [p8 0 0 p5 p4 p3 0 0 p0] */

	a0 *= 2;
	secp256k1_u128_accum_mul(&c, a0, a1);
	VERIFY_BITS_128(&c, 114);
	/* [d 0 t4 t3 0 c r0] = [p8 0 0 p5 p4 p3 0 p1 p0] */
	secp256k1_u128_accum_mul(&d, a2, a4);
	secp256k1_u128_accum_mul(&d, a3, a3);
	VERIFY_BITS_128(&d, 114);
	/* [d 0 t4 t3 0 c r0] = [p8 0 p6 p5 p4 p3 0 p1 p0] */
	secp256k1_u128_accum_mul(&c, secp256k1_u128_to_u64(&d) & M, R);
	secp256k1_u128_rshift(&d, 52);
	VERIFY_BITS_128(&c, 115);
	VERIFY_BITS_128(&d, 62);
	/* [d 0 0 t4 t3 0 c r0] = [p8 0 p6 p5 p4 p3 0 p1 p0] */
	r[1] = secp256k1_u128_to_u64(&c) & M;
	secp256k1_u128_rshift(&c, 52);
	VERIFY_BITS(r[1], 52);
	VERIFY_BITS_128(&c, 63);
	/* [d 0 0 t4 t3 c r1 r0] = [p8 0 p6 p5 p4 p3 0 p1 p0] */

	secp256k1_u128_accum_mul(&c, a0, a2);
	secp256k1_u128_accum_mul(&c, a1, a1);
	VERIFY_BITS_128(&c, 114);
	/* [d 0 0 t4 t3 c r1 r0] = [p8 0 p6 p5 p4 p3 p2 p1 p0] */
	secp256k1_u128_accum_mul(&d, a3, a4);
	VERIFY_BITS_128(&d, 114);
	/* [d 0 0 t4 t3 c r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
	secp256k1_u128_accum_mul(&c, R, secp256k1_u128_to_u64(&d));
	secp256k1_u128_rshift(&d, 64);
	VERIFY_BITS_128(&c, 115);
	VERIFY_BITS_128(&d, 50);
	/* [(d<<12) 0 0 0 t4 t3 c r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
	r[2] = secp256k1_u128_to_u64(&c) & M;
	secp256k1_u128_rshift(&c, 52);
	VERIFY_BITS(r[2], 52);
	VERIFY_BITS_128(&c, 63);
	/* [(d<<12) 0 0 0 t4 t3+c r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */

	secp256k1_u128_accum_mul(&c, R << 12, secp256k1_u128_to_u64(&d));
	secp256k1_u128_accum_u64(&c, t3);
	VERIFY_BITS_128(&c, 100);
	/* [t4 c r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
	r[3] = secp256k1_u128_to_u64(&c) & M;
	secp256k1_u128_rshift(&c, 52);
	VERIFY_BITS(r[3], 52);
	VERIFY_BITS_128(&c, 48);
	/* [t4+c r3 r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
	r[4] = secp256k1_u128_to_u64(&c) + t4;
	VERIFY_BITS(r[4], 49);
	/* [r4 r3 r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
}

static inline void secp256k1_fe_sqr(secp256k1_fe *r, const secp256k1_fe *a) { secp256k1_fe_sqr_inner(r->n, a->n); }

static void secp256k1_ge_verify(const secp256k1_ge *a) {
#ifdef VERIFY
	secp256k1_fe_verify(&a->x);
	secp256k1_fe_verify(&a->y);
	VERIFY_CHECK(a->infinity == 0 || a->infinity == 1);
#endif
	(void)a;
}

static void secp256k1_gej_verify(const secp256k1_gej *a) {
#ifdef VERIFY
	secp256k1_fe_verify(&a->x);
	secp256k1_fe_verify(&a->y);
	secp256k1_fe_verify(&a->z);
	VERIFY_CHECK(a->infinity == 0 || a->infinity == 1);
#endif
	(void)a;
}

static void secp256k1_fe_verify(const secp256k1_fe *a) { (void)a; }

static void secp256k1_fe_set_int(secp256k1_fe *r, int a) {
	r->n[0] = a;
	r->n[1] = r->n[2] = r->n[3] = r->n[4] = 0;
}

inline static void secp256k1_fe_add_int(secp256k1_fe *r, int a) { r->n[0] += a; }

static void secp256k1_fe_normalize_var(secp256k1_fe *r) {
	uint64_t t0 = r->n[0], t1 = r->n[1], t2 = r->n[2], t3 = r->n[3], t4 = r->n[4];

	/* Reduce t4 at the start so there will be at most a single carry from the first pass */
	uint64_t m;
	uint64_t x = t4 >> 48;
	t4 &= 0x0FFFFFFFFFFFFULL;

	/* The first pass ensures the magnitude is 1, ... */
	t0 += x * 0x1000003D1ULL;
	t1 += (t0 >> 52);
	t0 &= 0xFFFFFFFFFFFFFULL;
	t2 += (t1 >> 52);
	t1 &= 0xFFFFFFFFFFFFFULL;
	m = t1;
	t3 += (t2 >> 52);
	t2 &= 0xFFFFFFFFFFFFFULL;
	m &= t2;
	t4 += (t3 >> 52);
	t3 &= 0xFFFFFFFFFFFFFULL;
	m &= t3;

	/* ... except for a possible carry at bit 48 of t4 (i.e. bit 256 of the field element) */
	VERIFY_CHECK(t4 >> 49 == 0);

	/* At most a single final reduction is needed; check if the value is >= the field characteristic */
	x = (t4 >> 48) | ((t4 == 0x0FFFFFFFFFFFFULL) & (m == 0xFFFFFFFFFFFFFULL) & (t0 >= 0xFFFFEFFFFFC2FULL));

	if (x) {
		t0 += 0x1000003D1ULL;
		t1 += (t0 >> 52);
		t0 &= 0xFFFFFFFFFFFFFULL;
		t2 += (t1 >> 52);
		t1 &= 0xFFFFFFFFFFFFFULL;
		t3 += (t2 >> 52);
		t2 &= 0xFFFFFFFFFFFFFULL;
		t4 += (t3 >> 52);
		t3 &= 0xFFFFFFFFFFFFFULL;

		/* If t4 didn't carry to bit 48 already, then it should have after any final reduction */
		VERIFY_CHECK(t4 >> 48 == x);

		/* Mask off the possible multiple of 2^256 from the final reduction */
		t4 &= 0x0FFFFFFFFFFFFULL;
	}

	r->n[0] = t0;
	r->n[1] = t1;
	r->n[2] = t2;
	r->n[3] = t3;
	r->n[4] = t4;
}

inline static int secp256k1_fe_is_odd(const secp256k1_fe *a) { return a->n[0] & 1; }

inline static void secp256k1_fe_impl_negate_unchecked(secp256k1_fe *r, const secp256k1_fe *a, int m) {
	/* For all legal values of m (0..31), the following properties hold: */
	VERIFY_CHECK(0xFFFFEFFFFFC2FULL * 2 * (m + 1) >= 0xFFFFFFFFFFFFFULL * 2 * m);
	VERIFY_CHECK(0xFFFFFFFFFFFFFULL * 2 * (m + 1) >= 0xFFFFFFFFFFFFFULL * 2 * m);
	VERIFY_CHECK(0x0FFFFFFFFFFFFULL * 2 * (m + 1) >= 0x0FFFFFFFFFFFFULL * 2 * m);

	/* Due to the properties above, the left hand in the subtractions below is never less than
	 * the right hand. */
	r->n[0] = 0xFFFFEFFFFFC2FULL * 2 * (m + 1) - a->n[0];
	r->n[1] = 0xFFFFFFFFFFFFFULL * 2 * (m + 1) - a->n[1];
	r->n[2] = 0xFFFFFFFFFFFFFULL * 2 * (m + 1) - a->n[2];
	r->n[3] = 0xFFFFFFFFFFFFFULL * 2 * (m + 1) - a->n[3];
	r->n[4] = 0x0FFFFFFFFFFFFULL * 2 * (m + 1) - a->n[4];
}

static int secp256k1_ge_set_xo_var(secp256k1_ge *r, const secp256k1_fe *x, int odd) {
	secp256k1_fe x2, x3;
	int ret;
	secp256k1_fe_verify(x);
	r->x = *x;
	secp256k1_fe_sqr(&x2, x);
	secp256k1_fe_mul(&x3, x, &x2);
	r->infinity = 0;
	secp256k1_fe_add_int(&x3, SECP256K1_B);
	ret = secp256k1_fe_sqrt(&r->y, &x3);
	secp256k1_fe_normalize_var(&r->y);
	if (secp256k1_fe_is_odd(&r->y) != odd) {
		secp256k1_fe_negate(&r->y, &r->y, 1);
	}
	secp256k1_ge_verify(r);
	return ret;
}

static void secp256k1_gej_set_ge(secp256k1_gej *r, const secp256k1_ge *a) {
	secp256k1_ge_verify(a);
	r->infinity = a->infinity;
	r->x		= a->x;
	r->y		= a->y;
	secp256k1_fe_set_int(&r->z, 1);
	secp256k1_gej_verify(r);
}

static int secp256k1_gej_is_infinity(const secp256k1_gej *a) {
	secp256k1_gej_verify(a);
	return a->infinity;
}

static void secp256k1_fe_normalize_weak(secp256k1_fe *r) {
	uint64_t t0 = r->n[0], t1 = r->n[1], t2 = r->n[2], t3 = r->n[3], t4 = r->n[4];

	/* Reduce t4 at the start so there will be at most a single carry from the first pass */
	uint64_t x = t4 >> 48;
	t4 &= 0x0FFFFFFFFFFFFULL;

	/* The first pass ensures the magnitude is 1, ... */
	t0 += x * 0x1000003D1ULL;
	t1 += (t0 >> 52);
	t0 &= 0xFFFFFFFFFFFFFULL;
	t2 += (t1 >> 52);
	t1 &= 0xFFFFFFFFFFFFFULL;
	t3 += (t2 >> 52);
	t2 &= 0xFFFFFFFFFFFFFULL;
	t4 += (t3 >> 52);
	t3 &= 0xFFFFFFFFFFFFFULL;

	/* ... except for a possible carry at bit 48 of t4 (i.e. bit 256 of the field element) */
	VERIFY_CHECK(t4 >> 49 == 0);

	r->n[0] = t0;
	r->n[1] = t1;
	r->n[2] = t2;
	r->n[3] = t3;
	r->n[4] = t4;
}

/* Set r to the affine coordinates of Jacobian point (a.x, a.y, 1/zi). */
static void secp256k1_ge_set_ge_zinv(secp256k1_ge *r, const secp256k1_ge *a, const secp256k1_fe *zi) {
	secp256k1_fe zi2;
	secp256k1_fe zi3;
	secp256k1_ge_verify(a);
	secp256k1_fe_verify(zi);
	VERIFY_CHECK(!a->infinity);
	secp256k1_fe_sqr(&zi2, zi);
	secp256k1_fe_mul(&zi3, &zi2, zi);
	secp256k1_fe_mul(&r->x, &a->x, &zi2);
	secp256k1_fe_mul(&r->y, &a->y, &zi3);
	r->infinity = a->infinity;
	secp256k1_ge_verify(r);
}

static void secp256k1_ge_table_set_globalz(size_t len, secp256k1_ge *a, const secp256k1_fe *zr) {
	size_t i = len - 1;
	secp256k1_fe zs;

	if (len > 0) {
		/* Verify inputs a[len-1] and zr[len-1]. */
		secp256k1_ge_verify(&a[i]);
		secp256k1_fe_verify(&zr[i]);
		/* Ensure all y values are in weak normal form for fast negation of points */
		secp256k1_fe_normalize_weak(&a[i].y);
		zs = zr[i];

		/* Work our way backwards, using the z-ratios to scale the x/y values. */
		while (i > 0) {
			/* Verify all inputs a[i] and zr[i]. */
			secp256k1_fe_verify(&zr[i]);
			secp256k1_ge_verify(&a[i]);
			if (i != len - 1) {
				secp256k1_fe_mul(&zs, &zs, &zr[i]);
			}
			i--;
			secp256k1_ge_set_ge_zinv(&a[i], &a[i], &zs);
			/* Verify the output a[i]. */
			secp256k1_ge_verify(&a[i]);
		}
	}
}

static void secp256k1_gej_rescale(secp256k1_gej *r, const secp256k1_fe *s) {
	/* Operations: 4 mul, 1 sqr */
	secp256k1_fe zz;
	secp256k1_gej_verify(r);
	secp256k1_fe_verify(s);
#ifdef VERIFY
	VERIFY_CHECK(!secp256k1_fe_normalizes_to_zero_var(s));
#endif
	secp256k1_fe_sqr(&zz, s);
	secp256k1_fe_mul(&r->x, &r->x, &zz); /* r->x *= s^2 */
	secp256k1_fe_mul(&r->y, &r->y, &zz);
	secp256k1_fe_mul(&r->y, &r->y, s); /* r->y *= s^3 */
	secp256k1_fe_mul(&r->z, &r->z, s); /* r->z *= s   */
	secp256k1_gej_verify(r);
}
