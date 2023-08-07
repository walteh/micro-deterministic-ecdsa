#include "ecmult.h"

// static void secp256k1_ecmult_compute_table(secp256k1_ge_storage *table, int window_g, const secp256k1_gej *gen) {
// 	secp256k1_gej gj;
// 	secp256k1_ge ge, dgen;
// 	int j;

// 	gj = *gen;
// 	secp256k1_ge_set_gej_var(&ge, &gj);
// 	secp256k1_ge_to_storage(&table[0], &ge);

// 	secp256k1_gej_double_var(&gj, gen, NULL);
// 	secp256k1_ge_set_gej_var(&dgen, &gj);

// 	for (j = 1; j < ECMULT_TABLE_SIZE(window_g); ++j) {
// 		secp256k1_gej_set_ge(&gj, &ge);
// 		secp256k1_gej_add_ge_var(&gj, &gj, &dgen, NULL);
// 		secp256k1_ge_set_gej_var(&ge, &gj);
// 		secp256k1_ge_to_storage(&table[j], &ge);
// 	}
// }

// /* Like secp256k1_ecmult_compute_table, but one for both gen and gen*2^128. */
// static void secp256k1_ecmult_compute_two_tables(
// 	secp256k1_ge_storage *table, secp256k1_ge_storage *table_128, int window_g, const secp256k1_ge *gen
// ) {
// 	secp256k1_gej gj;
// 	int i;

// 	secp256k1_gej_set_ge(&gj, gen);
// 	secp256k1_ecmult_compute_table(table, window_g, &gj);
// 	for (i = 0; i < 128; ++i) {
// 		secp256k1_gej_double_var(&gj, &gj, NULL);
// 	}
// 	secp256k1_ecmult_compute_table(table_128, window_g, &gj);
// }

/** Convert a number to WNAF notation. The number becomes represented by sum(2^i * wnaf[i], i=0..bits),
 *  with the following guarantees:
 *  - each wnaf[i] is either 0, or an odd integer between -(1<<(w-1) - 1) and (1<<(w-1) - 1)
 *  - two non-zero entries in wnaf are separated by at least w-1 zeroes.
 *  - the number of set values in wnaf is returned. This number is at most 256, and at most one more
 *    than the number of bits in the (absolute value) of the input.
 */
static int secp256k1_ecmult_wnaf(int *wnaf, int len, const secp256k1_scalar *a, int w) {
	secp256k1_scalar s;
	int last_set_bit = -1;
	int bit			 = 0;
	int sign		 = 1;
	int carry		 = 0;

	VERIFY_CHECK(wnaf != NULL);
	VERIFY_CHECK(0 <= len && len <= 256);
	VERIFY_CHECK(a != NULL);
	VERIFY_CHECK(2 <= w && w <= 31);

	memset(wnaf, 0, len * sizeof(wnaf[0]));

	s = *a;
	if (secp256k1_scalar_get_bits(&s, 255, 1)) {
		secp256k1_scalar_negate(&s, &s);
		sign = -1;
	}

	while (bit < len) {
		int now;
		int word;
		if (secp256k1_scalar_get_bits(&s, bit, 1) == (unsigned int)carry) {
			bit++;
			continue;
		}

		now = w;
		if (now > len - bit) {
			now = len - bit;
		}

		word = secp256k1_scalar_get_bits_var(&s, bit, now) + carry;

		carry = (word >> (w - 1)) & 1;
		word -= carry << w;

		wnaf[bit]	 = sign * word;
		last_set_bit = bit;

		bit += now;
	}
#ifdef VERIFY
	{
		int verify_bit = bit;

		VERIFY_CHECK(carry == 0);

		while (verify_bit < 256) {
			VERIFY_CHECK(secp256k1_scalar_get_bits(&s, verify_bit, 1) == 0);
			verify_bit++;
		}
	}
#endif
	return last_set_bit + 1;
}

struct secp256k1_strauss_point_state {
	int wnaf_na_1[129];
	int wnaf_na_lam[129];
	int bits_na_1;
	int bits_na_lam;
};

struct secp256k1_strauss_state {
	/* aux is used to hold z-ratios, and then used to hold pre_a[i].x * BETA values. */
	secp256k1_fe *aux;
	secp256k1_ge *pre_a;
	struct secp256k1_strauss_point_state *ps;
};

// /** Fill a table 'pre_a' with precomputed odd multiples of a.
//  *  pre_a will contain [1*a,3*a,...,(2*n-1)*a], so it needs space for n group elements.
//  *  zr needs space for n field elements.
//  *
//  *  Although pre_a is an array of _ge rather than _gej, it actually represents elements
//  *  in Jacobian coordinates with their z coordinates omitted. The omitted z-coordinates
//  *  can be recovered using z and zr. Using the notation z(b) to represent the omitted
//  *  z coordinate of b:
//  *  - z(pre_a[n-1]) = 'z'
//  *  - z(pre_a[i-1]) = z(pre_a[i]) / zr[i] for n > i > 0
//  *
//  *  Lastly the zr[0] value, which isn't used above, is set so that:
//  *  - a.z = z(pre_a[0]) / zr[0]
//  */
// static void secp256k1_ecmult_odd_multiples_table(
// 	int n, secp256k1_ge *pre_a, secp256k1_fe *zr, secp256k1_fe *z, const secp256k1_gej *a
// ) {
// 	secp256k1_gej d, ai;
// 	secp256k1_ge d_ge;
// 	int i;

// 	VERIFY_CHECK(!a->infinity);

// 	secp256k1_gej_double_var(&d, a, NULL);

// 	/*
// 	 * Perform the additions using an isomorphic curve Y^2 = X^3 + 7*C^6 where C := d.z.
// 	 * The isomorphism, phi, maps a secp256k1 point (x, y) to the point (x*C^2, y*C^3) on the other curve.
// 	 * In Jacobian coordinates phi maps (x, y, z) to (x*C^2, y*C^3, z) or, equivalently to (x, y, z/C).
// 	 *
// 	 *     phi(x, y, z) = (x*C^2, y*C^3, z) = (x, y, z/C)
// 	 *   d_ge := phi(d) = (d.x, d.y, 1)
// 	 *     ai := phi(a) = (a.x*C^2, a.y*C^3, a.z)
// 	 *
// 	 * The group addition functions work correctly on these isomorphic curves.
// 	 * In particular phi(d) is easy to represent in affine coordinates under this isomorphism.
// 	 * This lets us use the faster secp256k1_gej_add_ge_var group addition function that we wouldn't be able to use
// 	 * otherwise.
// 	 */
// 	secp256k1_ge_set_xy(&d_ge, &d.x, &d.y);
// 	secp256k1_ge_set_gej_zinv(&pre_a[0], a, &d.z);
// 	secp256k1_gej_set_ge(&ai, &pre_a[0]);
// 	ai.z = a->z;

// 	/* pre_a[0] is the point (a.x*C^2, a.y*C^3, a.z*C) which is equivalent to a.
// 	 * Set zr[0] to C, which is the ratio between the omitted z(pre_a[0]) value and a.z.
// 	 */
// 	zr[0] = d.z;

// 	for (i = 1; i < n; i++) {
// 		secp256k1_gej_add_ge_var(&ai, &ai, &d_ge, &zr[i]);
// 		secp256k1_ge_set_xy(&pre_a[i], &ai.x, &ai.y);
// 	}

// 	/* Multiply the last z-coordinate by C to undo the isomorphism.
// 	 * Since the z-coordinates of the pre_a values are implied by the zr array of z-coordinate ratios,
// 	 * undoing the isomorphism here undoes the isomorphism for all pre_a values.
// 	 */
// 	secp256k1_fe_mul(z, &ai.z, &d.z);
// }

// static void secp256k1_ecmult_strauss_wnaf(
// 	const struct secp256k1_strauss_state *state,
// 	secp256k1_gej *r,
// 	size_t num,
// 	const secp256k1_gej *a,
// 	const secp256k1_scalar *na,
// 	const secp256k1_scalar *ng
// ) {
// 	secp256k1_ge tmpa;
// 	secp256k1_fe Z;
// 	/* Split G factors. */
// 	secp256k1_scalar ng_1, ng_128;
// 	int wnaf_ng_1[129];
// 	int bits_ng_1 = 0;
// 	int wnaf_ng_128[129];
// 	int bits_ng_128 = 0;
// 	int i;
// 	int bits = 0;
// 	size_t np;
// 	size_t no = 0;

// 	secp256k1_fe_set_int(&Z, 1);
// 	for (np = 0; np < num; ++np) {
// 		secp256k1_gej tmp;
// 		secp256k1_scalar na_1, na_lam;
// 		if (secp256k1_scalar_is_zero(&na[np]) || secp256k1_gej_is_infinity(&a[np])) {
// 			continue;
// 		}
// 		/* split na into na_1 and na_lam (where na = na_1 + na_lam*lambda, and na_1 and na_lam are ~128 bit) */
// 		secp256k1_scalar_split_lambda(&na_1, &na_lam, &na[np]);

// 		/* build wnaf representation for na_1 and na_lam. */
// 		state->ps[no].bits_na_1	  = secp256k1_ecmult_wnaf(state->ps[no].wnaf_na_1, 129, &na_1, WINDOW_A);
// 		state->ps[no].bits_na_lam = secp256k1_ecmult_wnaf(state->ps[no].wnaf_na_lam, 129, &na_lam, WINDOW_A);
// 		VERIFY_CHECK(state->ps[no].bits_na_1 <= 129);
// 		VERIFY_CHECK(state->ps[no].bits_na_lam <= 129);
// 		if (state->ps[no].bits_na_1 > bits) {
// 			bits = state->ps[no].bits_na_1;
// 		}
// 		if (state->ps[no].bits_na_lam > bits) {
// 			bits = state->ps[no].bits_na_lam;
// 		}

// 		/* Calculate odd multiples of a.
// 		 * All multiples are brought to the same Z 'denominator', which is stored
// 		 * in Z. Due to secp256k1' isomorphism we can do all operations pretending
// 		 * that the Z coordinate was 1, use affine addition formulae, and correct
// 		 * the Z coordinate of the result once at the end.
// 		 * The exception is the precomputed G table points, which are actually
// 		 * affine. Compared to the base used for other points, they have a Z ratio
// 		 * of 1/Z, so we can use secp256k1_gej_add_zinv_var, which uses the same
// 		 * isomorphism to efficiently add with a known Z inverse.
// 		 */
// 		tmp = a[np];
// 		if (no) {
// 			secp256k1_gej_rescale(&tmp, &Z);
// 		}
// 		secp256k1_ecmult_odd_multiples_table(
// 			ECMULT_TABLE_SIZE(WINDOW_A),
// 			state->pre_a + no * ECMULT_TABLE_SIZE(WINDOW_A),
// 			state->aux + no * ECMULT_TABLE_SIZE(WINDOW_A),
// 			&Z,
// 			&tmp
// 		);
// 		if (no)
// 			secp256k1_fe_mul(
// 				state->aux + no * ECMULT_TABLE_SIZE(WINDOW_A), state->aux + no * ECMULT_TABLE_SIZE(WINDOW_A), &(a[np].z)
// 			);

// 		++no;
// 	}

// 	/* Bring them to the same Z denominator. */
// 	if (no) {
// 		secp256k1_ge_table_set_globalz(ECMULT_TABLE_SIZE(WINDOW_A) * no, state->pre_a, state->aux);
// 	}

// 	for (np = 0; np < no; ++np) {
// 		for (i = 0; i < ECMULT_TABLE_SIZE(WINDOW_A); i++) {
// 			secp256k1_fe_mul(
// 				&state->aux[np * ECMULT_TABLE_SIZE(WINDOW_A) + i],
// 				&state->pre_a[np * ECMULT_TABLE_SIZE(WINDOW_A) + i].x,
// 				&secp256k1_const_beta
// 			);
// 		}
// 	}

// 	if (ng) {
// 		/* split ng into ng_1 and ng_128 (where gn = gn_1 + gn_128*2^128, and gn_1 and gn_128 are ~128 bit) */
// 		secp256k1_scalar_split_128(&ng_1, &ng_128, ng);

// 		/* Build wnaf representation for ng_1 and ng_128 */
// 		bits_ng_1	= secp256k1_ecmult_wnaf(wnaf_ng_1, 129, &ng_1, WINDOW_G);
// 		bits_ng_128 = secp256k1_ecmult_wnaf(wnaf_ng_128, 129, &ng_128, WINDOW_G);
// 		if (bits_ng_1 > bits) {
// 			bits = bits_ng_1;
// 		}
// 		if (bits_ng_128 > bits) {
// 			bits = bits_ng_128;
// 		}
// 	}

// 	secp256k1_gej_set_infinity(r);

// 	for (i = bits - 1; i >= 0; i--) {
// 		int n;
// 		secp256k1_gej_double_var(r, r, NULL);
// 		for (np = 0; np < no; ++np) {
// 			if (i < state->ps[np].bits_na_1 && (n = state->ps[np].wnaf_na_1[i])) {
// 				secp256k1_ecmult_table_get_ge(&tmpa, state->pre_a + np * ECMULT_TABLE_SIZE(WINDOW_A), n, WINDOW_A);
// 				secp256k1_gej_add_ge_var(r, r, &tmpa, NULL);
// 			}
// 			if (i < state->ps[np].bits_na_lam && (n = state->ps[np].wnaf_na_lam[i])) {
// 				secp256k1_ecmult_table_get_ge_lambda(
// 					&tmpa,
// 					state->pre_a + np * ECMULT_TABLE_SIZE(WINDOW_A),
// 					state->aux + np * ECMULT_TABLE_SIZE(WINDOW_A),
// 					n,
// 					WINDOW_A
// 				);
// 				secp256k1_gej_add_ge_var(r, r, &tmpa, NULL);
// 			}
// 		}
// 		if (i < bits_ng_1 && (n = wnaf_ng_1[i])) {
// 			secp256k1_ecmult_table_get_ge_storage(&tmpa, secp256k1_pre_g, n, WINDOW_G);
// 			secp256k1_gej_add_zinv_var(r, r, &tmpa, &Z);
// 		}
// 		if (i < bits_ng_128 && (n = wnaf_ng_128[i])) {
// 			secp256k1_ecmult_table_get_ge_storage(&tmpa, secp256k1_pre_g_128, n, WINDOW_G);
// 			secp256k1_gej_add_zinv_var(r, r, &tmpa, &Z);
// 		}
// 	}

// 	if (!r->infinity) {
// 		secp256k1_fe_mul(&r->z, &r->z, &Z);
// 	}
// }

// static void
// 	secp256k1_ecmult(secp256k1_gej *r, const secp256k1_gej *a, const secp256k1_scalar *na, const secp256k1_scalar *ng) {
// 	secp256k1_fe aux[ECMULT_TABLE_SIZE(WINDOW_A)];
// 	secp256k1_ge pre_a[ECMULT_TABLE_SIZE(WINDOW_A)];
// 	struct secp256k1_strauss_point_state ps[1];
// 	struct secp256k1_strauss_state state;

// 	state.aux	= aux;
// 	state.pre_a = pre_a;
// 	state.ps	= ps;
// 	secp256k1_ecmult_strauss_wnaf(&state, r, 1, a, na, ng);
// }
