/* Curve25519 (Montgomery form)
 * Daniel Beer <dlbeer@gmail.com>, 18 Apr 2014
 *
 * This file is in the public domain.
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <random.h>
#include <c25519.h>
#include <f25519.h>
#include <ed25519.h>
#include <morph25519.h>
#include "edsign.h"
#include "timing.h"


#define PARITY_BIT 0

#define EQUAL(a, b) if(!f25519_eq(a, b)) { printf("%s != %s\n",#a,#b); print_point(a, b);};

static void print_point(const uint8_t *x, const uint8_t *y)
{
	int i;

	printf("  ");
	for (i = 0; i < F25519_SIZE; i++)
		printf("%02x", x[i]);
	printf(", ");
	for (i = 0; i < F25519_SIZE; i++)
		printf("%02x", y[i]);
	printf("\n");
}

int tbench_dh_mt(TBENCH_ARGS)
{
	uint8_t e1[C25519_EXPONENT_SIZE];
	uint8_t e2[C25519_EXPONENT_SIZE];
	uint8_t q1[F25519_SIZE];
	uint8_t q2[F25519_SIZE];
	uint8_t r1[F25519_SIZE];
	uint8_t r2[F25519_SIZE];

	/* Create private keys */
	random_bytes(e1, C25519_EXPONENT_SIZE);
	random_bytes(e2, C25519_EXPONENT_SIZE);
	c25519_prepare(e1);
	c25519_prepare(e2);

	// START OF BENCHMARK
	START_TBENCH;

	/* Create public keys */
	c25519_smult(q1, c25519_base_x, e1);
	c25519_smult(q2, c25519_base_x, e2);

	/* Diffie-Hellman exchange */
	c25519_smult(r1, q2, e1);
	c25519_smult(r2, q1, e2);

	// END OF BENCHMARK
	FINISH_TBENCH;

	return f25519_eq(r1, r2);
}

int tbench_dh_ed(TBENCH_ARGS)
{
	uint8_t e1[C25519_EXPONENT_SIZE];
	uint8_t e2[C25519_EXPONENT_SIZE];
	struct ed25519_pt q1;
	struct ed25519_pt q2;
	struct ed25519_pt r1;
	struct ed25519_pt r2;
	uint8_t x1[32], x2[32], y1[32], y2[32];

	/* Create private keys */
	random_bytes(e1, C25519_EXPONENT_SIZE);
	random_bytes(e2, C25519_EXPONENT_SIZE);
	c25519_prepare(e1);
	c25519_prepare(e2);

	// START OF BENCHMARK
	START_TBENCH;

	/* Create public keys */
	ed25519_smult(&q1, &ed25519_base, e1);
	ed25519_smult(&q2, &ed25519_base, e2);

	/* Diffie-Hellman exchange */
	ed25519_smult(&r1, &q2, e1);
	ed25519_smult(&r2, &q1, e2);

	ed25519_unproject(x1, y1, &r1);
	ed25519_unproject(x2, y2, &r2);

	// END OF BENCHMARK
	FINISH_TBENCH;

	return f25519_eq(x1, x2) && f25519_eq(y1, y2);
}

int tbench_dh_mt_to_ed(TBENCH_ARGS)
{
	uint8_t e1[ED25519_EXPONENT_SIZE];
	uint8_t e2[ED25519_EXPONENT_SIZE];
	struct ed25519_pt q1;
	struct ed25519_pt q2;
	struct ed25519_pt r1;
	struct ed25519_pt r2;
	uint8_t x1[32], x2[32], y1[32], y2[32];
	uint8_t m1[32], m2[32], ex1[32], ex2[32], ey1[32], ey2[32], mx1[32], mx2[32], my1[32], my2[32];

	/* Create private keys */
	random_bytes(e1, ED25519_EXPONENT_SIZE);
	random_bytes(e2, ED25519_EXPONENT_SIZE);
	ed25519_prepare(e1);
	ed25519_prepare(e2);

	// START OF BENCHMARK
	START_TBENCH;

	/* Create public keys */
	ed25519_smult(&q1, &ed25519_base, e1);
	ed25519_unproject(mx1, my1, &q1);
	morph25519_e2m(m1, my1);

	ed25519_smult(&q2, &ed25519_base, e2);
	ed25519_unproject(mx2, my2, &q2);
	morph25519_e2m(m2, my2);

	/* Diffie-Hellman exchange */

	morph25519_m2e(ex1, ey1, m1, morph25519_eparity(mx1));
	ed25519_project(&q1, ex1, ey1);
	ed25519_smult(&r2, &q1, e2);
	ed25519_unproject(x2, y2, &r2);

	morph25519_m2e(ex2, ey2, m2, morph25519_eparity(mx2));
	ed25519_project(&q2, ex2, ey2);
	ed25519_smult(&r1, &q2, e1);
	ed25519_unproject(x1, y1, &r1);

	// END OF BENCHMARK
	FINISH_TBENCH;

	EQUAL(mx1, ex1);
	EQUAL(my1, ey1);
	EQUAL(mx2, ex2);
	EQUAL(my2, ey2);
	EQUAL(x1, x2);
	EQUAL(y1, y2);
	return 1;
}

int tbench_dh_ed_to_mt(TBENCH_ARGS)
{
	uint8_t e1[C25519_EXPONENT_SIZE];
	uint8_t e2[C25519_EXPONENT_SIZE];
	uint8_t q1[F25519_SIZE];
	uint8_t q2[F25519_SIZE];
	uint8_t r1[F25519_SIZE];
	uint8_t r2[F25519_SIZE];

	uint8_t m1[32], m2[32], ex1[32], ex2[32], ey1[32], ey2[32], qm1[32], qm2[32], mx1[32], mx2[32], my1[32], my2[32];

	/* Create private keys */
	random_bytes(e1, C25519_EXPONENT_SIZE);
	random_bytes(e2, C25519_EXPONENT_SIZE);
	ed25519_prepare(e1);
	ed25519_prepare(e2);

	// START OF BENCHMARK
	START_TBENCH;

	/* Create public keys */
	c25519_smult(q1, c25519_base_x, m1);
	c25519_smult(q2, c25519_base_x, m2);
	morph25519_m2e(ex1, ey1, q1, PARITY_BIT);
	morph25519_m2e(ex2, ey2, q2, PARITY_BIT);

	/* Diffie-Hellman exchange */

	morph25519_e2m(qm1, ey1);
	morph25519_e2m(qm2, ey2);

	c25519_smult(r1, qm2, m1);
	c25519_smult(r2, qm1, m2);

	morph25519_m2e(mx1, my1, r1, PARITY_BIT);
	morph25519_m2e(mx2, my2, r2, PARITY_BIT);

	// END OF BENCHMARK
	FINISH_TBENCH;

	return f25519_eq(r1, r2) && f25519_eq(mx1, mx2) && f25519_eq(my1, my2);
}

int tbench_dh_wei_to_ed(TBENCH_ARGS)
{
	uint8_t e1[ED25519_EXPONENT_SIZE];
	uint8_t e2[ED25519_EXPONENT_SIZE];
	struct ed25519_pt q1;
	struct ed25519_pt q2;
	struct ed25519_pt r1;
	struct ed25519_pt r2;
	uint8_t x1[32], x2[32], y1[32], y2[32];
	uint8_t dhx1[32], dhx2[32], dhy1[32], dhy2[32], ex1[32], ex2[32], ey1[32], ey2[32], wx1[32], wx2[32], wy1[32], wy2[32];

	/* Create private keys */
	random_bytes(e1, ED25519_EXPONENT_SIZE);
	random_bytes(e2, ED25519_EXPONENT_SIZE);
	ed25519_prepare(e1);
	ed25519_prepare(e2);

	// START OF BENCHMARK
	START_TBENCH;

	/* Create public keys */
	ed25519_smult(&q1, &ed25519_base, e1);
	ed25519_unproject(ex1, ey1, &q1);
	morph25519_e2w(wx1, wy1, ex1, ey1);

	ed25519_smult(&q2, &ed25519_base, e2);
	ed25519_unproject(ex2, ey2, &q2);
	morph25519_e2w(wx2, wy2, ex2, ey2);

	/* Diffie-Hellman exchange */

	morph25519_w2e(dhx1, dhy1, wx1, wy1);
	ed25519_project(&q1, dhx1, dhy1);
	ed25519_smult(&r2, &q1, e2);
	ed25519_unproject(x2, y2, &r2);

	morph25519_w2e(dhx2, dhy2, wx2, wy2);
	ed25519_project(&q2, dhx2, dhy2);
	ed25519_project(&q2, ex2, ey2);
	ed25519_smult(&r1, &q2, e1);
	ed25519_unproject(x1, y1, &r1);

	// END OF BENCHMARK
	FINISH_TBENCH;

	EQUAL(dhx1, ex1);
	EQUAL(dhy1, ey1);
	EQUAL(dhx2, ex2);
	EQUAL(dhy2, ey2);
	EQUAL(x1, x2);
	EQUAL(y1, y2);
	return 1;
}

int tbench_dh_wei_to_mt(TBENCH_ARGS)
{
	uint8_t e1[C25519_EXPONENT_SIZE];
	uint8_t e2[C25519_EXPONENT_SIZE];
	uint8_t r1[F25519_SIZE];
	uint8_t r2[F25519_SIZE];
	uint8_t NOTUSED[F25519_SIZE];
	const uint8_t* IGNORED = f25519_one;

	uint8_t m1[32], m2[32], wx1[32], wx2[32], wy1[32], wy2[32], qm1[32], qm2[32], mx1[32], mx2[32], my1[32], my2[32];

	/* Create private keys */
	random_bytes(e1, C25519_EXPONENT_SIZE);
	random_bytes(e2, C25519_EXPONENT_SIZE);
	c25519_prepare(e1);
	c25519_prepare(e2);

	// START OF BENCHMARK
	START_TBENCH;

	/* Create public keys */
	c25519_smult(m1, c25519_base_x, e1);
	c25519_smult(m2, c25519_base_x, e2);
	morph25519_m2w(wx1, wy1, m1, IGNORED);
	morph25519_m2w(wx2, wy2, m2, IGNORED);

	/* Diffie-Hellman exchange */

	morph25519_w2m(qm1, NOTUSED, wx1, wy1);
	morph25519_w2m(qm2, NOTUSED, wx2, wy2);
	c25519_smult(r1, qm2, e1);
	c25519_smult(r2, qm1, e2);
	morph25519_m2w(mx1, my1, r1, IGNORED);
	morph25519_m2w(mx2, my2, r2, IGNORED);

	// END OF BENCHMARK
	FINISH_TBENCH;

	EQUAL(m1, qm1);
	EQUAL(m2, qm2);
	EQUAL(r1, r2);
	EQUAL(mx1, mx2);
	EQUAL(my1, my2);
	return 1;
}

#define EDSIGN_PUBLIC_KEY_SIZE 32
#define MAX_MSG_SIZE  128
#define EDSIGN_SIGNATURE_SIZE 64
#define EDSIGN_SECRET_KEY_SIZE 32

int tbench_eddsa_sign(TBENCH_ARGS)
{
	uint8_t pub[EDSIGN_PUBLIC_KEY_SIZE];
	uint8_t msg[MAX_MSG_SIZE];
	uint8_t signature[EDSIGN_SIGNATURE_SIZE];
	uint8_t secret[EDSIGN_SECRET_KEY_SIZE];

	random_bytes(secret, EDSIGN_SECRET_KEY_SIZE);
	random_bytes(msg, MAX_MSG_SIZE);

	// START OF BENCHMARK
	START_TBENCH;
	edsign_sec_to_pub(pub, secret);
	edsign_sign(signature, pub, secret, msg, MAX_MSG_SIZE);
	// END OF BENCHMARK
	FINISH_TBENCH;

	return edsign_verify(signature, pub, msg, MAX_MSG_SIZE);
}

int tbench_eddsa_verify(TBENCH_ARGS)
{
	uint8_t pub[EDSIGN_PUBLIC_KEY_SIZE];
	uint8_t msg[MAX_MSG_SIZE];
	uint8_t signature[EDSIGN_SIGNATURE_SIZE];
	uint8_t secret[EDSIGN_SECRET_KEY_SIZE];

	random_bytes(secret, EDSIGN_SECRET_KEY_SIZE);
	random_bytes(msg, MAX_MSG_SIZE);

	edsign_sec_to_pub(pub, secret);
	edsign_sign(signature, pub, secret, msg, MAX_MSG_SIZE);

	// START OF BENCHMARK
	START_TBENCH;
	int ret = 1;
	ret = edsign_verify(signature, pub, msg, MAX_MSG_SIZE);
	// END OF BENCHMARK
	FINISH_TBENCH;
	return ret;
}