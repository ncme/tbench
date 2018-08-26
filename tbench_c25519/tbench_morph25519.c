/* Curve25519 (Montgomery form)
 * Daniel Beer <dlbeer@gmail.com>, 18 Apr 2014
 *
 * This file is in the public domain.
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <random.h>
#include <morph25519.h>
#include <f25519.h>

#define TBENCH_COUNT_MICROS
#include "timing.h"

#define MORPH25519_SIZE 32
#define PARITY_BIT 0

int tbench_morph25519_w2m(TBENCH_ARGS)
{
	uint8_t wx[MORPH25519_SIZE], wy[MORPH25519_SIZE];
    uint8_t mx[MORPH25519_SIZE], my[MORPH25519_SIZE];

	// Create random point
	random_bytes(wx, MORPH25519_SIZE);
	random_bytes(wy, MORPH25519_SIZE);
	f25519_normalize(wx);
    f25519_normalize(wy);

	// START OF BENCHMARK
	START_TBENCH;

    morph25519_w2m(mx, my, wx, wy);

	// END OF BENCHMARK
	FINISH_TBENCH;

    uint8_t x[MORPH25519_SIZE], y[MORPH25519_SIZE];
    morph25519_m2w(x, y, mx, my);

	return f25519_eq(x, wx) && f25519_eq(y, wy);
}

int tbench_morph25519_m2w(TBENCH_ARGS)
{
    uint8_t mx[MORPH25519_SIZE], my[MORPH25519_SIZE];
    uint8_t wx[MORPH25519_SIZE], wy[MORPH25519_SIZE];

	// Create random point
	random_bytes(mx, MORPH25519_SIZE);
	random_bytes(my, MORPH25519_SIZE);
	f25519_normalize(mx);
    f25519_normalize(my);

	// START OF BENCHMARK
	START_TBENCH;

	morph25519_m2w(wx, wy, mx, my);

	// END OF BENCHMARK
	FINISH_TBENCH;

    uint8_t x[MORPH25519_SIZE], y[MORPH25519_SIZE];
    morph25519_w2m(x, y, wx, wy);

	return f25519_eq(x, mx) && f25519_eq(y, my);
}

int tbench_morph25519_w2e(TBENCH_ARGS)
{
	uint8_t wx[MORPH25519_SIZE], wy[MORPH25519_SIZE];
    uint8_t ex[MORPH25519_SIZE], ey[MORPH25519_SIZE];

	// Create random point
	random_bytes(wx, MORPH25519_SIZE);
	random_bytes(wy, MORPH25519_SIZE);
	f25519_normalize(wx);
    f25519_normalize(wy);

	// START OF BENCHMARK
	START_TBENCH;

	morph25519_w2e(ex, ey, wx, wy);

	// END OF BENCHMARK
	FINISH_TBENCH;

    uint8_t x[MORPH25519_SIZE], y[MORPH25519_SIZE];
    morph25519_e2w(x, y, ex, ey);

	return f25519_eq(x, wx) && f25519_eq(y, wy);
}

int tbench_morph25519_e2w(TBENCH_ARGS)
{
    uint8_t ex[MORPH25519_SIZE], ey[MORPH25519_SIZE];
	uint8_t wx[MORPH25519_SIZE], wy[MORPH25519_SIZE];

	// Create random point
	random_bytes(ex, MORPH25519_SIZE);
	random_bytes(ey, MORPH25519_SIZE);
	f25519_normalize(ex);
    f25519_normalize(ey);

	// START OF BENCHMARK
	START_TBENCH;

    morph25519_e2w(wx, wy, ex, ey);

	// END OF BENCHMARK
	FINISH_TBENCH;

    uint8_t x[MORPH25519_SIZE], y[MORPH25519_SIZE];
    morph25519_w2e(x, y, wx, wy);

	return f25519_eq(x, ex) && f25519_eq(y, ey);
}

int tbench_morph25519_e2m(TBENCH_ARGS)
{
    uint8_t ex[MORPH25519_SIZE], ey[MORPH25519_SIZE];
	uint8_t mx[MORPH25519_SIZE], my[MORPH25519_SIZE];

	// Create random point
	random_bytes(ex, MORPH25519_SIZE);
	random_bytes(ey, MORPH25519_SIZE);
	f25519_normalize(ex);
    f25519_normalize(ey);

	// START OF BENCHMARK
	START_TBENCH;

    morph25519_e2m(mx, my, ex, ey);

	// END OF BENCHMARK
	FINISH_TBENCH;

    uint8_t x[MORPH25519_SIZE], y[MORPH25519_SIZE];
    morph25519_m2e(x, y, mx, my);

	return f25519_eq(x, ex) && f25519_eq(y, ey);
}

int tbench_morph25519_m2e(TBENCH_ARGS)
{
	uint8_t mx[MORPH25519_SIZE], my[MORPH25519_SIZE];
    uint8_t ex[MORPH25519_SIZE], ey[MORPH25519_SIZE];

	// Create random point
	random_bytes(mx, MORPH25519_SIZE);
	random_bytes(my, MORPH25519_SIZE);
	f25519_normalize(mx);
    f25519_normalize(my);

	// START OF BENCHMARK
	START_TBENCH;

	morph25519_m2e(ex, ey, mx, my);

	// END OF BENCHMARK
	FINISH_TBENCH;

    uint8_t x[MORPH25519_SIZE], y[MORPH25519_SIZE];
    morph25519_e2m(x, y, ex, ey);

	return f25519_eq(x, mx) && f25519_eq(y, my);
}

int tbench_morph25519_mx2ey(TBENCH_ARGS)
{
	uint8_t mx[MORPH25519_SIZE];
    uint8_t ey[MORPH25519_SIZE];

	// Create random point
	random_bytes(mx, MORPH25519_SIZE);
    f25519_normalize(mx);

	// START OF BENCHMARK
	START_TBENCH;

    morph25519_mx2ey(ey, mx);

	// END OF BENCHMARK
	FINISH_TBENCH;

    uint8_t x[MORPH25519_SIZE];
    morph25519_ey2mx(x, ey);

	return f25519_eq(x, mx);
}

int tbench_morph25519_mx2wx(TBENCH_ARGS)
{
	uint8_t mx[MORPH25519_SIZE];
    uint8_t wx[MORPH25519_SIZE];

	// Create random point
	random_bytes(mx, MORPH25519_SIZE);
    f25519_normalize(mx);

	// START OF BENCHMARK
	START_TBENCH;

    morph25519_mx2wx(wx, mx);

	// END OF BENCHMARK
	FINISH_TBENCH;

    uint8_t x[MORPH25519_SIZE];
    morph25519_wx2mx(x, wx);

	return f25519_eq(x, mx);
}

int tbench_morph25519_wx2mx(TBENCH_ARGS)
{
	uint8_t mx[MORPH25519_SIZE];
    uint8_t wx[MORPH25519_SIZE];

	// Create random point
	random_bytes(wx, MORPH25519_SIZE);
    f25519_normalize(wx);

	// START OF BENCHMARK
	START_TBENCH;

    morph25519_wx2mx(mx, wx);

	// END OF BENCHMARK
	FINISH_TBENCH;

    uint8_t x[MORPH25519_SIZE];
    morph25519_mx2wx(x, mx);

	return f25519_eq(x, wx);
}

int tbench_morph25519_ey2mx(TBENCH_ARGS)
{
	uint8_t mx[MORPH25519_SIZE];
    uint8_t ex[MORPH25519_SIZE], ey[MORPH25519_SIZE];

	// Create random point
    random_bytes(ex, MORPH25519_SIZE);
	random_bytes(ey, MORPH25519_SIZE);
	f25519_normalize(ex);
    f25519_normalize(ey);

	// START OF BENCHMARK
	START_TBENCH;

    morph25519_ey2mx(mx, ey);

	// END OF BENCHMARK
	FINISH_TBENCH;

    uint8_t x[MORPH25519_SIZE], y[MORPH25519_SIZE];
    morph25519_mx2e(x, y, mx, PARITY_BIT);

	return f25519_eq(y, ey);
}

int tbench_morph25519_ey2ex(TBENCH_ARGS)
{
    uint8_t ex[MORPH25519_SIZE], ey[MORPH25519_SIZE];

	// Create random point
	random_bytes(ey, MORPH25519_SIZE);
    f25519_normalize(ey);

	// START OF BENCHMARK
	START_TBENCH;

    morph25519_ey2ex(ex, ey, PARITY_BIT);

	// END OF BENCHMARK
	FINISH_TBENCH;

	return f25519_eq(ey, ey);
}

int tbench_morph25519_recover_mt(TBENCH_ARGS)
{
    uint8_t xQ[MORPH25519_SIZE], yQ[MORPH25519_SIZE], zQ[MORPH25519_SIZE];
	uint8_t xP[MORPH25519_SIZE], yP[MORPH25519_SIZE];
	uint8_t XQ[MORPH25519_SIZE], ZQ[MORPH25519_SIZE] = {1};
	uint8_t xD[MORPH25519_SIZE], zD[MORPH25519_SIZE] = {1};

	// Create random point
	random_bytes(xP, MORPH25519_SIZE);
	random_bytes(yP, MORPH25519_SIZE);
	random_bytes(XQ, MORPH25519_SIZE);
	random_bytes(xD, MORPH25519_SIZE);

    f25519_normalize(xP);
	f25519_normalize(yP);
	f25519_normalize(XQ);
	f25519_normalize(xD);

	// START OF BENCHMARK
	START_TBENCH;

	morph25519_montgomery_recovery(xQ, yQ, zQ, xP, yP, XQ, ZQ, xD, zD);

	// END OF BENCHMARK
	FINISH_TBENCH;

	return 1;
}

int tbench_morph25519_wx2wy(TBENCH_ARGS)
{
	uint8_t wx[MORPH25519_SIZE], wy[MORPH25519_SIZE];

	// Create random point
	random_bytes(wy, MORPH25519_SIZE);
    f25519_normalize(wy);

	// START OF BENCHMARK
	START_TBENCH;

    morph25519_wx2wy(wy, wx, PARITY_BIT);

	// END OF BENCHMARK
	FINISH_TBENCH;

	return f25519_eq(wy, wy);
}