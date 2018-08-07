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

int tbench_morph25519_mx2e(TBENCH_ARGS)
{
	uint8_t mx[MORPH25519_SIZE];
    uint8_t ex[MORPH25519_SIZE], ey[MORPH25519_SIZE];

	// Create random point
	random_bytes(mx, MORPH25519_SIZE);
    f25519_normalize(mx);

	// START OF BENCHMARK
	START_TBENCH;

    morph25519_m2e(ex, ey, mx, PARITY_BIT);

	// END OF BENCHMARK
	FINISH_TBENCH;

    uint8_t x[MORPH25519_SIZE];
    morph25519_e2m(x, ey);

	return f25519_eq(x, mx);
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

    morph25519_e2m(mx, ey);

	// END OF BENCHMARK
	FINISH_TBENCH;

    uint8_t x[MORPH25519_SIZE], y[MORPH25519_SIZE];
    morph25519_m2e(x, y, mx, PARITY_BIT);

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

    ey2ex(ex, ey, PARITY_BIT);

	// END OF BENCHMARK
	FINISH_TBENCH;

    uint8_t x[MORPH25519_SIZE], y[MORPH25519_SIZE];
    morph25519_m2e(x, y, mx, PARITY_BIT);

	return f25519_eq(y, ey);
}