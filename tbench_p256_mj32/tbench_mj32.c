#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "random.h"
#include "timing.h"
#include "crypto_scalarmult_nistp256.h"

#include "crypto_verify_64.c"
#include "morph25519.h"

typedef unsigned char u8;

#define BYTES crypto_scalarmult_nistp256_BYTES
#define SCALARBYTES crypto_scalarmult_nistp256_SCALARBYTES

int tbench_mj32p256(TBENCH_ARGS) {
	u8 prik1[SCALARBYTES], prik2[SCALARBYTES];
	u8 pubk1[BYTES],  pubk2[BYTES];
	u8 shak1[BYTES],  shak2[BYTES];

	/* Create private keys */
	random_bytes(prik1, SCALARBYTES);
	random_bytes(prik2, SCALARBYTES);

	// START OF BENCHMARK
	START_TBENCH;
	#ifndef Wei25519
	static const unsigned char basepoint[BYTES] = {
    0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47,
    0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
    0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0,
    0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
    0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b,
    0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16,
    0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce,
    0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5
	};
	#else
	static const unsigned char basepoint[BYTES] = {
		0x2a, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xad, 0x24, 0x5a, // the x coordinate of the base point
		0x20, 0xae, 0x19, 0xa1, 0xb8, 0xa0, 0x86, 0xb4,
		0xe0, 0x1e, 0xdd, 0x2c, 0x77, 0x48, 0xd1, 0x4c,
		0x92, 0x3d, 0x4d, 0x7e, 0x6d, 0x7c, 0x61, 0xb2,
		0x29, 0xe9, 0xc5, 0xa2, 0x7e, 0xce, 0xd3, 0xd9  // the y coordinate of the base point
	};
	#endif
	/* Create public keys */
	assert(0 == crypto_scalarmult_nistp256_base(pubk1, prik1));
	assert(0 == crypto_scalarmult_nistp256_base(pubk2, prik2));
	//assert(0 == crypto_scalarmult_nistp256(pubk1, prik1, basepoint));
	//assert(0 == crypto_scalarmult_nistp256(pubk2, prik2, basepoint));

	/* Diffie-Hellman exchange */
	assert(0 == crypto_scalarmult_nistp256(shak1, prik1, pubk2));
	assert(0 == crypto_scalarmult_nistp256(shak2, prik2, pubk1));
	// END OF BENCHMARK
	FINISH_TBENCH;

	return !crypto_verify_64(shak1, shak2);
}
/*
int tbench_ref10_wei_to_x25519(TBENCH_ARGS) {
	u8 prik1[PRIV_KEY_LEN], prik2[PRIV_KEY_LEN];
	u8 pubk1[PUB_KEY_LEN],  pubk2[PUB_KEY_LEN];
	u8 shak1[PUB_KEY_LEN],  shak2[PUB_KEY_LEN];

	u8 NOTUSED[PRIV_KEY_LEN], IGNORED[PRIV_KEY_LEN] = {1};
	u8 weix1[32], weiy1[32], weix2[32], weiy2[32];
	u8 dhk1[PUB_KEY_LEN], dhk2[PUB_KEY_LEN];

	// Create private keys
	random_bytes(prik1, PRIV_KEY_LEN);
	random_bytes(prik2, PRIV_KEY_LEN);

	// START OF BENCHMARK
	START_TBENCH;

	// Create public keys
	crypto_scalarmult_curve25519_ref10_base(pubk1, prik1);
	crypto_scalarmult_curve25519_ref10_base(pubk2, prik2);
	morph25519_m2w(weix1, weiy1, pubk1, IGNORED);
	morph25519_m2w(weix2, weiy2, pubk2, IGNORED);

	// Diffie-Hellman exchange

	morph25519_w2m(dhk1, NOTUSED, weix1, weiy1);
	morph25519_w2m(dhk2, NOTUSED, weix2, weiy2);
	crypto_scalarmult_curve25519_ref10(shak1, dhk2, prik1);
	crypto_scalarmult_curve25519_ref10(shak2, dhk1, prik2);

	// END OF BENCHMARK
	FINISH_TBENCH;

	return crypto_verify_32(shak1, shak2);
}
*/