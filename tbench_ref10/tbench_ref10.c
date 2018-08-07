#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "random.h"
#include "timing.h"
#include "x25519_ref10.c"
#include "scalarmult_ed25519_ref10.c"
#include "crypto_verify_32.c"
#include "morph25519.h"

typedef unsigned char u8;

#define PUB_KEY_LEN 32
#define PRIV_KEY_LEN 32

int tbench_ref10x25519(TBENCH_ARGS) {
	u8 prik1[PRIV_KEY_LEN], prik2[PRIV_KEY_LEN];
	u8 pubk1[PUB_KEY_LEN],  pubk2[PUB_KEY_LEN];
	u8 shak1[PUB_KEY_LEN],  shak2[PUB_KEY_LEN];

	/* Create private keys */
	random_bytes(prik1, PRIV_KEY_LEN);
	random_bytes(prik2, PRIV_KEY_LEN);

	// START OF BENCHMARK
	START_TBENCH;

	/* Create public keys */
	crypto_scalarmult_curve25519_ref10_base(pubk1, prik1);
	crypto_scalarmult_curve25519_ref10_base(pubk2, prik2);

	/* Diffie-Hellman exchange */
	crypto_scalarmult_curve25519_ref10(shak1, pubk2, prik1);
	crypto_scalarmult_curve25519_ref10(shak2, pubk1, prik2);

	// END OF BENCHMARK
	FINISH_TBENCH;

	return crypto_verify_32(shak1, shak2);
}

int tbench_ref10ed25519(TBENCH_ARGS) {
	u8 prik1[PRIV_KEY_LEN], prik2[PRIV_KEY_LEN];
	u8 pubk1[PUB_KEY_LEN],  pubk2[PUB_KEY_LEN];
	u8 shak1[PUB_KEY_LEN],  shak2[PUB_KEY_LEN];

	/* Create private keys */
	random_bytes(prik1, PRIV_KEY_LEN);
	random_bytes(prik2, PRIV_KEY_LEN);

	// START OF BENCHMARK
	START_TBENCH;

	/* Create public keys */
	crypto_scalarmult_ed25519_base(pubk1, prik1);
	crypto_scalarmult_ed25519_base(pubk2, prik2);

	/* Diffie-Hellman exchange */

	crypto_scalarmult_ed25519(shak1, pubk2, prik1);
	crypto_scalarmult_ed25519(shak2, pubk1, prik2);

	// END OF BENCHMARK
	FINISH_TBENCH;

	return crypto_verify_32(shak1, shak2);
}

int tbench_ref10_wei_to_x25519(TBENCH_ARGS) {
	u8 prik1[PRIV_KEY_LEN], prik2[PRIV_KEY_LEN];
	u8 pubk1[PUB_KEY_LEN],  pubk2[PUB_KEY_LEN];
	u8 shak1[PUB_KEY_LEN],  shak2[PUB_KEY_LEN];

	u8 NOTUSED[PRIV_KEY_LEN], IGNORED[PRIV_KEY_LEN] = {1};
	u8 weix1[32], weiy1[32], weix2[32], weiy2[32];
	u8 dhk1[PUB_KEY_LEN], dhk2[PUB_KEY_LEN];

	/* Create private keys */
	random_bytes(prik1, PRIV_KEY_LEN);
	random_bytes(prik2, PRIV_KEY_LEN);

	// START OF BENCHMARK
	START_TBENCH;

	/* Create public keys */
	crypto_scalarmult_curve25519_ref10_base(pubk1, prik1);
	crypto_scalarmult_curve25519_ref10_base(pubk2, prik2);
	morph25519_m2w(weix1, weiy1, pubk1, IGNORED);
	morph25519_m2w(weix2, weiy2, pubk2, IGNORED);

	/* Diffie-Hellman exchange */
	morph25519_w2m(dhk1, NOTUSED, weix1, weiy1);
	morph25519_w2m(dhk2, NOTUSED, weix2, weiy2);
	crypto_scalarmult_curve25519_ref10(shak1, dhk2, prik1);
	crypto_scalarmult_curve25519_ref10(shak2, dhk1, prik2);

	// END OF BENCHMARK
	FINISH_TBENCH;

	return crypto_verify_32(shak1, shak2);
}