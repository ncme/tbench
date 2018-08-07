#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <random.h>
#include "tweetnacl.h"
#include "morph25519.h"
#include "timing.h"

typedef unsigned char u8;

#define PUB_KEY_LEN 32
#define PRIV_KEY_LEN 32
#define NONCE_LEN 24
#define PADDING_LEN 32

#define EQUAL(a, b) if(crypto_verify_32(a, b)) { printf("%s != %s\n",#a,#b); print_point(a, b);};

void hexdump(u8 *data, int len)
{
	int i;
	for (i = 0; i < len; i++) {
		printf("%02X", (u8)data[i]);
	}
	printf("\n");
}

void print_point(u8 *a, u8 *b) {
	hexdump(a, 32);
	hexdump(b, 32);
}

void ecc_bytes2native(u8 *p_bytes)
{
	u8 p_native[32];
    unsigned i;
    for(i=0; i<32; ++i)
    {
        p_native[i] = p_bytes[32-i-1];
    }
	p_bytes = p_native;
}

void ecc_native2bytes(u8 *p_native)
{
	u8 p_bytes[32];
    unsigned i;
    for(i=0; i<32; ++i)
    {
        p_bytes[32-i-1] = p_native[i];
    }
	p_native = p_bytes;
}

int tbench_tweetnacl_x25519(TBENCH_ARGS) {
	u8 prik1[PRIV_KEY_LEN], prik2[PRIV_KEY_LEN];
	u8 pubk1[PUB_KEY_LEN],  pubk2[PUB_KEY_LEN];
	u8 shak1[PUB_KEY_LEN],  shak2[PUB_KEY_LEN];

	/* Create private keys */
	random_bytes(prik1, PRIV_KEY_LEN);
	random_bytes(prik2, PRIV_KEY_LEN);

	// START OF BENCHMARK
	START_TBENCH;

	/* Create public keys */
	crypto_scalarmult_curve25519_base(pubk1, prik1);
	crypto_scalarmult_curve25519_base(pubk2, prik2);

	/* Diffie-Hellman exchange */

	crypto_scalarmult(shak1, prik1, pubk2);
	crypto_scalarmult(shak2, prik2, pubk1);

	// END OF BENCHMARK
	FINISH_TBENCH;

	EQUAL(shak1, shak2);

	return 0 == crypto_verify_32(shak1, shak2);
}

int tbench_tweetnacl_wei_to_mt(TBENCH_ARGS) {
	u8 prik1[PRIV_KEY_LEN], prik2[PRIV_KEY_LEN];
	u8 pubk1[PUB_KEY_LEN],  pubk2[PUB_KEY_LEN];
	u8 pbwx1[PUB_KEY_LEN],  pbwx2[PUB_KEY_LEN];
	u8 pbwy1[PUB_KEY_LEN],  pbwy2[PUB_KEY_LEN];
	u8 shak1[PUB_KEY_LEN],  shak2[PUB_KEY_LEN];
	u8 pbmx1[PUB_KEY_LEN],  pbmx2[PUB_KEY_LEN];
	u8 shwx1[PUB_KEY_LEN],  shwx2[PUB_KEY_LEN];
	u8 shwy1[PUB_KEY_LEN],  shwy2[PUB_KEY_LEN];
	u8 IGNORED[PUB_KEY_LEN] = {0},  NOTUSED[PUB_KEY_LEN];

	/* Create private keys */
	random_bytes(prik1, PRIV_KEY_LEN);
	random_bytes(prik2, PRIV_KEY_LEN);

	// START OF BENCHMARK
	START_TBENCH;

	/* Create public keys */
	crypto_scalarmult_curve25519_base(pubk1, prik1);
	crypto_scalarmult_curve25519_base(pubk2, prik2);
	morph25519_m2w(pbwx1, pbwy1, pubk1, IGNORED);
	morph25519_m2w(pbwx2, pbwy2, pubk2, IGNORED);

	/* Diffie-Hellman exchange */

	morph25519_w2m(pbmx1, NOTUSED, pbwx1, pbwy1);
	morph25519_w2m(pbmx2, NOTUSED, pbwx2, pbwy2);

	crypto_scalarmult(shak1, prik1, pubk2);
	crypto_scalarmult(shak2, prik2, pubk1);

	morph25519_m2w(shwx1, shwy1, shak1, IGNORED);
	morph25519_m2w(shwx2, shwy2, shak2, IGNORED);

	// END OF BENCHMARK
	FINISH_TBENCH;

	EQUAL(shak1, shak2);
	EQUAL(pubk1, pbmx1);
	EQUAL(pubk2, pbmx2);
	EQUAL(shwx1, shwx2);
	EQUAL(shwy1, shwy2);

	return 0 == crypto_verify_32(shak1, shak2);
}

#define PARITY_BIT 0

int tbench_tweetnacl_ed_to_mt(TBENCH_ARGS) {
	u8 prik1[PRIV_KEY_LEN], prik2[PRIV_KEY_LEN];
	u8 pubk1[PUB_KEY_LEN],  pubk2[PUB_KEY_LEN];
	u8 pbwx1[PUB_KEY_LEN],  pbwx2[PUB_KEY_LEN];
	u8 pbwy1[PUB_KEY_LEN],  pbwy2[PUB_KEY_LEN];
	u8 shak1[PUB_KEY_LEN],  shak2[PUB_KEY_LEN];
	u8 pbmx1[PUB_KEY_LEN],  pbmx2[PUB_KEY_LEN];
	u8 shwx1[PUB_KEY_LEN],  shwx2[PUB_KEY_LEN];
	u8 shwy1[PUB_KEY_LEN],  shwy2[PUB_KEY_LEN];

	/* Create private keys */
	random_bytes(prik1, PRIV_KEY_LEN);
	random_bytes(prik2, PRIV_KEY_LEN);

	// START OF BENCHMARK
	START_TBENCH;

	/* Create public keys */
	crypto_scalarmult_curve25519_base(pubk1, prik1);
	crypto_scalarmult_curve25519_base(pubk2, prik2);
	morph25519_m2e(pbwx1, pbwy1, pubk1, PARITY_BIT);
	morph25519_m2e(pbwx2, pbwy2, pubk2, PARITY_BIT);

	/* Diffie-Hellman exchange */

	morph25519_e2m(pbmx1, pbwy1);
	morph25519_e2m(pbmx2, pbwy2);

	crypto_scalarmult(shak1, prik1, pubk2);
	crypto_scalarmult(shak2, prik2, pubk1);

	morph25519_m2e(shwx1, shwy1, shak1, PARITY_BIT);
	morph25519_m2e(shwx2, shwy2, shak2, PARITY_BIT);

	// END OF BENCHMARK
	FINISH_TBENCH;

	EQUAL(shak1, shak2);
	EQUAL(pubk1, pbmx1);
	EQUAL(pubk2, pbmx2);
	EQUAL(shwx1, shwx2);
	EQUAL(shwy1, shwy2);

	return 0 == crypto_verify_32(shak1, shak2);
}