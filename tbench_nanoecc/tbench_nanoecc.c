#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "random.h"
#include "nanoecc.h"
#include "timing.h"
#include "morph25519.h"

void vli_print(uint8_t *p_vli, unsigned int p_size)
{
    while(p_size)
    {
        printf("%02X ", p_vli[p_size - 1]);
        --p_size;
    }
}

int tbench_dh_P256(TBENCH_ARGS){
    EccPoint l_Q1, l_Q2; /* public keys */
    uint8_t l_secret1[NUM_ECC_DIGITS], l_secret2[NUM_ECC_DIGITS];
    uint8_t l_shared1[NUM_ECC_DIGITS], l_shared2[NUM_ECC_DIGITS];
    uint8_t l_random1[NUM_ECC_DIGITS], l_random2[NUM_ECC_DIGITS];

	random_bytes(l_secret1, NUM_ECC_DIGITS);
	random_bytes(l_secret2, NUM_ECC_DIGITS);

	random_bytes(l_random1, NUM_ECC_DIGITS);
	random_bytes(l_random2, NUM_ECC_DIGITS);

	// START OF BENCHMARK
	START_TBENCH;

	ecc_make_key(&l_Q1, l_secret1, l_secret1);
	ecc_make_key(&l_Q2, l_secret2, l_secret2);
	// exchange public keys

	if (!ecdh_shared_secret(l_shared1, &l_Q1, l_secret2, l_random1))
	{
		printf("shared_secret() failed (1)\n");
		return 0;
	}

	if (!ecdh_shared_secret(l_shared2, &l_Q2, l_secret1, l_random2))
	{
		printf("shared_secret() failed (2)\n");
		return 0;
	}

	// END OF BENCHMARK
	FINISH_TBENCH;

	if (memcmp(l_shared1, l_shared2, NUM_ECC_DIGITS) != 0)
	{
		printf("Shared secrets are not identical!\n");
		printf("Shared secret 1 = ");
		vli_print(l_shared1, NUM_ECC_DIGITS);
		printf("\n");
		printf("Shared secret 2 = ");
		vli_print(l_shared2, NUM_ECC_DIGITS);
		printf("\n");
		printf("Private key 1 = ");
		vli_print(l_secret1, NUM_ECC_DIGITS);
		printf("\n");
		printf("Private key 2 = ");
		vli_print(l_secret2, NUM_ECC_DIGITS);
		printf("\n");
		return 0;
	}
    return 1;
}

int nanoeccDhMtToWeiTest(TBENCH_ARGS){
    EccPoint l_Q1, l_Q2, l_P1, l_P2; /* public keys */
    uint8_t l_secret1[NUM_ECC_DIGITS], l_secret2[NUM_ECC_DIGITS];
    uint8_t l_shared1[NUM_ECC_DIGITS], l_shared2[NUM_ECC_DIGITS];
    uint8_t l_random1[NUM_ECC_DIGITS], l_random2[NUM_ECC_DIGITS];
	uint8_t px1[NUM_ECC_DIGITS], px2[NUM_ECC_DIGITS];
	uint8_t py1[NUM_ECC_DIGITS], py2[NUM_ECC_DIGITS];
	uint8_t sx1[NUM_ECC_DIGITS], sx2[NUM_ECC_DIGITS];
	uint8_t IGNORED[NUM_ECC_DIGITS] = {0};
	uint8_t UNUSED[NUM_ECC_DIGITS];

	random_bytes(l_secret1, NUM_ECC_DIGITS);
	random_bytes(l_secret2, NUM_ECC_DIGITS);

	random_bytes(l_random1, NUM_ECC_DIGITS);
	random_bytes(l_random2, NUM_ECC_DIGITS);

	// START OF BENCHMARK
	START_TBENCH;

	ecc_make_key(&l_Q1, l_secret1, l_secret1);
	ecc_make_key(&l_Q2, l_secret2, l_secret2);

	morph25519_w2m(px1, py1, l_Q1.x, l_Q1.y);
	morph25519_w2m(px2, py2, l_Q2.x, l_Q2.y);

	// exchange public keys

	morph25519_m2w(l_P1.x, l_P1.y, px1, py1);
	morph25519_m2w(l_P2.x, l_P2.y, px2, py2);

	if (!ecdh_shared_secret(l_shared1, &l_P1, l_secret2, l_random1))
	{
		printf("shared_secret() failed (1)\n");
		return 0;
	}

	if (!ecdh_shared_secret(l_shared2, &l_P2, l_secret1, l_random2))
	{
		printf("shared_secret() failed (2)\n");
		return 0;
	}

	morph25519_w2m(sx1, UNUSED, l_shared1, IGNORED);
	morph25519_w2m(sx2, UNUSED, l_shared2, IGNORED);

	// END OF BENCHMARK
	FINISH_TBENCH;

	if (memcmp(l_shared1, l_shared2, NUM_ECC_DIGITS) != 0)
	{
		printf("Shared secrets are not identical!\n");
		printf("Shared secret 1 = ");
		vli_print(sx1, NUM_ECC_DIGITS);
		printf("\n");
		printf("Shared secret 2 = ");
		vli_print(l_shared2, NUM_ECC_DIGITS);
		printf("\n");
		printf("Private key 1 = ");
		vli_print(l_secret1, NUM_ECC_DIGITS);
		printf("\n");
		printf("Private key 2 = ");
		vli_print(l_secret2, NUM_ECC_DIGITS);
		printf("\n");
		return 0;
	}
	if (memcmp(sx1, sx2, NUM_ECC_DIGITS) != 0)
	{
		printf("Converted shared secrets are not identical!\n");
		printf("Shared secret 1 = ");
		vli_print(sx1, NUM_ECC_DIGITS);
		printf("\n");
		printf("Shared secret 2 = ");
		vli_print(sx2, NUM_ECC_DIGITS);
		printf("\n");
		return 0;
	}
    return 1;
}