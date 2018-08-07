#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "random.h"
#include "ecc.h"
#include "test_helper.h"
#include "convert.h"
#include "timing.h"

static int isSameDebug(const uint32_t *A, const uint32_t *B, uint8_t length){
	if(0 != memcmp(A, B, length * sizeof(uint32_t)))  {
		printf("ERROR: ");
		ecc_printNumber(A, length);
		printf(" != ");
		ecc_printNumber(B, length);
	}

	return !memcmp(A, B, length * sizeof(uint32_t));
}

int tbench_dh_P256(long acycles[], int i){
	ecc_ec_init(SECP256R1);
	//These are testvalues taken from the NIST P-256 definition
	//6b17d1f2 e12c4247 f8bce6e5 63a440f2 77037d81 2deb33a0 f4a13945 d898c296
	uint32_t BasePointx[8] = {	0xd898c296, 0xf4a13945, 0x2deb33a0, 0x77037d81,
								0x63a440f2, 0xf8bce6e5, 0xe12c4247, 0x6b17d1f2};

	//4fe342e2 fe1a7f9b 8ee7eb4a 7c0f9e16 2bce3357 6b315ece cbb64068 37bf51f5
	uint32_t BasePointy[8] = {	0x37bf51f5, 0xcbb64068, 0x6b315ece, 0x2bce3357,
								0x7c0f9e16, 0x8ee7eb4a, 0xfe1a7f9b, 0x4fe342e2};

	uint32_t tempx[8];
	uint32_t tempy[8];
	uint32_t tempAx2[8];
	uint32_t tempAy2[8];
	uint32_t tempBx1[8];
	uint32_t tempBy1[8];
	uint32_t tempBx2[8];
	uint32_t tempBy2[8];
	uint32_t secretA[8];
	uint32_t secretB[8];
	ecc_setRandom(secretA);
	ecc_setRandom(secretB);

	// START OF BENCHMARK
	START_TBENCH;

	ecc_ec_mult(BasePointx, BasePointy, secretA, tempx, tempy);
	ecc_ec_mult(BasePointx, BasePointy, secretB, tempBx1, tempBy1);
	//public key exchange
	ecc_ec_mult(tempBx1, tempBy1, secretA, tempAx2, tempAy2);
	ecc_ec_mult(tempx, tempy, secretB, tempBx2, tempBy2);

	// END OF BENCHMARK
	FINISH_TBENCH;

	// Sanity check
	assert(ecc_isSame(tempAx2, tempBx2, arrayLength));
	assert(ecc_isSame(tempAy2, tempBy2, arrayLength));

	return 1;
}

int tbench_dh_Wei(long acycles[], int i){
	ecc_ec_init(WEI25519);

	static const uint32_t wei25519_Gx[8] = {0xaaad245a, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa, 0x2aaaaaaa};
	static const uint32_t wei25519_Gy[8] = {0x7eced3d9, 0x29e9c5a2, 0x6d7c61b2, 0x923d4d7e, 0x7748d14c, 0xe01edd2c, 0xb8a086b4, 0x20ae19a1};
	uint32_t tempx[8];
	uint32_t tempy[8];
	uint32_t tempAx2[8];
	uint32_t tempAy2[8];
	uint32_t tempBx1[8];
	uint32_t tempBy1[8];
	uint32_t tempBx2[8];
	uint32_t tempBy2[8];
	uint32_t secretA[8];
	uint32_t secretB[8];
	ecc_setRandom(secretA);
	ecc_setRandom(secretB);

	// START OF BENCHMARK
	START_TBENCH;

	ecc_ec_mult(wei25519_Gx, wei25519_Gy, secretA, tempx, tempy);
	ecc_ec_mult(wei25519_Gx, wei25519_Gy, secretB, tempBx1, tempBy1);
	//public key exchange
	ecc_ec_mult(tempBx1, tempBy1, secretA, tempAx2, tempAy2);
	ecc_ec_mult(tempx, tempy, secretB, tempBx2, tempBy2);

	// END OF BENCHMARK
	FINISH_TBENCH;

	// Sanity check
	assert(ecc_isSame(tempAx2, tempBx2, arrayLength));
	assert(ecc_isSame(tempAy2, tempBy2, arrayLength));

	return 1;
}

int tbench_dh_Ed(long acycles[], int i){
	ecc_ec_init(WEI25519);
	static const uint32_t ed25519_Gx[8] = {0x8f25d51a, 0xc9562d60, 0x9525a7b2, 0x692cc760, 0xfdd6dc5c, 0xc0a4e231, 0xcd6e53fe, 0x216936d3};
	static const uint32_t ed25519_Gy[8] = {0x66666658, 0x66666666, 0x66666666, 0x66666666, 0x66666666, 0x66666666, 0x66666666, 0x66666666};
	uint32_t tempx[8];
	uint32_t tempy[8];
	uint32_t tempAx2[8];
	uint32_t tempAy2[8];
	uint32_t tempBx1[8];
	uint32_t tempBy1[8];
	uint32_t tempBx2[8];
	uint32_t tempBy2[8];
	uint32_t secretA[8];
	uint32_t secretB[8];
	uint32_t ed25519_QAx[8];
	uint32_t ed25519_QAy[8];
	uint32_t ed25519_QBx[8];
	uint32_t ed25519_QBy[8];

	ecc_setRandom(secretA); // Alice: d_A
	ecc_setRandom(secretB); // Bob: d_B

	uint32_t BasePointx[8];
	uint32_t BasePointy[8];

	// START OF BENCHMARK
	START_TBENCH;

	twisted_edwards_to_short_weierstrass(ed25519_Gx, ed25519_Gy, BasePointx, BasePointy);

	ecc_ec_mult(BasePointx, BasePointy, secretA, tempx, tempy); 	// Alice: Q_A
	ecc_ec_mult(BasePointx, BasePointy, secretB, tempBx1, tempBy1); // Bob: Q_B

	short_weierstrass_to_twisted_edwards(tempx, tempy, ed25519_QAx, ed25519_QAy);
	short_weierstrass_to_twisted_edwards(tempBx1, tempBy1, ed25519_QBx, ed25519_QBy);

	twisted_edwards_to_short_weierstrass(ed25519_QAx, ed25519_QAy, tempx, tempy);
	twisted_edwards_to_short_weierstrass(ed25519_QBx, ed25519_QBy, tempBx1, tempBy1);

	ecc_ec_mult(tempBx1, tempBy1, secretA, tempAx2, tempAy2); // Alice: (x_k,y_k) = d_A * Q_B
	ecc_ec_mult(tempx, tempy, secretB, tempBx2, tempBy2); // Bob: (x_k, y_k) = d_B * Q_A

	// END OF BENCHMARK
	FINISH_TBENCH;

	// Sanity Check
	isSameDebug(tempAx2, tempBx2, arrayLength);
	isSameDebug(tempAy2, tempBy2, arrayLength);

	return 1;
}