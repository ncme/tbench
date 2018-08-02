#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "random.h"
#include "cpucycles.h"
#include <relic.h>
#include <relic_test.h>

#define BENCH_RELIC_SHOW_OUTPUT 1
#define BENCH_ASSERT_EQUAL_INT(a,b) if(a != b) return 0;

void print_mem(void *mem, int len) {
  int i;
  unsigned char *p = (unsigned char *)mem;
  for (i=0;i<len;i++) {
    printf("0x%02x ", p[i]);
  }
  printf("\n");
}

int tbench_relic_ecdh(long* acycles, int i)
{
    /*  The following is an example for doing an elliptic-curve Diffie-Hellman
        key exchange.
    */

    /* Select an elliptic curve configuration */
    if (ep_param_set_any() == STS_OK) {
#if (BENCH_RELIC_SHOW_OUTPUT == 1)
        ec_param_print();
#endif

        bn_t privateA;
        ec_t publicA;
        uint8_t sharedKeyA[MD_LEN];

        bn_t privateB;
        ec_t publicB;
        uint8_t sharedKeyB[MD_LEN];

        bn_null(privateA);
        ec_null(publicA);

        bn_new(privateA);
        ec_new(publicA);

        bn_null(privateB);
        ec_null(publicB);

        bn_new(privateB);
        ec_new(publicB);

        // START OF BENCHMARK
        long long cycles = cpucycles();

        /* User A generates private/public key pair */
        BENCH_ASSERT_EQUAL_INT(STS_OK, cp_ecdh_gen(privateA, publicA));

#if (BENCH_RELIC_SHOW_OUTPUT == 1)
        printf("User A\n");
        printf("======\n");
        printf("private key: ");
        bn_print(privateA);
        printf("\npublic key:  ");
        ec_print(publicA);
        printf("\n");
#endif

        /* User B generates private/public key pair */
        BENCH_ASSERT_EQUAL_INT(STS_OK, cp_ecdh_gen(privateB, publicB));

#if (BENCH_RELIC_SHOW_OUTPUT == 1)
        printf("User B\n");
        printf("======\n");
        printf("private key: ");
        bn_print(privateB);
        printf("\npublic key:  ");
        ec_print(publicB);
        printf("\n");
#endif

        /* In a protocol you would exchange the public keys now */

        /* User A calculates shared secret */
        BENCH_ASSERT_EQUAL_INT(STS_OK, cp_ecdh_key(sharedKeyA, MD_LEN, privateA, publicB));

#if (BENCH_RELIC_SHOW_OUTPUT == 1)
        printf("\nshared key computed by user A: ");
        print_mem(sharedKeyA, MD_LEN);
#endif

        /* User B calculates shared secret */
        BENCH_ASSERT_EQUAL_INT(STS_OK, cp_ecdh_key(sharedKeyB, MD_LEN, privateB, publicA));

        // END OF BENCHMARK
        acycles[i] = (long) (cpucycles() - cycles);

#if (BENCH_RELIC_SHOW_OUTPUT == 1)
        printf("\nshared key computed by user B: ");
        print_mem(sharedKeyB, MD_LEN);
#endif

        /* The secrets should be the same now */
        BENCH_ASSERT_EQUAL_INT(CMP_EQ, util_cmp_const(sharedKeyA, sharedKeyB, MD_LEN));

        bn_free(privateA);
        ec_free(publicA);

        bn_free(privateB);
        ec_free(publicB);
#if (BENCH_RELIC_SHOW_OUTPUT == 1)
        printf("\nRELIC EC-DH test successful\n");
#endif
	return 1;
    }
	return 0;
}
