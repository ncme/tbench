/*
 * tiny crypto bench - entry point
 *
 * Copyright (C) 2018 Nikolas Rösener <nroesener@uni-bremen.de>
 *
 */

#include <stdio.h>
#include <timex.h>
#include <board.h>
#include <periph/uart.h>
#include "xtimer.h"
//#include <shed.h>

#include "tbench.h"

/* disable LED switching for boards that don't have one */
#ifndef LED0_PORT
	#undef LED0_ON
	#undef LED0_TOGGLE
	#undef LED0_OFF
	#define LED0_ON {}
	#define LED0_TOGGLE {}
	#define LED0_OFF {}
#endif

#define ONE_SECOND (1U * US_PER_SEC)
#define sleep(t) xtimer_periodic_wakeup(&last_wakeup, t * US_PER_MS);

int main(void)
{
    LED0_OFF;
    xtimer_ticks32_t last_wakeup = xtimer_now();

    printf("You are running RIOT on a(n) %s board.\n", RIOT_BOARD);
    printf("This board features a(n) %s MCU.\n", RIOT_MCU);

    while(1) {
		printf("\n\nStart of a tbench cycle!\n");
        LED0_ON;
        xtimer_periodic_wakeup(&last_wakeup, ONE_SECOND);
        LED0_OFF;

		//print_stack();

		if(RUN_BENCH)
			printf("IMPL %-12s (%03d iterations)   Last\tMean\t  Median      Min\t Max\n",
					IMPL, TBENCH_CYCLES);
		else
			printf("No benchmarks loaded!\n");

		#ifdef TBENCH_DH_P256
			run_benchmark("TBENCH_DH_P256", TBENCH, TBENCH_CYCLES, TBENCH_DH_P256);
		#endif
		#ifdef TBENCH_DH_WEI25519
			run_benchmark("TBENCH_DH_WEI25519", TBENCH, TBENCH_CYCLES, TBENCH_DH_WEI25519);
		#endif
		#ifdef TBENCH_DH_ED25519_TO_WEI25519
			run_benchmark("TBENCH_DH_ED25519_TO_WEI25519",
				TBENCH, TBENCH_CYCLES, TBENCH_DH_ED25519_TO_WEI25519);
		#endif
		#ifdef TBENCH_DH_CURVE25519_TO_WEI25519
			run_benchmark("TBENCH_DH_CURVE25519_TO_WEI25519",
				TBENCH, TBENCH_CYCLES, TBENCH_DH_CURVE25519_TO_WEI25519);
		#endif
		#ifdef TBENCH_DH_X25519
			run_benchmark("TBENCH_DH_X25519 ",
				TBENCH, TBENCH_CYCLES, TBENCH_DH_X25519);
		#endif
		#ifdef TBENCH_DH_CURVE25519
			run_benchmark("TBENCH_DH_CURVE25519 ",
				TBENCH, TBENCH_CYCLES, TBENCH_DH_CURVE25519);
		#endif
		#ifdef TBENCH_DH_ED25519
			run_benchmark("TBENCH_DH_ED25519",
				TBENCH, TBENCH_CYCLES, TBENCH_DH_ED25519);
		#endif
		#ifdef TBENCH_DH_ED25519_TO_X25519
			run_benchmark("TBENCH_DH_ED_TO_MTX",
				TBENCH, TBENCH_CYCLES, TBENCH_DH_ED25519_TO_X25519);
		#endif
		#ifdef TBENCH_DH_ED25519_TO_CURVE25519
			run_benchmark("TBENCH_DH_ED_TO_MT",
				TBENCH, TBENCH_CYCLES, TBENCH_DH_ED25519_TO_CURVE25519);
		#endif
		#ifdef TBENCH_DH_X25519_TO_ED25519
			run_benchmark("TBENCH_DH_MTX_TO_ED",
				TBENCH, TBENCH_CYCLES, TBENCH_DH_X25519_TO_ED25519);
		#endif
		#ifdef TBENCH_DH_CURVE25519_TO_ED25519
			run_benchmark("TBENCH_DH_MT_TO_ED",
				TBENCH, TBENCH_CYCLES, TBENCH_DH_CURVE25519_TO_ED25519);
		#endif
		#ifdef TBENCH_DH_WEI25519_1_TO_X25519
			run_benchmark("TBENCH_DH_WEI_TO_MTX",
				TBENCH, TBENCH_CYCLES, TBENCH_DH_WEI25519_1_TO_X25519);
		#endif
		#ifdef TBENCH_DH_WEI25519_1_TO_CURVE25519
			run_benchmark("TBENCH_DH_WEI_TO_MT",
				TBENCH, TBENCH_CYCLES, TBENCH_DH_WEI25519_1_TO_CURVE25519);
		#endif
		#ifdef TBENCH_DH_WEI25519_1_TO_ED25519
			run_benchmark("TBENCH_DH_WEI_TO_ED",
				TBENCH, TBENCH_CYCLES, TBENCH_DH_WEI25519_1_TO_ED25519);
		#endif
		#ifdef TBENCH_EDDSA_ED25519_SIGN
			run_benchmark("TBENCH_EDDSA_ED25519_SIGN",
				TBENCH, TBENCH_CYCLES, TBENCH_EDDSA_ED25519_SIGN);
		#endif
		#ifdef TBENCH_EDDSA_ED25519_VERIFY
			run_benchmark("TBENCH_EDDSA_ED25519_VERIFY",
				TBENCH, TBENCH_CYCLES, TBENCH_EDDSA_ED25519_VERIFY);
		#endif
		#ifdef TBENCH_ECDSA_ED25519_SIGN
			run_benchmark("TBENCH_ECDSA_ED25519_SIGN",
				TBENCH, TBENCH_CYCLES, TBENCH_ECDSA_ED25519_SIGN);
		#endif
		#ifdef TBENCH_ECDSA_ED25519_VERIFY
			run_benchmark("TBENCH_ECDSA_ED25519_VERIFY",
				TBENCH, TBENCH_CYCLES, TBENCH_ECDSA_ED25519_VERIFY);
		#endif
		#ifdef TBENCH_CONV_WX2MX
			run_benchmark("TBENCH_CONV_WX2MX",
				TBENCH, TBENCH_CYCLES, TBENCH_CONV_WX2MX);
		#endif
		#ifdef TBENCH_CONV_MX2WX
			run_benchmark("TBENCH_CONV_MX2WX",
				TBENCH, TBENCH_CYCLES, TBENCH_CONV_MX2WX);
		#endif
		#ifdef TBENCH_CONV_MX2EY
			run_benchmark("TBENCH_CONV_MX2EY",
				TBENCH, TBENCH_CYCLES, TBENCH_CONV_MX2EY);
		#endif
		#ifdef TBENCH_CONV_EY2WX
			run_benchmark("TBENCH_CONV_EY2WX",
				TBENCH, TBENCH_CYCLES, TBENCH_CONV_EY2WX);
		#endif
		#ifdef TBENCH_CONV_EY2MX
			run_benchmark("TBENCH_CONV_EY2MX",
				TBENCH, TBENCH_CYCLES, TBENCH_CONV_EY2MX);
		#endif
		#ifdef TBENCH_CONV_W2M
			run_benchmark("TBENCH_CONV_W2M",
				TBENCH, TBENCH_CYCLES, TBENCH_CONV_W2M);
		#endif
		#ifdef TBENCH_CONV_W2E
			run_benchmark("TBENCH_CONV_W2E",
				TBENCH, TBENCH_CYCLES, TBENCH_CONV_W2E);
		#endif
		#ifdef TBENCH_CONV_M2W
			run_benchmark("TBENCH_CONV_M2W",
				TBENCH, TBENCH_CYCLES, TBENCH_CONV_M2W);
		#endif
		#ifdef TBENCH_CONV_M2E
			run_benchmark("TBENCH_CONV_M2E",
				TBENCH, TBENCH_CYCLES, TBENCH_CONV_M2E);
		#endif
		#ifdef TBENCH_CONV_E2W
			run_benchmark("TBENCH_CONV_E2W",
				TBENCH, TBENCH_CYCLES, TBENCH_CONV_E2W);
		#endif
		#ifdef TBENCH_CONV_E2M
			run_benchmark("TBENCH_CONV_E2M",
				TBENCH, TBENCH_CYCLES, TBENCH_CONV_E2M);
		#endif
		#ifdef TBENCH_RECOVER_EX
			run_benchmark("TBENCH_RECOVER_EX",
				TBENCH, TBENCH_CYCLES, TBENCH_RECOVER_EX);
		#endif
		#ifdef TBENCH_RECOVER_MY
			run_benchmark("TBENCH_RECOVER_MY",
				TBENCH, TBENCH_CYCLES, TBENCH_RECOVER_MY);
		#endif
		#ifdef TBENCH_RECOVER_WY
			run_benchmark("TBENCH_RECOVER_WY",
				TBENCH, TBENCH_CYCLES, TBENCH_RECOVER_WY);
		#endif

		for(int i = 0; i < 20; i++) {
			sleep(100);
			LED0_TOGGLE;
		}
        LED0_OFF;

        xtimer_periodic_wakeup(&last_wakeup, ONE_SECOND);
		printf("\nEnd of a tbench cycle!\n\n");
    }
}