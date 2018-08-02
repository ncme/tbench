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
        LED0_ON;
        xtimer_periodic_wakeup(&last_wakeup, ONE_SECOND);
        LED0_OFF;

		if(RUN_BENCH)
			printf("IMPL %d (%03d iterations)\t\t     Last\tMean\t  Median      Min\t Max\n",
					TBENCH, TBENCH_CYCLES);
		else
			printf("No benchmarks loaded!");

		#ifdef TBENCH_P256
			run_benchmark("TBENCH_P256", TBENCH, TBENCH_CYCLES, TBENCH_P256);
		#endif
		#ifdef TBENCH_WEI25519
			run_benchmark("TBENCH_WEI25519", TBENCH, TBENCH_CYCLES, TBENCH_WEI25519);
		#endif
		#ifdef TBENCH_ED25519_TO_WEI25519
			run_benchmark("TBENCH_ED25519_TO_WEI25519",
				TBENCH, TBENCH_CYCLES, TBENCH_ED25519_TO_WEI25519);
		#endif
		#ifdef TBENCH_CURVE25519_TO_WEI25519
			run_benchmark("TBENCH_CURVE25519_TO_WEI25519",
				TBENCH, TBENCH_CYCLES, TBENCH_CURVE25519_TO_WEI25519);
		#endif
		#ifdef TBENCH_DH_X25519
			run_benchmark("TBENCH_DH_X25519 ",
				TBENCH, TBENCH_CYCLES, TBENCH_DH_X25519);
		#endif
		#ifdef TBENCH_DH_ED25519
			run_benchmark("TBENCH_DH_ED25519",
				TBENCH, TBENCH_CYCLES, TBENCH_DH_ED25519);
		#endif
		#ifdef TBENCH_DH_ED25519_TO_X25519
			run_benchmark("TBENCH_DH_ED_TO_MT",
				TBENCH, TBENCH_CYCLES, TBENCH_DH_ED25519_TO_X25519);
		#endif
		#ifdef TBENCH_DH_X25519_TO_ED25519
			run_benchmark("TBENCH_DH_MT_TO_ED",
				TBENCH, TBENCH_CYCLES, TBENCH_DH_X25519_TO_ED25519);
		#endif
		#ifdef TBENCH_DH_WEI25519_1_TO_X25519
			run_benchmark("TBENCH_DH_WEI_TO_MT",
				TBENCH, TBENCH_CYCLES, TBENCH_DH_WEI25519_1_TO_X25519);
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

		for(int i = 0; i < 20; i++) {
			sleep(100);
			LED0_TOGGLE;
		}
        LED0_OFF;

        xtimer_periodic_wakeup(&last_wakeup, ONE_SECOND);
		printf("\n\n");
    }
}