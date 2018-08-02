/* tbench configuration */

#define TBENCH_CYCLES 16

/* tbench supported benchmarks */

#define TWEETNACL 	1
#define C25519 		2
#define TINYDTLS 	3
#define NANOECC		4
#define REF10		5
#define RELIC		6

#define RUN_BENCH 1

#if TBENCH == TWEETNACL
	#include "tbench_tweetnacl.h"
#elif TBENCH == C25519
	#include "tbench_c25519.h"
#elif TBENCH == TINYDTLS
	#include "tbench_tinyDTLS.h"
#elif TBENCH == NANOECC
	#include "tbench_nanoecc.h"
#elif TBENCH == REF10
	#include "tbench_ref10.h"
#elif TBENCH == RELIC
	#include "tbench_relic.h"
#else
	#undef RUN_BENCH
	#define RUN_BENCH 0
#endif

/* tbench functions */

int run_benchmark(const char* tbench_name, unsigned int implementation,
        const unsigned int cycle_count, int (*tbench_func)(long*, int));