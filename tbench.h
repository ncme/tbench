#include "timing.h"

/* tbench configuration */

#define TBENCH_CYCLES 16

/* tbench supported benchmarks */

#define TWEETNACL 	1
#define C25519 		2
#define TINYDTLS 	3
#define NANOECC		4
#define REF10		5
#define MJ32		6
#define RELIC		7

#define RUN_BENCH 1

#if TBENCH == TWEETNACL
	#include "tbench_tweetnacl.h"
	#define IMPL "tweetnacl"
#elif TBENCH == C25519
	//#include "tbench_c25519.h"
	#include "tbench_morph25519.h"
	#define IMPL "C25519"
#elif TBENCH == TINYDTLS
	#include "tbench_tinyDTLS.h"
	#define IMPL "tinyDTLS"
#elif TBENCH == NANOECC
	#include "tbench_nanoecc.h"
	#define IMPL "nano-ecc"
#elif TBENCH == REF10
	#include "tbench_ref10.h"
	#define IMPL "ref10 (NaCl)"
#elif TBENCH == MJ32
	#include "tbench_mj32.h"
	#define IMPL "mj32 (ref)"
#elif TBENCH == RELIC
	#include "tbench_relic.h"
	#define IMPL "Relic"
#else
	#undef RUN_BENCH
	#define RUN_BENCH 0
#endif
#ifndef IMPL
	#define IMPL "None"
#endif

/* tbench functions */

int run_benchmark(const char* tbench_name, unsigned int implementation,
        const unsigned int cycle_count, int (*tbench_func)(TBENCH_ARGS));