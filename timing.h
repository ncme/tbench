#include <stdint.h>

typedef uint32_t timer_result_t;

#ifdef TBENCH_COUNT_CYCLES
#define TBENCH_ARGS timer_result_t* _acycles, unsigned int _i
#define START_TBENCH timer_result_t _cycles = cpucycles();
#define FINISH_TBENCH _acycles[_i] = (timer_result_t) (cpucycles() - _cycles);
#endif
#ifdef TBENCH_COUNT_MICROS
#define TBENCH_ARGS timer_result_t* _amicros, unsigned int _i
#define START_TBENCH timer_result_t _micros = microseconds();
#define FINISH_TBENCH _amicros[_i] = (timer_result_t) (microseconds() - _micros);
#endif
#ifndef TBENCH_ARGS
#define TBENCH_ARGS timer_result_t* _amillis, unsigned int _i
#define START_TBENCH timer_result_t _millis = milliseconds();
#define FINISH_TBENCH _amillis[_i] = (timer_result_t) (milliseconds() - _millis);
#endif

timer_result_t cpucycles(void);
timer_result_t microseconds(void);
timer_result_t milliseconds(void);