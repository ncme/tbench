#include "xtimer.h"
#include <stdint.h>
#include "timing.h"

timer_result_t cpucycles(void) {
    return xtimer_now().ticks32;
}

timer_result_t microseconds(void) {
    return xtimer_usec_from_ticks(xtimer_now());
}

timer_result_t milliseconds(void) {
    return xtimer_usec_from_ticks(xtimer_now()) / 1000;
}