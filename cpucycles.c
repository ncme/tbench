#include "xtimer.h"
#include <stdint.h>

uint32_t cpucycles(void) {
    return xtimer_usec_from_ticks(xtimer_now());
}