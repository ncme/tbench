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
/*
#define STACK_MARKER                (0x77777777)
void print_stack(void)
{
    int count = 0;
    uint32_t *sp = (uint32_t *)sched_active_thread->sp;
    do {
        sp++;
        count++;
    } while (*sp != STACK_MARKER);
    printf("current stack size: %i byte\n", count);
}
*/