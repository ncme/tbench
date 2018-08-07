
#include <assert.h>
#include <stdio.h>
#include "timing.h"

static long mean(unsigned int m, timer_result_t a[])
{
    long long sum=0, i;
    for(i=0; i<m; i++)
        sum+=a[i];
    return((long)sum/m);
}


static long median(unsigned int n, timer_result_t x[])
{
    float temp;
    int i, j;
    for(i=0; i<n-1; i++) {
        for(j=i+1; j<n; j++) {
            if(x[j] < x[i]) {
                temp = x[i];
                x[i] = x[j];
                x[j] = temp;
            }
        }
    }
    if(n%2==0) {
        return (long) ((x[n/2] + x[n/2 - 1]) / 2.0);
    } else {
        return (long) x[n/2];
    }
}

static long min(timer_result_t array[], unsigned int size)
{
    assert(array != NULL);
    assert(size >= 0);

    if ((array == NULL) || (size <= 0))
       return -1;

    long val = 2147483647;
    for (int i = 0; i < size; i++)
        if (array[i] < val)
            val = (long) array[i];
    return val;
}

static long max(timer_result_t array[], unsigned int size)
{
    assert(array != NULL);
    assert(size >= 0);

    if ((array == NULL) || (size <= 0))
       return -1;

    long val = -2147483648;
    for (int i = 0; i < size; i++) {
        long cmp = (long) array[i];
        if (cmp > val)
            val = cmp;
    }
    return val;
}

static void print_results(const char* tbench_name, timer_result_t acycles[],
        const unsigned int cycle_count)
{
	printf("%-30s %10ld %10ld %10ld %10ld %10ld\n",
        tbench_name, acycles[cycle_count - 1],
        mean(cycle_count, acycles),
        median(cycle_count, acycles),
        min(acycles, cycle_count),
        max(acycles, cycle_count)
    );
}

int run_benchmark(const char* tbench_name, unsigned int implementation,
        const unsigned int cycle_count, int (*tbench_func)(TBENCH_ARGS))
{
	timer_result_t acycles[cycle_count]; unsigned int i;

	for(i = 0; i < cycle_count; i++) {
		if(!tbench_func(acycles, i)) {
            printf("Test %s failed! (IMPL %d)\n", tbench_name, implementation);
            return -1;
        }
	}
	print_results(tbench_name, acycles, cycle_count);
    return 0;
}
