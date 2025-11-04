/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2-Clause */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#ifndef EFA_PERF_TIMER_H
#define EFA_PERF_TIMER_H

#include <stdint.h>
#include <stdio.h>

/* Enable/disable performance timing - set to 1 to enable */
#define EFA_PERF_TIMING_ENABLED 0

#if EFA_PERF_TIMING_ENABLED

/* RDTSC inline function for x86_64 */
static inline uint64_t efa_rdtsc(void)
{
#if defined(__x86_64__) || defined(__i386__)
    uint32_t lo, hi;
    __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
    return ((uint64_t)hi << 32) | lo;
#elif defined(__aarch64__)
    uint64_t val;
    __asm__ __volatile__("mrs %0, cntvct_el0" : "=r" (val));
    return val;
#else
    /* Fallback for other architectures - use a simple counter */
    static uint64_t counter = 0;
    return ++counter;
#endif
}

#define WIN_SHIFT (13)  /* 8192 samples */
#define WIN_MASK ((1 << WIN_SHIFT) - 1)

/* Statistics tracking function with separate counters per operation */
static inline void efa_perf_timer_stats(uint64_t diff_cycles, const char *tag) {
    if (diff_cycles > 10000) {
        return;  /* Skip outliers */
    }
    
    if (tag[0] == 'S') {  /* SEND */
        static uint64_t send_total = 0;
        static uint32_t send_count = 0;
        static uint64_t send_max = 0, send_min = 0xFFFFFFFFFFFFFFFFULL;
        
        send_total += diff_cycles;
        send_count++;
        if (diff_cycles > send_max) send_max = diff_cycles;
        if (diff_cycles < send_min) send_min = diff_cycles;
        
        if ((send_count & WIN_MASK) == 0) {
            uint64_t avg = send_total >> WIN_SHIFT;
            printf("EFA %s Stats - %u samples: avg %lu cycles, min %lu, max %lu\n",
                   tag, send_count, avg, send_min, send_max);
            send_count = 0;
            send_total = send_max = 0;
            send_min = 0xFFFFFFFFFFFFFFFFULL;
        }
    } else if (tag[0] == 'W' && tag[1] == 'R') {  /* WRITE */
        static uint64_t write_total = 0;
        static uint32_t write_count = 0;
        static uint64_t write_max = 0, write_min = 0xFFFFFFFFFFFFFFFFULL;
        
        write_total += diff_cycles;
        write_count++;
        if (diff_cycles > write_max) write_max = diff_cycles;
        if (diff_cycles < write_min) write_min = diff_cycles;
        
        if ((write_count & WIN_MASK) == 0) {
            uint64_t avg = write_total >> WIN_SHIFT;
            printf("EFA %s Stats - %u samples: avg %lu cycles, min %lu, max %lu\n",
                   tag, write_count, avg, write_min, write_max);
            write_count = 0;
            write_total = write_max = 0;
            write_min = 0xFFFFFFFFFFFFFFFFULL;
        }
    } else {  /* WQE_COPY */
        static uint64_t wqe_total = 0;
        static uint32_t wqe_count = 0;
        static uint64_t wqe_max = 0, wqe_min = 0xFFFFFFFFFFFFFFFFULL;
        
        wqe_total += diff_cycles;
        wqe_count++;
        if (diff_cycles > wqe_max) wqe_max = diff_cycles;
        if (diff_cycles < wqe_min) wqe_min = diff_cycles;
        
        if ((wqe_count & WIN_MASK) == 0) {
            uint64_t avg = wqe_total >> WIN_SHIFT;
            printf("EFA %s Stats - %u samples: avg %lu cycles, min %lu, max %lu\n",
                   tag, wqe_count, avg, wqe_min, wqe_max);
            wqe_count = 0;
            wqe_total = wqe_max = 0;
            wqe_min = 0xFFFFFFFFFFFFFFFFULL;
        }
    }
}

/* Performance timing structure */
struct efa_perf_timer {
    uint64_t start_cycles;
    uint64_t end_cycles;
    const char *operation_name;
};

/* Start timing */
#define EFA_PERF_TIMER_START(timer, op_name) \
    do { \
        (timer)->operation_name = (op_name); \
        (timer)->start_cycles = efa_rdtsc(); \
    } while (0)

/* End timing and optionally print result */
#define EFA_PERF_TIMER_END(timer) \
    do { \
        (timer)->end_cycles = efa_rdtsc(); \
    } while (0)

/* Calculate elapsed cycles */
#define EFA_PERF_TIMER_CYCLES(timer) \
    ((timer)->end_cycles - (timer)->start_cycles)

/* Print timing result with statistics */
#define EFA_PERF_TIMER_PRINT(timer, tag) \
    do { \
        uint64_t cycles = EFA_PERF_TIMER_CYCLES(timer); \
        efa_perf_timer_stats(cycles, tag); \
    } while (0)

/* Print timing result with context and statistics */
#define EFA_PERF_TIMER_PRINT_CTX(timer, ctx) \
    do { \
        uint64_t cycles = EFA_PERF_TIMER_CYCLES(timer); \
        efa_perf_timer_stats(cycles, (timer)->operation_name); \
    } while (0)

#define EFA_PERF_TIMER_DECLARE(timer) struct efa_perf_timer timer

#else /* EFA_PERF_TIMING_ENABLED */

/* No-op macros when timing is disabled */
struct efa_perf_timer { int dummy; };
#define EFA_PERF_TIMER_DECLARE(timer) do { } while (0)
#define EFA_PERF_TIMER_START(timer, op_name) do { } while (0)
#define EFA_PERF_TIMER_END(timer) do { } while (0)
#define EFA_PERF_TIMER_CYCLES(timer) (0)
#define EFA_PERF_TIMER_PRINT(timer, tag) do { } while (0)
#define EFA_PERF_TIMER_PRINT_CTX(timer, ctx) do { } while (0)

#endif /* EFA_PERF_TIMING_ENABLED */

#endif /* EFA_PERF_TIMER_H */