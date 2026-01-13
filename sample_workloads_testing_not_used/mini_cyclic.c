#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <sched.h>

static volatile int keep_running = 1;

static void sigint_handler(int sig) {
    (void)sig;
    keep_running = 0;
}

/* Helper to get monotonic time in ns */
static inline uint64_t nsec_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

int main(int argc, char *argv[])
{
    struct timespec interval = {0, 1000000};   // 1 ms
    uint64_t next, now, delta, worst = 0, avg = 0;
    uint64_t iter = 0;
    cpu_set_t mask;

    /* Optionally pin to one CPU */
    CPU_ZERO(&mask);
    CPU_SET(0, &mask);
    sched_setaffinity(0, sizeof(mask), &mask);

    printf("mini_cyclic PID=%d interval=%ld ns\n",
           getpid(), (long)interval.tv_nsec);

    signal(SIGINT, sigint_handler);

    next = nsec_now();

    while (keep_running) {
        next += interval.tv_nsec;
        struct timespec ts = {
            .tv_sec  = next / 1000000000ULL,
            .tv_nsec = next % 1000000000ULL
        };

        clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, NULL);

        now = nsec_now();
        delta = (now > next) ? (now - next) : 0;

        if (delta > worst)
            worst = delta;
        avg += delta;
        iter++;

        if ((iter % 1000) == 0)
            printf("iter=%llu  avg=%llu ns  max=%llu ns\r",
                   (unsigned long long)iter,
                   (unsigned long long)(avg / iter),
                   (unsigned long long)worst);
    }

    printf("\nExiting. Ran %llu iterations.\n", (unsigned long long)iter);
    return 0;
}

