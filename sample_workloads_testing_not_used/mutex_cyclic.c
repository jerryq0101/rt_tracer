#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <sched.h>
#include <pthread.h>

static volatile int keep_running = 1;
static pthread_mutex_t test_mutex = PTHREAD_MUTEX_INITIALIZER;

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

/* Worker thread: periodically holds the mutex so the RT thread blocks on it */
static void *lock_holder_thread(void *arg)
{
    (void)arg;
    while (keep_running) {
        /* Hold the mutex for ~5 ms, then release it */
        pthread_mutex_lock(&test_mutex);
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 5 * 1000 * 1000 }; // 5 ms
        nanosleep(&ts, NULL);
        pthread_mutex_unlock(&test_mutex);

        /* Sleep a bit before next hold */
        ts.tv_sec = 0;
        ts.tv_nsec = 5 * 1000 * 1000;
        nanosleep(&ts, NULL);
    }
    return NULL;
}

int main(int argc, char *argv[])
{
    struct timespec interval = {0, 1000000};   // 1 ms (1e6 ns)
    uint64_t next, now, delta, worst = 0, avg = 0;
    uint64_t iter = 0;
    cpu_set_t mask;
    pthread_t holder_tid;

    /* Optionally pin to one CPU */
    CPU_ZERO(&mask);
    CPU_SET(0, &mask);
    sched_setaffinity(0, sizeof(mask), &mask);

    printf("mixed_sleep PID=%d interval=%ld ns\n",
           getpid(), (long)interval.tv_nsec);

    signal(SIGINT, sigint_handler);

    /* Start the lock-holder thread */
    pthread_create(&holder_tid, NULL, lock_holder_thread, NULL);

    /* Initialize 'next' to now */
    next = nsec_now();

    while (keep_running) {
        next += interval.tv_nsec;
        struct timespec ts = {
            .tv_sec  = next / 1000000000ULL,
            .tv_nsec = next % 1000000000ULL
        };

        /* TIMER-BASED SLEEP: this should hit clock_nanosleep in kernel */
        clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, NULL);

        /* Occasionally try to take the mutex and potentially BLOCK on it */
        if ((iter % 500) == 0) {
            /* This may block if lock_holder_thread holds it:
             * kernel will sleep on a futex/rt_mutex, *not* on a timer.
             */
            pthread_mutex_lock(&test_mutex);
            /* Do something trivial while holding it */
            pthread_mutex_unlock(&test_mutex);
        }

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
    keep_running = 0;
    pthread_join(holder_tid, NULL);
    return 0;
}
