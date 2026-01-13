#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <sched.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>

static volatile int keep_running = 1;
static pthread_mutex_t test_mutex = PTHREAD_MUTEX_INITIALIZER;

static void sigint_handler(int sig) {
    (void)sig;
    keep_running = 0;
}

static inline uint64_t nsec_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

/* Low-priority lock holder */
static void *lock_holder_thread(void *arg)
{
    (void)arg;

    // Set SCHED_FIFO low priority
    struct sched_param sp = { .sched_priority = 20 };
    pthread_setschedparam(pthread_self(), SCHED_FIFO, &sp);

    while (keep_running) {
        pthread_mutex_lock(&test_mutex);
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 5 * 1000 * 1000 }; // 5 ms
        nanosleep(&ts, NULL);
        pthread_mutex_unlock(&test_mutex);

        ts.tv_sec = 0;
        ts.tv_nsec = 5 * 1000 * 1000;
        nanosleep(&ts, NULL);
    }
    return NULL;
}

/* Medium-priority CPU hog that never touches the mutex */
static void *hog_thread(void *arg)
{
    (void)arg;

    struct sched_param sp = { .sched_priority = 50 };
    pthread_setschedparam(pthread_self(), SCHED_FIFO, &sp);

    while (keep_running) {
        // Busy loop to hog CPU
        asm volatile("" ::: "memory");
    }
    return NULL;
}

int main(int argc, char *argv[])
{
    struct timespec interval = {0, 1000000};   // 1 ms
    uint64_t next, now, delta, worst = 0, avg = 0;
    uint64_t iter = 0;
    cpu_set_t mask;
    pthread_t holder_tid, hog_tid;

    /* Pin to CPU 0 */
    CPU_ZERO(&mask);
    CPU_SET(0, &mask);
    if (sched_setaffinity(0, sizeof(mask), &mask) != 0) {
        perror("sched_setaffinity");
    }

    /* Make main the highest-priority RT thread */
    struct sched_param sp = { .sched_priority = 80 };
    if (sched_setscheduler(0, SCHED_FIFO, &sp) != 0) {
        perror("sched_setscheduler (need root)");
    }

    printf("prio_inversion_demo PID=%d interval=%ld ns\n",
           getpid(), (long)interval.tv_nsec);

    signal(SIGINT, sigint_handler);

    /* Start low-priority lock holder */
    pthread_create(&holder_tid, NULL, lock_holder_thread, NULL);

    /* Start medium-priority CPU hog */
    pthread_create(&hog_tid, NULL, hog_thread, NULL);

    next = nsec_now();

    while (keep_running) {
        next += interval.tv_nsec;
        struct timespec ts = {
            .tv_sec  = next / 1000000000ULL,
            .tv_nsec = next % 1000000000ULL
        };

        // High-priority periodic sleep (relief)
        clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, NULL);

        // Occasionally try to take the mutex, potentially blocking on L
        if ((iter % 500) == 0) {
            pthread_mutex_lock(&test_mutex);
            // trivial work
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
    pthread_join(hog_tid, NULL);
    return 0;
}
