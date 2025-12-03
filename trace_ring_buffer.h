#ifndef SLO_EVENTS_H
#define SLO_EVENTS_H

#include <linux/kfifo.h>
#include <linux/sched.h>
#include <linux/types.h>

// Global ring buffer
#define QUEUE_LEN 16384

// Understand what prev_state is
struct sched_switch_info {
        char name[TASK_COMM_LEN];
        bool preempt;
        unsigned int prev_state;
        int on_cpu;
        int recent_used_cpu;
        int wake_cpu;

        // General knowledge about the task
        int prio;
        int static_prio;
        int normal_prio;
        unsigned int rt_priority;
};

struct sched_wakeup_info {
        char name[TASK_COMM_LEN];
        int wake_cpu;
        int recent_used_cpu;

        // General knowledge about the Task
        int prio;
        int static_prio;
        int normal_prio;
        unsigned int rt_priority;
};

struct sys_sleep_info {
        // TODO: this name could be replaced with a pid
        char name[TASK_COMM_LEN];
};

enum event_type {
        SCHED_SWITCH,
        SCHED_WAKEUP,
        SYS_SLEEP
};

struct slo_event {
        enum event_type type;
        union {
                struct sched_switch_info;
                struct sched_wakeup_info;
                struct sys_sleep_info;
        };
};

/*
Functions that are needed 
*/
int slo_queue_init(void);
void slo_queue_exit(void);

int slo_queue_push(const struct slo_event *ev);
int slo_queue_pop(struct slo_event *ev);

bool slo_queue_empty(void);
bool slo_queue_full(void);

#endif
