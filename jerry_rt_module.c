#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/tracepoint.h>
#include <linux/sched.h>
#include <linux/ktime.h>
#include <linux/slab.h>
#include <linux/limits.h>
#include <linux/compiler.h>
#include <linux/string.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jerry Qi");
MODULE_DESCRIPTION("A Simple Kernel Module to track latency");
MODULE_VERSION("1.0");

/*
The pointer to the tracepoint.
This used to be a kernel symbol that is exported.
Newer kernels don't export this
TODO: Figure out why a tracepoint might be a pointer
*/
static struct tracepoint *tp_sched_switch;
static struct tracepoint *tp_sched_wakeup;


struct TaskLatency {
        s64 max;
        s64 min;
        int pid;
        s64 latest_wakeup;
};

struct TaskLatency *my_task;
static int target_pid = -1;
module_param(target_pid, int, 0444);

/*
Helper functions
*/
static void update_max(struct TaskLatency *task, s64 latency) {
        if (latency > task->max) {
                WRITE_ONCE(task->max, latency);
        }
}

static void update_min(struct TaskLatency *task, s64 latency) {
        if (latency < task->min) {
                WRITE_ONCE(task->min, latency);
        }
}

/*
Function that would be called whn sched_switched happens
*/
static void sched_switched_handler(void *data, bool preempt, struct task_struct *prev, struct task_struct *next, unsigned int prev_state)
{
    struct TaskLatency *t = READ_ONCE(my_task);
    if (!t || next->pid != t->pid) {
        return;
    }
    {
        s64 wu = xchg(&t->latest_wakeup, 0);
        if (wu != 0) {
                s64 now = ktime_get_ns();
                s64 delta = now - wu;
                update_min(t, delta);
                update_max(t, delta);
        }
    }
}

/*
Function that would be called when sched_wakeup happens.
*/
static void sched_wakeup_handler(void *data, struct task_struct *p)
{
        struct TaskLatency *t = READ_ONCE(my_task);
        if (t) {
                if (p->pid == t->pid) {
                        WRITE_ONCE(t->latest_wakeup, ktime_get_ns());
                }
        }
}

/*
Used to find the correct tracepoint that we want to hook onto
*/
static void find_tp(struct tracepoint *tp, void *priv)
{
        if (strcmp(tp->name, "sched_switch") == 0) {
                tp_sched_switch = tp;
        } else if (strcmp(tp->name, "sched_wakeup") == 0) {
                tp_sched_wakeup = tp;
        }
}


/*
init: initializes tracepoints and links handler functions to those tracepoints
*/
static int __init rt_module_init(void)
{
        if (target_pid < 0) {
                pr_err("jerry_rt_module: Set Module param target_pid=<pid\n");
                return -EINVAL;
        }

        // Allocate GFP_KERNEL in initialization
        my_task = kzalloc(sizeof(struct TaskLatency), GFP_KERNEL);
        if (!my_task)
                return -ENOMEM;
        my_task->pid = target_pid;
        my_task->min = LLONG_MAX;
        my_task->max = 0;
        my_task->latest_wakeup = 0;

        pr_info("jerry_rt_module: looking for tracepoints...\n");
        
        // kernel macro that just calls find_tp with each tracepoint it knows
        for_each_kernel_tracepoint(find_tp, NULL);

        if (!tp_sched_switch) {
                pr_err("jerry_rt_module: We don't have sched_switch. ftrace not loaded?");
                kfree(my_task);
                return -ENOENT;
        }
        if (!tp_sched_wakeup) {
                pr_err("jerry_rt_module: We don't have sched_wakeup. ftrace not loaded?");
                kfree(my_task);
                return -ENOENT;
        }

        pr_info("jerry_rt_module: Found sched_switch and sched_wakeup trace point");
        pr_info("jerry_rt_module: Registering the probe function for each event");

        if (tracepoint_probe_register(tp_sched_switch, sched_switched_handler, NULL)) {
                pr_err("jerry_rt_module: Failed to register probe\n");
                return -EINVAL;
        }

        if (tracepoint_probe_register(tp_sched_wakeup, sched_wakeup_handler, NULL)) {
                pr_err("jerry_rt_module: Failed to register probe for sched_wakeup\n");
                tracepoint_probe_unregister(tp_sched_switch, sched_switched_handler, NULL);
                kfree(my_task);
                return -EINVAL;
        }
        
        pr_info("jerry_rt_module: Success! sched_switch and sched_wakeup are both registered");
        return 0;
}


static void __exit rt_module_exit(void)
{
        // Unregister the schedule 
        if (tp_sched_switch) {
                // tell the thing to stop calling our function
                tracepoint_probe_unregister(tp_sched_switch, sched_switched_handler, NULL);
        }
        if (tp_sched_wakeup) {
                tracepoint_probe_unregister(tp_sched_wakeup, sched_wakeup_handler, NULL);
        }

        // Wait so that probe function is not still running on other cores
        tracepoint_synchronize_unregister();

        if (my_task) {
                pr_info("PID %d latency ns: min=%lld max=%lld\n", my_task->pid, my_task->min, my_task->max);
                kfree(my_task);
                my_task = NULL;
        }
}

module_init(rt_module_init);
module_exit(rt_module_exit);

