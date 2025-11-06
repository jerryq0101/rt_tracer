#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/tracepoint.h>
#include <linux/sched.h>
#include <linux/ktime.h>

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
        ktime_t latest_wakeup;
};

struct TaskLatency *my_task;

/*
Helper functions
*/
static void update_max(struct TaskLatency *task, s64 latency) {
        if (latency > task->max) {
                task->max = latency;
        }
}

static void update_min(struct TaskLatency *task, s64 latency) {
        if (latency < task->min) {
                task->min = latency;
        }
}

/*
Function that would be called whn sched_switched happens
*/
static void sched_switched_handler(void *data, bool preempt, unsigned int prev_state, struct task_struct *prev, struct task_struct *next)
{
        if (my_task) {
                // check if this switched is about my_task
                if (next->pid == my_task->pid) {
                        // our program is now running, therefore calculate latency
                        if (my_task->latest_wakeup) {
                                ktime_t schedule_time = ktime_get();
                                s64 delta_ns = ktime_to_ns(ktime_sub(schedule_time, my_task->latest_wakeup));
                                update_max(my_task, delta_ns);
                                update_min(my_task, delta_ns);
                        }
                }
        }
}

/*
Function that would be called when sched_wakeup happens.
Specific function prototypes exist of what each tracepoint can call (each supplying different information).
*/
static void sched_wakeup_handler(void *data, struct task_struct *p)
{
        if (my_task) {
                if (p->pid == my_task->pid) {
                        my_task->latest_wakeup = ktime_get();
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
        pr_info("jerry_rt_module: looking for tracepoints...\n");
        
        // kernel macro that just calls find_tp with each tracepoint it knows
        for_each_kernel_tracepoint(find_tp, NULL);

        if (!tp_sched_switch) {
                pr_err("jerry_rt_module: We don't have sched_switch. ftrace not loaded?");
                return -ENOENT;
        }
        if (!tp_sched_wakeup) {
                pr_err("jerry_rt_module: We don't have sched_wakeup. ftrace not loaded?");
        }

        pr_info("jerry_rt_module: Found sched_switch and sched_wakeup trace point");
        pr_info("jerry_rt_module: Registering the probe function for each event");

        if (tracepoint_probe_register(tp_sched_switch, sched_switched_handler, NULL)) {
                pr_err("jerry_rt_module: Failed to register probe\n");
                return -EINVAL;
        }

        if (tracepoint_probe_register(tp_sched_wakeup, sched_wakeup_handler, NULL)) {
                pr_err("jerry_rt_module: Failed to register probe for sched_wakeup\n");
                return -EINVAL;
        }
        
        pr_info("jerry_rt_module: Success! sched_switch and sched_wakeup are both registered");
        return 0;
}

static void __exit rt_module_exit(void)
{
        // If the tracepoint attached our function then
        if (tp_sched_switch) {
                // tell the thing to stop calling our function
                tracepoint_probe_unregister(tp_sched_switch, sched_switched_handler, NULL);
        }
        if (tp_sched_wakeup) {
                tracepoint_probe_unregister(tp_sched_wakeup, sched_wakeup_handler, NULL);
        }

        // Wait so that probe function is not still running on other cores
        tracepoint_synchronize_unregister();
}

module_init(rt_module_init);
module_exit(rt_module_exit);

