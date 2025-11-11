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
#include <linux/vmalloc.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>

#define PIDTAB_SIZE 65536
#define TASK_COMM_LEN 20                // TASK LEN < 20 needed. Otherwise kern panic.

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jerry Qi");
MODULE_DESCRIPTION("A Simple Kernel Module to track latency");
MODULE_VERSION("1.0");

static struct tracepoint *tp_sched_switch;
static struct tracepoint *tp_sched_wakeup;


struct task_latency_entry {
        u32 gen;        // How many times this pid has been reused
        bool active;    // Pid being tracked

        int pid;        // Current pid
        char comm[TASK_COMM_LEN];              // Task name

        s64 min_ns;     // Minimum latency
        s64 max_ns;     // Maximum latency

        s64 last_wakeup_ns;     // Timestamp of the sched_wake event
};

static struct task_latency_entry *pidtab;

static inline struct task_latency_entry *slot_for(pid_t pid)
{
        if (pid < 0 || pid >= PIDTAB_SIZE) {
                return NULL;
        } else {
                return &pidtab[pid];
        }
}

/*
Helper functions
TODO: change this to not spin, we showed that we don't race when updating for a single pid.
*/
static __always_inline void update_minmax(struct task_latency_entry *e, s64 v)
{
        if (READ_ONCE(e->max_ns) < v) {
                WRITE_ONCE(e->max_ns, v);
        }
        if (v < READ_ONCE(e->min_ns)) {
                WRITE_ONCE(e->min_ns, v);
        }
}

/*
Adding a pid to be recorded, and removing a pid to be recorded

TODO: potentialy doing value reset at the last part of removal.
*/
static int start_recording_pid(pid_t pid)
{
        struct task_latency_entry *e = slot_for(pid);
        if (!e) {
                return -EINVAL;
        }

        // Mark inactive first to allow us to reinitialize handlers
        WRITE_ONCE(e->active, false);

        // Reinit stats
        WRITE_ONCE(e->pid, pid);
        WRITE_ONCE(e->min_ns, LLONG_MAX);
        WRITE_ONCE(e->max_ns, 0);
        WRITE_ONCE(e->last_wakeup_ns, 0);

        // Set PID's name
        struct task_struct *p = pid_task(find_vpid(pid), PIDTYPE_PID);
        if (p) {
                get_task_comm(e->comm, p);
        } else {
                strncpy(e->comm, "<unknown>", TASK_COMM_LEN);
        }
        
        // Increment to show that this is not the original PID anymore.
        WRITE_ONCE(e->gen, READ_ONCE(e->gen) + 1);

        smp_wmb();
        WRITE_ONCE(e->active, true);
        return 0;
}


static void stop_recording_pid(pid_t pid)
{
        struct task_latency_entry *e = slot_for(pid);
        if (!e) {
                return;
        }

        WRITE_ONCE(e->active, false);
}


/*
Function that would be called whn sched_switched happens
*/
static void sched_switched_handler(void *data, bool preempt, struct task_struct *prev, struct task_struct *next, unsigned int prev_state)
{
        // Track latency statistics for the next task switched into 
        struct task_latency_entry *e = slot_for(next->pid);
        s64 wu, now;

        if (!e) {
                return;
        }
        if (!READ_ONCE(e->active)) {
                return;
        }
        if (READ_ONCE(e->pid) != next->pid) {
                return;
        }

        wu = xchg(&e->last_wakeup_ns, 0);
        if (wu == 0) {
                return;
        }
        now = ktime_get_ns();
        s64 delta = now - wu;
        update_minmax(e, delta);
}

/*
Function that would be called when sched_wakeup happens.
*/
static void sched_wakeup_handler(void *data, struct task_struct *p)
{
        struct task_latency_entry *e = slot_for(p->pid);
        // set the specific number for last latency
        if (!e) {
                return;
        }
        if (READ_ONCE(e->active) == false) {
                return;
        }
        if (READ_ONCE(e->pid) != p->pid) {
                return;
        }

        WRITE_ONCE(e->last_wakeup_ns, ktime_get_ns());
        // smp_store_release(&e->last_wakeup_ns, ktime_get_ns());
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
Kernel sysfs input handling
*/
static ssize_t add_pid_store(struct kobject *kobj, struct kobj_attribute *attr,
                                const char *buf, size_t count)
{
        pid_t pid;
        if (kstrtoint(buf, 10, &pid) == 0) {
                start_recording_pid(pid);
        }
        return count;
}

static ssize_t del_pid_store(struct kobject *kobj,
                             struct kobj_attribute *attr,
                             const char *buf, size_t count)
{
    pid_t pid;
    if (kstrtoint(buf, 10, &pid) == 0)
        stop_recording_pid(pid);
    return count;
}

static struct kobj_attribute add_pid_attr = __ATTR_WO(add_pid);
static struct kobj_attribute del_pid_attr = __ATTR_WO(del_pid);

static struct attribute *rt_attrs[] = {
        &add_pid_attr.attr,
        &del_pid_attr.attr,
        NULL,
};
ATTRIBUTE_GROUPS(rt);

static struct kobject *rt_kobj;

/*
init: initializes tracepoints and links handler functions to those tracepoints
*/
static int __init rt_module_init(void)
{
        // Allocate GFP_KERNEL in initialization
        pidtab = vzalloc(sizeof(struct task_latency_entry) * PIDTAB_SIZE);

        pr_info("jerry_rt_module: looking for tracepoints...\n");
        
        // kernel macro that just calls find_tp with each tracepoint it knows
        for_each_kernel_tracepoint(find_tp, NULL);

        if (!tp_sched_switch) {
                pr_err("jerry_rt_module: We don't have sched_switch. ftrace not loaded?");
                vfree(pidtab);
                return -ENOENT;
        }
        if (!tp_sched_wakeup) {
                pr_err("jerry_rt_module: We don't have sched_wakeup. ftrace not loaded?");
                vfree(pidtab);
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
                vfree(pidtab);
                return -EINVAL;
        }

        // Registering the attribute group
        rt_kobj = kobject_create_and_add("jerry_rt_module", kernel_kobj);
        if (!rt_kobj) {
                return -ENOMEM;
        }
        sysfs_create_groups(rt_kobj, rt_groups);
        
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

        if (pidtab) {
                for (int i = 0; i < PIDTAB_SIZE; i++) {
                        struct task_latency_entry *curr = slot_for(i);
                        if (READ_ONCE(curr->active) == true) {
                                pr_info(
                                        "jerry_rt_module: PID=%d, Name=%s, minLat=%lli, maxLat=%lli", 
                                        i, curr->comm, READ_ONCE(curr->min_ns), READ_ONCE(curr->max_ns)
                                );
                        }
                }
                vfree(pidtab);
        }

        sysfs_remove_groups(rt_kobj, rt_groups);
        kobject_put(rt_kobj);
}

module_init(rt_module_init);
module_exit(rt_module_exit);
