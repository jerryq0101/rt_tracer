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
#include <asm/unistd.h>

#define PIDTAB_SIZE 65536
#define TASK_COMM_LEN 20                // TASK LEN < 20 needed. Otherwise kern panic.

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jerry Qi");
MODULE_DESCRIPTION("A Simple Kernel Module to track latency");
MODULE_VERSION("1.0");

static struct tracepoint *tp_sched_switch;
static struct tracepoint *tp_sched_wakeup;
static struct tracepoint *tp_sys_enter;

enum sleep_cause {
        SC_NONE = 0,
        SC_TIMER,
        SC_OTHER, // FUTURE: SC_LOCK, SC_IO, etc. But its ok for now.
};


/*
TODO: check my space efficiency here. This is a lot more than 2MB 
*/
struct task_latency_entry {
        u32 gen;                                // How many times this pid has been reused
        bool active;                            // Pid being tracked
        int pid;                                // Current pid
        char comm[TASK_COMM_LEN];               // Task name

        s64 min_ns;                             // Minimum latency
        s64 max_ns;                             // Maximum latency
        s64 last_wakeup_ns;                     // Timestamp of the sched_wake event

        // Response time measurement - voluntary sleep
        // Def'n = latest sleep (because of any reason) - latest wake up
        s64 curr_wu_ns;                         // Wake used by this activation (copied at switch in)
        s64 resp_min_ns;
        s64 resp_max_ns;

        // Specific Response time tracking
        // Defn of response time = time_"relief-ed"_from_its_duty - time_awaken
        enum sleep_cause scause;                // cause of next sleep
        enum sleep_cause last_sleep_cause;      // last sleep cause needed because need to know if we came back from HW or lock, or we had a relief and this is a new cycle
        // s64 sleep_start_ns;                     // When we switched out (potentially useful? for later states?)
        s64 cycle_start_ns;                     // When the control loop iteration started
        bool cycle_active;

        s64 resp_cycle_max_ns;                  // Max response time
        s64 resp_cycle_min_ns;                  // Min Response time
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

TODO: PID struct initialization changes for the new FSM stuff
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
        WRITE_ONCE(e->curr_wu_ns, 0);
        WRITE_ONCE(e->resp_min_ns, LLONG_MAX);
        WRITE_ONCE(e->resp_max_ns, 0);
        WRITE_ONCE(e->scause, SC_NONE);
        WRITE_ONCE(e->last_sleep_cause, SC_NONE);
        WRITE_ONCE(e->cycle_start_ns, 0);
        WRITE_ONCE(e->cycle_active, false);
        WRITE_ONCE(e->resp_cycle_max_ns, 0);
        WRITE_ONCE(e->resp_cycle_min_ns, LLONG_MAX);

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

Task is running 
*/
static void sched_switched_handler(void *data, bool preempt, struct task_struct *prev, struct task_struct *next, unsigned int prev_state)
{
        // Track latency statistics for the next task switched into 
        struct task_latency_entry *e = slot_for(next->pid);
        // Need to now also consider the previous task because it is getting switched out
        s64 wu, now;
        
        if (!e) {
                return;
        }
        
        if (READ_ONCE(e->active)) {
                wu = xchg(&e->last_wakeup_ns, 0);
                if (wu != 0) {
                        now = ktime_get_ns();
                        s64 delta = now - wu;
                        update_minmax(e, delta);
                        
                        // Write down the last wake up time used 
                        WRITE_ONCE(e->curr_wu_ns, wu);
                }
        }

        struct task_latency_entry *p = slot_for(prev->pid);
        // Check for response time (p ends running)
        if (p && READ_ONCE(p->active)) {
                // Indicates a voluntary exit
                bool voluntary = prev_state & (TASK_INTERRUPTIBLE | TASK_UNINTERRUPTIBLE | TASK_PARKED | TASK_IDLE | TASK_DEAD);
                
                if (voluntary) {
                        s64 now = ktime_get_ns();
                        enum sleep_cause vol_sleep_cause = READ_ONCE(p->scause);
                        if (vol_sleep_cause == SC_NONE) {
                                vol_sleep_cause = SC_OTHER;
                        }
                        WRITE_ONCE(p->last_sleep_cause, vol_sleep_cause);
                        WRITE_ONCE(p->scause, SC_NONE);

                        s64 wu = xchg(&p->curr_wu_ns, 0);

                        // Record the the voluntary sleep (any type)
                        if (wu) {
                                s64 resp = now - wu;
                                if (resp > p->resp_max_ns) {
                                        WRITE_ONCE(p->resp_max_ns, resp);
                                }
                                if (resp < p->resp_min_ns) {
                                        WRITE_ONCE(p->resp_min_ns, resp);
                                }
                        }

                        if (vol_sleep_cause == SC_TIMER && READ_ONCE(p->cycle_active)) {
                                s64 cs = READ_ONCE(p->cycle_start_ns);
                                if (cs) {
                                        s64 cycle = now - cs;
                                        if (cycle > READ_ONCE(p->resp_cycle_max_ns)) {
                                                WRITE_ONCE(p->resp_cycle_max_ns, cycle);
                                        }
                                        if (cycle < READ_ONCE(p->resp_cycle_min_ns)) {
                                                WRITE_ONCE(p->resp_cycle_min_ns, cycle);
                                        }
                                }
                                WRITE_ONCE(p->cycle_active, false);
                                WRITE_ONCE(p->cycle_start_ns, 0);
                        }
                }
        }
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

        s64 now = ktime_get_ns();
        WRITE_ONCE(e->last_wakeup_ns, now);

        // Validate this assumption later
        if (READ_ONCE(e->last_sleep_cause) == SC_TIMER) {
                WRITE_ONCE(e->cycle_active, true);
                WRITE_ONCE(e->cycle_start_ns, now);
        }
}



static __always_inline bool is_timer_sleep_syscall(long id)
{
        #ifdef __NR_nanosleep
                if (id == __NR_nanosleep)
                        return true;
        #endif
        #ifdef __NR_nanosleep_time64
                if (id == __NR_nanosleep_time64)
                        return true;
        #endif
        #ifdef __NR_clock_nanosleep
                if (id == __NR_clock_nanosleep)
                        return true;
        #endif
        #ifdef __NR_clock_nanosleep_time64
                if (id == __NR_clock_nanosleep_time64)
                        return true;
        #endif
                return false;
}

/*
Handler for all syscalls. However only checking for if its a sleep syscall here.
The "sys enter" handler will only handle sleeps
*/
static void sys_enter_handler(void *data, struct pt_regs *regs, long id)
{
        if (!is_timer_sleep_syscall(id)) {
                return;
        }
        struct task_latency_entry *e = slot_for(current->pid);
        if (!e || !READ_ONCE(e->active)) {
                return;
        }

        WRITE_ONCE(e->scause, SC_TIMER);
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
        } else if (strcmp(tp->name, "sys_enter") == 0) {
                tp_sys_enter = tp;
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

        if (tracepoint_probe_register(tp_sys_enter, sys_enter_handler, NULL)) {
                pr_err("jerry_rt_module: Failed to register sys_enter probe\n");
                tracepoint_probe_unregister(tp_sched_switch, sched_switched_handler, NULL);
                tracepoint_probe_unregister(tp_sched_wakeup, sched_wakeup_handler, NULL);
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
        if (tp_sys_enter) {
                tracepoint_probe_unregister(tp_sys_enter, sys_enter_handler, NULL);
        }

        // Wait so that probe function is not still running on other cores
        tracepoint_synchronize_unregister();

        if (pidtab) {
                for (int i = 0; i < PIDTAB_SIZE; i++) {
                        struct task_latency_entry *curr = slot_for(i);
                        if (READ_ONCE(curr->active) == true) {
                                pr_info(
                                        "jerry_rt_module: PID=%d, Name=%s, minLat=%lli, maxLat=%lli,\nminResponseTimeVoluntarySleepAllTypes=%lli, maxResponseTimeVoluntarySleepAllTypes=%lli, \nminResponseTimeVoluntarySleepReliefBased=%lli, maxResponseTimeVoluntarySleepReliefBased=%lli", 
                                        i, curr->comm, READ_ONCE(curr->min_ns), 
                                        READ_ONCE(curr->max_ns), 
                                        READ_ONCE(curr->resp_min_ns), READ_ONCE(curr->resp_max_ns), 
                                        READ_ONCE(curr->resp_cycle_min_ns), READ_ONCE(curr->resp_cycle_max_ns)
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
