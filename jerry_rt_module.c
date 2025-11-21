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
#include <linux/interrupt.h>
#include <asm/unistd.h>

#define PIDTAB_SIZE 65536

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jerry Qi");
MODULE_DESCRIPTION("A Simple Kernel Module to track latency");
MODULE_VERSION("1.0");

static struct tracepoint *tp_sched_switch;
static struct tracepoint *tp_sched_wakeup;
static struct tracepoint *tp_sys_enter;
static struct tracepoint *tp_irq_thread_start_processing;
static struct tracepoint *tp_irq_thread_end_processing;

enum violation_field {
        LATENCY,
        RESPONSE,
        RESPONSE_RELIEF,
        IRQ_HANDLING
};


enum sleep_cause {
        SC_NONE = 0,
        SC_TIMER,
        SC_OTHER, // FUTURE: SC_LOCK, SC_IO, etc for other potential state tacking 
};

struct task_stat_slo {
        // For Latency
        s64 latency_bound;
        int latency_violations;
        // TODO: Could be interesting to have a average violation size.
        
        // For Response time voluntary sleep
        s64 response_bound;
        int response_violations;
        
        // Response time relief sleep
        s64 response_relief_bound;
        int response_relief_violations;
        
        // IRQ tracepoints
        s64 irq_handling_bound;
        int irq_handling_violations;
};

/*
TODO: check my space efficiency here.
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
        
        // IRQ handler (kernel patch) statistics
        s64 last_handler_call_entry;
        s64 interrupt_handler_max_ns;           // max single interrupt handling iteration in the loop
        s64 interrupt_handler_min_ns;
        
        // SLO implementation
        struct task_stat_slo v;
};

static void update_violation(enum violation_field field, s64 value, struct task_latency_entry *e);

#define DEFINE_SLO_SETTER(name, field) \
static void set_##name(pid_t pid, s64 value) { \
        struct task_latency_entry *e = slot_for(pid); \
        if (e) { \
                struct task_stat_slo *s = &e->v; \
                WRITE_ONCE(s->field, value); \
        } \
}


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
        WRITE_ONCE(e->last_handler_call_entry, 0);
        WRITE_ONCE(e->interrupt_handler_max_ns, 0);
        WRITE_ONCE(e->interrupt_handler_min_ns, LLONG_MAX);
        // SLO violation
        WRITE_ONCE(e->v.latency_bound, LLONG_MAX);
        WRITE_ONCE(e->v.latency_violations, 0);
        WRITE_ONCE(e->v.response_bound, LLONG_MAX);
        WRITE_ONCE(e->v.response_violations, 0);
        WRITE_ONCE(e->v.response_relief_bound, LLONG_MAX);
        WRITE_ONCE(e->v.response_relief_violations, 0);
        WRITE_ONCE(e->v.irq_handling_bound, LLONG_MAX);
        WRITE_ONCE(e->v.irq_handling_violations, 0);

        // Set PID's name
        struct task_struct *p = pid_task(find_vpid(pid), PIDTYPE_PID);
        if (p) {
                get_task_comm(e->comm, p);
        } else {
                strncpy(e->comm, "<unknown>", TASK_COMM_LEN);
        }
        
        // Increment to show that this is not the original PID anymore.
        WRITE_ONCE(e->gen, READ_ONCE(e->gen) + 1);

        smp_store_release(&e->active, true);
        return 0;
}


static void stop_recording_pid(pid_t pid)
{
        struct task_latency_entry *e = slot_for(pid);
        if (!e) {
                return;
        }

        // For visibility when the tracepoint is fired immediately after.
        smp_store_release(&e->active, false);
}


/*
Function that would be called whn sched_switched happens

Task is running 
*/
static void sched_switched_handler(void *data, bool preempt, struct task_struct *prev, struct task_struct *next, unsigned int prev_state)
{
        // Track latency statistics for the next task switched into 
        struct task_latency_entry *e = slot_for(next->pid);
        s64 wu, now;
        
        if (e && smp_load_acquire(&e->active)) {
                wu = xchg(&e->last_wakeup_ns, 0);
                if (wu != 0) {
                        now = ktime_get_ns();
                        s64 delta = now - wu;
                        update_minmax(e, delta);
                        update_violation((enum violation_field) LATENCY, delta, e);
                        
                        // Write down the last wake up time used (this is for response time)
                        WRITE_ONCE(e->curr_wu_ns, wu);
                }
        }

        struct task_latency_entry *p = slot_for(prev->pid);
        if (p && smp_load_acquire(&p->active)) {
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
                                update_violation((enum violation_field) RESPONSE, resp, p);
                        }

                        if (vol_sleep_cause == SC_TIMER && READ_ONCE(p->cycle_active)) {
                                s64 cs = xchg(&p->cycle_start_ns, 0);
                                if (cs) {
                                        s64 cycle = now - cs;
                                        if (cycle > READ_ONCE(p->resp_cycle_max_ns)) {
                                                WRITE_ONCE(p->resp_cycle_max_ns, cycle);
                                        }
                                        if (cycle < READ_ONCE(p->resp_cycle_min_ns)) {
                                                WRITE_ONCE(p->resp_cycle_min_ns, cycle);
                                        }
                                        update_violation((enum violation_field) RESPONSE_RELIEF, cycle, p);
                                }
                                WRITE_ONCE(p->cycle_active, false);
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
        if (smp_load_acquire(&e->active) == false) {
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
        if (!e || smp_load_acquire(&e->active) == false) {
                return;
        }

        WRITE_ONCE(e->scause, SC_TIMER);
}



/*
Handler for IRQ tracepoints.
*/
static void irq_handling_fn_entry_handler(void *data, int irq, struct irqaction *action)
{
        if (action != NULL) {
                struct task_struct *irq_thread = action->thread;
                pid_t pid = irq_thread->pid;
                struct task_latency_entry *e = slot_for(pid);
                
                if (e && smp_load_acquire(&e->active)) {
                        WRITE_ONCE(e->last_handler_call_entry, ktime_get_ns());
                }
        }
}

static void irq_handler_fn_exit_handler(void *data, int irq, struct irqaction *action)
{
        if (action != NULL) {
                struct task_struct *irq_thread = action->thread;
                if (irq_thread == 0) {
                        return;
                }
                pid_t pid = irq_thread->pid;
                struct task_latency_entry *e = slot_for(pid);
                
                if (e && smp_load_acquire(&e->active)) {
                        s64 le = xchg(&e->last_handler_call_entry, 0);
                        if (le != 0) {
                                s64 delta = ktime_get_ns() - le;
                                if (delta < READ_ONCE(e->interrupt_handler_min_ns)) {
                                        WRITE_ONCE(e->interrupt_handler_min_ns, delta);
                                }
                                if (delta > READ_ONCE(e->interrupt_handler_max_ns)) {
                                        WRITE_ONCE(e->interrupt_handler_max_ns, delta);
                                }
                                update_violation((enum violation_field) IRQ_HANDLING, delta, e);
                        }
                }
        }
}



/**
 * Function to update violation status for a particular field
 * @field is the specific metric that this value is applicable for
 * 
 * 
 */
static void update_violation(enum violation_field field, s64 value, struct task_latency_entry *e) {
        s64 bound;
        switch (field) {
                case LATENCY:
                        /**
                         * This value update was intended for latency
                         */
                        bound = READ_ONCE(e->v.latency_bound);
                        if (value > bound) {
                                WRITE_ONCE(e->v.latency_violations, READ_ONCE(e->v.latency_violations) + 1);
                        }
                case RESPONSE:
                        bound = READ_ONCE(e->v.response_bound);
                        if (value > bound) {
                                WRITE_ONCE(e->v.response_violations, READ_ONCE(e->v.response_violations) + 1);
                        }
                case RESPONSE_RELIEF:
                        bound = READ_ONCE(e->v.response_relief_bound);
                        if (value > bound) {
                                WRITE_ONCE(e->v.response_relief_violations, READ_ONCE(e->v.response_relief_violations) + 1);
                        }
                case IRQ_HANDLING:
                        bound = READ_ONCE(e->v.irq_handling_bound);
                        if (value > bound) {
                                WRITE_ONCE(e->v.irq_handling_violations, READ_ONCE(e->v.irq_handling_violations) + 1);
                        }
                default:
                        break;
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
        } else if (strcmp(tp->name, "sys_enter") == 0) {
                tp_sys_enter = tp;
        } else if (strcmp(tp->name, "irq_threaded_handler_entry") == 0) {
                tp_irq_thread_start_processing = tp;
        } else if (strcmp(tp->name, "irq_threaded_handler_exit") == 0) {
                tp_irq_thread_end_processing = tp;
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
        if (kstrtoint(buf, 10, &pid) == 0) {
                stop_recording_pid(pid);
        }
        return count;
}


DEFINE_SLO_SETTER(latency_bound, latency_bound);
DEFINE_SLO_SETTER(response_bound, response_bound);
DEFINE_SLO_SETTER(response_relief_bound, response_relief_bound);
DEFINE_SLO_SETTER(irq_handling_bound, irq_handling_bound);


/**
 * Helper function parse for two integers
 */
static int parse_two_ints(const char *buf, size_t count,
                          int *first, int *second)
{
        char tmp[64];
        char *space;
        int ret;
        size_t len;

        /* Clamp and copy, add '\0' */
        len = min(count, sizeof(tmp) - 1);
        memcpy(tmp, buf, len);
        tmp[len] = '\0';

        /* Find the space separator */
        space = strchr(tmp, ' ');
        if (!space) {
                return -EINVAL;
        }

        *space = '\0';           /* Split into two C strings */

        ret = kstrtoint(tmp, 10, first);
        if (ret)
                return ret;

        ret = kstrtoint(space + 1, 10, second);
        if (ret) {
                return ret;
        }

        return 0;
}

/**
 * kobj is just the sysfs object the attr is under
 * attr is the struct that contains the file name, permissions and pointers to store show functions
 * buf is the raw buffer of characters userspace wrote into the sysfs file
 * count is number of bytes written.
 * 
 * We expect echo "A B", where pid = A, bound = B 
 * This function would tell us the particular bound it is for.
 */
static ssize_t set_slo_latency_bound_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
        pid_t pid;
        int bound;

        parse_two_ints(buf, count, &pid, &bound);
        set_latency_bound(pid, bound);

        return count;
}


static ssize_t set_slo_response_bound_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
        pid_t pid;
        int bound;

        parse_two_ints(buf, count, &pid, &bound);
        set_response_bound(pid, bound);

        return count;
}

static ssize_t set_slo_response_relief_bound_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
        pid_t pid;
        int bound;

        parse_two_ints(buf, count, &pid, &bound);
        set_response_relief_bound(pid, bound);

        return count;
}

static ssize_t set_slo_irq_handling_bound_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
        pid_t pid;
        int bound;

        parse_two_ints(buf, count, &pid, &bound);
        set_irq_handling_bound(pid, bound);

        return count;
}




// static void set_latency_bound(pid_t pid, s64 bound) {
//         struct task_latency_entry *e = slot_for(pid);
//         if (e) {
//                 struct task_stat_slo *s = &e->v;
//                 WRITE_ONCE(s->latency_bound, bound);
//         }
// }







/**
 * _ATTR_WO macro expands into something like .attr = something, .store=add_pid_store, .show=add_pid_show. Since we register the attr, when that attr is written to, we'd call the function registered with store
 */
static struct kobj_attribute add_pid_attr = __ATTR_WO(add_pid);
static struct kobj_attribute del_pid_attr = __ATTR_WO(del_pid);
static struct kobj_attribute set_slo_latency_bound_attr = __ATTR_WO(set_slo_latency_bound);
static struct kobj_attribute set_slo_response_bound_attr = __ATTR_WO(set_slo_response_bound);
static struct kobj_attribute set_slo_response_relief_bound_attr = __ATTR_WO(set_slo_response_relief_bound);
static struct kobj_attribute set_slo_irq_handling_bound_attr = __ATTR_WO(set_slo_irq_handling_bound);

static struct attribute *rt_attrs[] = {
        &add_pid_attr.attr,
        &del_pid_attr.attr,
        &set_slo_latency_bound_attr.attr,
        &set_slo_response_bound_attr.attr,
        &set_slo_response_relief_bound_attr.attr,
        &set_slo_irq_handling_bound_attr.attr,
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
        if (!pidtab) {
                pr_err("jerry_rt_module: failed to allocate pidtab\n");
                return -ENOMEM;
        }

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
        if (!tp_sys_enter) {
                pr_err("jerry_rt_module: We don't have sys_enter tracepoint\n");
                vfree(pidtab);
                return -ENOENT;
        }
        if (!tp_irq_thread_start_processing) {
                pr_err("jerry_rt_module: We don't have tp_irq_thread_start_processing tracepoint\n");
                vfree(pidtab);
                return -ENOENT;
        }
        if (!tp_irq_thread_end_processing) {
                pr_err("jerry_rt_module: We don't have tp_irq_thread_end_processing tracepoint\n");
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

        if (tracepoint_probe_register(tp_irq_thread_start_processing, irq_handling_fn_entry_handler, NULL)) {
                pr_err("jerry_rt_module: Failed to register irq_threaded_handler_entry probe\n");
                tracepoint_probe_unregister(tp_sched_switch, sched_switched_handler, NULL);
                tracepoint_probe_unregister(tp_sched_wakeup, sched_wakeup_handler, NULL);
                tracepoint_probe_unregister(tp_sys_enter, sys_enter_handler, NULL);
                vfree(pidtab);
                return -EINVAL;
        }
        
        if (tracepoint_probe_register(tp_irq_thread_end_processing, irq_handler_fn_exit_handler, NULL)) {
                pr_err("jerry_rt_module: Failed to register irq_threaded_handler_entry probe\n");
                tracepoint_probe_unregister(tp_sched_switch, sched_switched_handler, NULL);
                tracepoint_probe_unregister(tp_sched_wakeup, sched_wakeup_handler, NULL);
                tracepoint_probe_unregister(tp_sys_enter, sys_enter_handler, NULL);
                tracepoint_probe_unregister(tp_irq_thread_start_processing, irq_handling_fn_entry_handler, NULL);
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
        if (tp_irq_thread_start_processing) {
                tracepoint_probe_unregister(tp_irq_thread_start_processing, irq_handling_fn_entry_handler, NULL);
        }
        if (tp_irq_thread_end_processing) {
                tracepoint_probe_unregister(tp_irq_thread_end_processing, irq_handler_fn_exit_handler, NULL);
        }

        // Wait so that probe function is not still running on other cores
        tracepoint_synchronize_unregister();

        if (pidtab) {
                for (int i = 0; i < PIDTAB_SIZE; i++) {
                        struct task_latency_entry *curr = slot_for(i);
                        if (smp_load_acquire(&curr->active) == true) {
                                if (strncmp(curr->comm, "irq/", 4) == 0) {
                                        pr_info("IRQ %s (PID=%d):\n", curr->comm, i);
                                        pr_info("  service_time_min/max (wake->first sleep): %lld / %lld ns\n", curr->resp_min_ns, curr->resp_max_ns);
                                        pr_info("  latency_min/max (wake->first run): %lld / %lld ns\n", curr->min_ns, curr->max_ns);
                                        pr_info("  per interrupt bottom half handling time (single iteration): %lld / %lld ns\n", curr->interrupt_handler_min_ns, curr->interrupt_handler_max_ns);

                                        struct task_stat_slo *v = &curr->v;
                                        if (v->latency_violations) {
                                                pr_info("  LatencyBound=%lld, Violations=%lld", v->latency_bound, v->latency_violations);
                                        }
                                }
                                else {
                                        pr_info(
                                                "jerry_rt_module: PID=%d, Name=%s, minLat=%lli, maxLat=%lli,\nminResponseTimeVoluntarySleepAllTypes=%lli, maxResponseTimeVoluntarySleepAllTypes=%lli, \nminResponseTimeVoluntarySleepReliefBased=%lli, maxResponseTimeVoluntarySleepReliefBased=%lli", 
                                                i, curr->comm, READ_ONCE(curr->min_ns), 
                                                READ_ONCE(curr->max_ns), 
                                                READ_ONCE(curr->resp_min_ns), READ_ONCE(curr->resp_max_ns), 
                                                READ_ONCE(curr->resp_cycle_min_ns), READ_ONCE(curr->resp_cycle_max_ns)
                                        );
                                }
                        }
                }
                vfree(pidtab);
        }

        sysfs_remove_groups(rt_kobj, rt_groups);
        kobject_put(rt_kobj);
}

module_init(rt_module_init);
module_exit(rt_module_exit);
