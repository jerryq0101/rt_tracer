#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/tracepoint.h>
#include <linux/sched.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jerry Qi");
MODULE_DESCRIPTION("A Simple Kernel Module");
MODULE_VERSION("1.0");

/*
The pointer to the tracepoint.
This used to be a kernel symbol that is exported.
Newer kernels don't export this
TODO: Figure out why a tracepoint might be a pointer
*/
static struct tracepoint *tp_sched_switch;

/*
This is the function that will be called once a tracepoint is triggered
*/
static void probe_test(void *data, bool preempt, struct task_struct *prev, struct task_struct *next)
{
        static atomic_t count = ATOMIC_INIT(0);

        if (atomic_inc_return(&count) % 10000 == 0) {
                pr_info("jerry_rt_module: Switch from %s to %s\n", prev->comm, next->comm);
        }
}

/*
Used to find the correct tracepoint that we want to hook onto
*/
static void find_tp(struct tracepoint *tp, void *priv)
{
        if (strcmp(tp->name, "sched_switch") == 0) {
                tp_sched_switch = tp;
        }
}



static int __init rt_module_init(void)
{
        pr_info("jerry_rt_module: looking for tracepoints...\n");
        
        // kernel macro that just calls find_tp with each tracepoint it knows
        for_each_kernel_tracepoint(find_tp, NULL);

        if (!tp_sched_switch) {
                pr_err("We don't have sched_switch. ftrace not loaded?");
                return -ENOENT;
        }

        pr_info("jerry_rt_module: Found sched_switch trace point");
        pr_info("jerry_rt_module: Registering the probe function");

        if (tracepoint_probe_register(tp_sched_switch, probe_test, NULL)) {
                pr_err("jerry_rt_module: Failed to register probe\n");
                return -EINVAL;
        }
        
        pr_info("jerry_rt_module: Success! look at the dmesg for switch events");
        return 0;
}

static void __exit rt_module_exit(void)
{
        // If the tracepoint attached our function then
        if (tp_sched_switch) {
                // tell the thing to stop calling our function
                tracepoint_probe_unregister(tp_sched_switch, probe_test, NULL);
                // Wait so that probe function is not still running on other cores
                tracepoint_synchronize_unregister();
        }
}

module_init(rt_module_init);
module_exit(rt_module_exit);

