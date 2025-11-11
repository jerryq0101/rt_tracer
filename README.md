# Project - RT

The vision of this tool is to allow people to run this on an existing Linux system that cares about real time execution, and see <b>quickly</b> if the system is in a healthy real time state.

A healthy real time state means that the intended important tasks are being addressed (low latency) and also finished (responded to) on time.

This is (hopefully) helpful for applications that are time critical. For example rockets that need a motor turned in a particular moment. Verifying that latency is low allows one to know the task is being gotten to in a short time. Verifying that response time is low allows one to know that the task is being finished in a short time.

The core point of this application is specific to verifying scheduling / RT qualities in a quicker manner than browsing the entire trace-cmd or kernelshark logs (which is a lot).

## The first part - Latency

To begin, I made a kernel module to track latency for a particular time period. 

This is a draft to describe the mechanism of how the initial module works. This doesn't need to be polished right now 11/10/25.

To begin, I subscribe particular tracepoints to sched_wakeup and sched_running. 

sched_wakeup: is the particular point where a process switches state to ready.

sched_running: is precisely the moment before a process is context switched to on a specific core.

The definition of latency that I am trackin here is sched_running - sched_wakeup.
- This tracks precisely the decision making of the scheduler and interaction with other tasks. 
- This would not track factors such as time when hardware sends the interrupt to the 

I use ftrace's tracepoints:
- they are in pointer form, so I find it using for_each_kernel_tracepoint 
- then register my custom handler functions to the wakeup and the sched_switch points
- effectively, the tracepoints are a subscription of events where they would do a call back for my function.

The functions that they would call back at are shced_wakeup_handler and sched_switched_handler.

TLDR: 
1. Registering tracepoints at each sched_wakeup and sched_switch. 
2. We have a pid table.
3. If the particular pid wakes up, we record its wakeup time. 
4. If a particular pid gets switched to we calculate its latency using the last wakeup time.

Expectation: a pid wakes up - record, ... scheduler does its thing ..., some scheduler decides to pick the pid and schedule it - record. This pair of data forms the min/max.


Full process: 
1. Hardware interrupt happens
2. CPU gets that signal
3. It schedules an IRQ thread to handle this particular hardware interrupt (max priority). - (IRQ threads are specific to PREEMPT_RT systems)
4. The IRQ thread  will call a device specific handler. If a process was sleeping and waiting for that task, then the handler would go onto the wait queue, and would mark that process to be ready. (AT THIS POINT, WAKEUP TRACEPOINT FIRES)
5. The IRQ Thread would then call the scheduler.
6. (Same core scheduler) Scheduler would make a decision to schedule a task (PREEMPT_RT: the highest priority one)
7. Before the scheduler calls context switch to a task, sched_switched fires.

### Recording

Core stat recorded. sched_wakeup handler will continously record the latest wakeup time. sched_switched handler will record the time and subtract the latest wake up time from it, and collect one instance of latency. 

### Thoughts on races

We want to make sure that the data we are collecting is valid. 

This requires ensuring that there is mutual exclusion for the pidtab array at a particular pid. In other words, A can't access pidtab[30] at the same time as B, where A and B are different threads.

Given we are running on Pi 4 which has 4 CPU cores, an IRQ thread could run at the same time as another IRQ thread. A context switch could happen at the same time as on another core.

Assumption: The hardware will send one interrupt at a particular time
==> CPU will acknowledge it and create one new IRQ handler thread
==> The single IRQ handler thread will get scheduled on a single core
==> Therefore there will only be one wakeup for a particular pid at a time.

Assumption: At a particular time only one task can be switched to
==> one core would take that task off the run queue and make it unavailable for others
==> one sched_switched event
==> one call to update_minmax(this task)
==> Two sequential updates to this task's min max variable only at a single time.

Therefore, for a unique pid, latest_wakeup_ns updates will not race.

For a unique pid, min or max updates will not race. 

For a single pid, we know that it cannot be in two transition states at once. In particular, being woken, and being switched to at the same time. Therefore, the modification of last_wakeup_ns and read of last_wakeup_ns at the same time is not possible.

Therefore, no concurrent modification of a single task_latency_entry can occur.

### Notes Sched Switched Handler

Takes the latest_wakeup value and consumes it. By setting it to 0 atomically using xchg, we prevent double consumption situations from happening.

### Notes Sched Wakeup Handler

Just sets a last_wakeup_ns value. 

There could be multiple wakeups that come before a sched_switch event. We will set last_wakeup_ns everytime. 

Therefore, latency = running - last_wakeup_time


### On sched_wakeup and sched_switched being on different cores

Say the task being woken up right now is Task A.

IRQ thread might start on Core 1. sched_wakeup for task A would come from Core 1. Scheduler will also be called on the same Core 1 in that IRQ thread.

Say Core 1 scheduler doesn't take task A from run queue.

In another core 3 in a later time, the scheduler could be called and if task A is the highest priority out of run queue, then it can context switch to task A. So there could be a pair of sched_wakeup and sched_switch handlers that are run on different cores.

### On Coherence and Consistency

About cache coherence and consistency. The question of when a core calling sched_switch handler, will it see the updated last_wakeup_ns?

The most that we can do as programmers is to ensure that there aren't any thread level races for a single pid. We can't verify that if wake on core 1 happens before switch on core 2, that we will for sure see that on core 2, that is the hardware's job to sync. 

smp_wmb() in start_recording_pid(pid) does a semi-consistency guarantee. It ensures that before the WRITE to active=true, the other CPUs have seen all the previous setup happen while active = false. Therefore if we see active=true, and then pid's struct must have been setup already. Therefore we won't ever be writing to a unsetup pid struct.

Potentialy smp consistency enforcement applies to other cases I didn't consider yet...

READ_ONCE/WRITE_ONCE is making sure that the compiler doesn't do any funny reordering (e.g. partial word writes or reads). 

Remark that the CPU will do reordering of instructions, but it will ensure that dependencies and hazards get resolved.

### Current model 

We add and delete pids that are being tracked.

We use sysfs to allow for the kernel module to receive inputs using a file. Echoing to one of the files in the directory allows us to call a function to add a pid to tracked.


