# Project - RT

The vision of this tool is to allow people to run this on an existing Linux system that cares about real time execution, and see <b>quickly</b> if the system is in a healthy real time state.

A healthy real time state means that the intended important tasks are being addressed (low latency) and also finished (responded to) on time.

This is (hopefully) helpful for applications that are time critical. For example rockets that need a motor turned in a particular moment. Verifying that latency is low allows one to know the task is being gotten to in a short time. Verifying that response time is low allows one to know that the task is being finished in a short time.

The core point of this application is specific to verifying scheduling / RT qualities in a quicker manner than browsing the entire trace-cmd or kernelshark logs (which is a lot). Or, if there is a particular oddity, we can quickly pin point which process is the root of the issue.

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
7. Before the scheduler calls context switch to a task, sched_switched fires, and we record that tracepoint.

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

### Current UX model 

We add and delete pids that are being tracked.

We use sysfs to allow for the kernel module to receive inputs using a file. Echoing to one of the files in the directory allows us to call a function to add a pid to tracked.

## The second part - response time

There are some changes to previous expectations.

### Updated World View

It turns out the control loop did not behave as expected in industry: "A good control loop would (barely) block."

However, this doesn't make any difference to us because we both track wake -> rest voluntary sleep, wake -> first voluntary sleep. So following those industry assumptions, we would have first voluntary sleep = rest voluntary sleep. 
- It is still helpful because there could be bad programming and this is not the case
- It is still helpful because there could be other background tasks that are also structured like this.

Control loops would not directly read from devices. A good control loop would depend on IRQs to ingest data. IRQs would be at a higher priority priority than the control loop. 

Hardware interrupt -> higher priority IRQ thread services the hardware -> IRQ thread places data in some shared buffer and finishes -> control loop (lower priority) would read from the buffer.

Conclusions from this:
1. IRQ threads should be tracked because they are handling data (I go into what they should be tracked for below response time tracking)
2. (The control loop would barely block one mentioned above)

### The Response time model 

Response time = time for "relief" sleep - time woken up

Response time = time for first voluntary sleep - time woken up 

Initially when designing response time metric, I didn't account for the fact that a task may sleep. In order to account for this, I decided to split them into two metrics, a "relief" sleep metric, and a metric from wake until the first sleep.

A control loop is assumed to have a relief sleep at the end. This is because if a control loop doesn't have a relief sleep it would be looping in an undefined frequency determined randomly by the hardware itself. Put a relief sleep (even if super short) to have a definition of frequency for the control loop.

Despite the updated world model, I believe that tracking both is still useful. As mentioned above: it's good when control loop actually blocks, and it's good for other user level tasks that do potentially block.

### Implementation of response_time = time at first voluntary sleep - time woken up

`static void sched_switched_handler(void *data, bool preempt, struct task_struct *prev, struct task_struct *next, unsigned int prev_state)`

From sched_switch TP_PROTO, the tracepoint that fires gives information on the previous task (prev) that is switching out and the new task (next) that is switching in. The prev and next structs provide information about each of these tasks.

prev_state indicates the state that the prev task that is currently in at this tracepoint.

`                bool voluntary = prev_state & (TASK_INTERRUPTIBLE | TASK_UNINTERRUPTIBLE | TASK_PARKED | TASK_IDLE | TASK_DEAD);`

At a sched_switch out of prev, we check if prev is entering one of these states. Each one of these states indicates that prev is either going to sleep or exiting (entailing that it has finished its "current action"). If it is one of such switch reasons, we subtract the current time (voluntary sleep) by the wakeup to calculate the response time. This allows us to calculate max/min.
- curr_wu_ns is the a holding variable for the wakeup time (it is only set if we are switched into, and cleared on every voluntary sleep to not have multiple voluntary sleep using the same wakeup)

Why must this switch capture a state change that causes a voluntary sleep?

Say a switch was happening because the task was killed, by the time the scheduler had determined that this task needs to be moved off of the CPU, an according state change happened for this task in order to cause such an action.

The flow is like: 
1. A task's state change happens because of some action happened (it is calling something blocking)
2. schedule() is called to reflect such a change
3. scheduler realizes this task's state is not running anymore, and starts running some other process.

Therefore a state for a particular prev has to have been updated to cause a particular sched_switch.

If it is a state change that causes a preemption, we do not capture it. Preemption would leave the task still in prev_state=RUNNING. Unlike the flow depicted above, the state of the program doesn't change and the state doesn't direct the scheduler to make a change. The scheduler simply decides to move the program from the CPU to the run queue 


### Implementation of response_time = time at relief sleep - time woken up.

This implementation relies on a similar model with the above. A relief sleep is a particular type of voluntary sleep.

However, for this one, we do want to use an FSM to reason about it.

We define a task entering relief sleep as the task calling nanosleep() or clock_nanosleep().

If we want to distinguish this from other voluntary sleep reasons, we trace sleep syscalls.

The flow then goes like this:
1. Program runs
2. Program calls sleep
3. sleep changes program state
4. scheduler removes program from the CPU

Core: a program has to have first called sleep() (to change its state), then reach our sched_switch tracepoint.

Therefore, if we track whether this voluntary has a sleep right before it, we are able to distinguish if this voluntary sleep is a relief sleep or not.

![Mini FSM](./resources/mini_FSM.png)

To implement this FSM, we introduce several new variables in the task latency struct.

scause - accounts when a sleep call happens (used when sched_switch happens)

last_sleep_cause - say if program did a voluntary sleep, sched_switch'ed out, and there was a wakeup, we need to know whether the previous sleep was part of our cycle or not.

cycle_start_ns - this is the variable we consume at q_2, and we set at q_0

cycle_active - if our program is between a wakeup and a relief sleep.

resp_cycle_max/min_ns - tracks the max / min values in response time from wakeup to relief.


### Thoughts on applicability

Response time is being tracked for user programs, the control loop and IRQ threads.

For the control loop (a good design), response time will be similar to relief response time.

For a background user program, there could be multiple cases.

1 - User program is a periodically run loop that accesses hardware 

2 - User program is an event activated function that blocks 

3 - User program is an event activated function that doesn't block 

Remark that you need a loop even with a non-periodic task that is waiting on hardware interrupts. Since after the first interrupt comes, it handles it, you just finish execution and that task is gone.

For 1, there are hardware accesses, there is a relief sleep at end of each iteration Both response times are the same in Grant's model. However in blocking cases, relief sleep version captures that.

For 2, only the first voluntary sleep version captures something (a little bit) useful. We can't capture the relief sleep because there is no nanosleep, it would voluntary sleep to wait for the next interrupt. so the true time would be sleep because blocking on loop initial interrupt - woken up from interrupt. TODO: figure out how to track this potentially.

For 3, only the first voluntary sleep version of response time would be useful. This captures the whole cycle.


