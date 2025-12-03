#include <linux/spinlock.h>
#include <linux/slab.h>
#include "trace_ring_buffer.h"

static DECLARE_KFIFO(event_fifo, struct slo_event, QUEUE_LEN);
static spinlock_t event_fifo_lock;                                      // events (diff pids) can be added at same time.

int slo_queue_init(void)
{
        spin_lock_init(&event_fifo_lock);
        return 0;
}

void slo_queue_exit(void)
{

}

int slo_queue_push(const struct slo_event *ev)
{
        unsigned long flags;
        unsigned int copied;

        spin_lock_irqsave(&event_fifo_lock, flags);
        copied = kfifo_in(&event_fifo, ev, 1);

        if (copied == 0)        // 0 bytes successfully inserted
        {
                struct slo_event dummy;
                slo_queue_pop(&dummy);
                copied = kfifo_in(&event_fifo, ev, 1);
        }
        spin_unlock_irqrestore(&event_fifo_lock, flags);

        return (copied == 1) ? 0 : -ENOSPC;
}

int slo_queue_pop(struct slo_event *ev)
{
        unsigned long flags;
        unsigned int removed;

        spin_lock_irqsave(&event_fifo_lock, flags);
        removed = kfifo_out(&event_fifo, ev, 1);
        spin_unlock_irqrestore(&event_fifo_lock, flags);

        return (removed == 1) ? 0 : -ENOSPC;
}


bool slo_queue_empty()
{
        return ((kfifo_avail(&event_fifo) / sizeof(struct slo_event)) == QUEUE_LEN);
}

bool slo_queue_full()
{
        return kfifo_avail(&event_fifo) == 0;
}


// TODO: make a function that basically goes through and gets all the events out.
/*

Slo violation triggering.

Good case: begin is inside of the ring buffer, end is around the end of the ring buffer

I'd have to find begin inside the ring buffer somehow. also finding the end to secure the region.


*/

/**
 * fetch an array of slo events from beginning to end, relevant region. 
 * should not have removed any event in the fifo queue after this.
 * order of events is kept in resulting queue.
 * 
 * return 1 or 0 for success / fail.
 */
// int slo_queue_fetch_sequence(struct slo_event **arr) 
// {

// }


// TODO: for each violation, make filter for the logs for for things that are important to it.

