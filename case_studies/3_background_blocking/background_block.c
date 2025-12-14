/**
 * Purpose is to demonstrate that for a background process that does not adhere to a
 * control loop like fashion, this can still be useful.
 * 
 * A event driven telemetry burst on event. (mimicing a irq pull, and then the task would wake up)
 * 
 * Do a burst of CPU work and then do a write. and accidentally include an extra voluntary sleep.
 * This showcases a bad case for the tool.
 */

