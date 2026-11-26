package daemon

import (
	"context"
	"time"

	"github.com/pagnet-code/pagnet/transport"
)

type directEndpointWakeWrite struct {
	entry    *directEndpointWakeAttachment
	typ      string
	raw      []byte
	deadline time.Time
}

// One absolute budget covers admission, the bounded queue, the shared writer
// mutex and socket I/O. It is never renewed when a retry reaches the writer.
func (c *directEndpointWakeConnection) writeBudget() time.Duration {
	budget := 2 * time.Second
	if c.daemon != nil && c.daemon.writeTimeout > 0 && c.daemon.writeTimeout < budget {
		budget = c.daemon.writeTimeout
	}
	return budget
}

func (c *directEndpointWakeConnection) notifyWatchdogLocked() {
	select {
	case c.watch <- struct{}{}:
	default:
	}
}

// Caller owns mu. Admission never waits for either the queue or the writer.
func (c *directEndpointWakeConnection) enqueueLocked(entry *directEndpointWakeAttachment, typ string, payload interface{ CanonicalBytes() ([]byte, error) }, received time.Time) bool {
	canonical, err := payload.CanonicalBytes()
	if err != nil {
		return false
	}
	env, err := transport.NewEnvelope(typ, payload)
	if err != nil {
		return false
	}
	env.Payload = canonical
	raw, err := transport.MarshalNativeJSON(env)
	if err != nil {
		return false
	}
	job := &directEndpointWakeWrite{entry: entry, typ: typ, raw: raw, deadline: received.Add(c.writeBudget())}
	select {
	case c.queue <- job:
		c.pendingWrites[job] = struct{}{}
		c.notifyWatchdogLocked()
		return true
	default:
		return false
	}
}

// Closing drains only the already bounded queue, including best-effort
// unsubscribes admitted before done closed. No new attachments can enter it.
func (c *directEndpointWakeConnection) runWriter() {
	defer close(c.writerDone)
	for {
		select {
		case job := <-c.queue:
			c.writeJob(job)
		default:
			select {
			case job := <-c.queue:
				c.writeJob(job)
			case <-c.done:
				for {
					select {
					case job := <-c.queue:
						c.writeJob(job)
					default:
						return
					}
				}
			}
		}
	}
}

func (c *directEndpointWakeConnection) finishWrite(job *directEndpointWakeWrite, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.pendingWrites, job)
	if err != nil && job.typ != transport.MsgDirectEndpointWakeUnsubscribe {
		c.removeLocked(job.entry, true, err)
	}
	c.notifyWatchdogLocked()
}

func (c *directEndpointWakeConnection) writeJob(job *directEndpointWakeWrite) {
	if c.daemon == nil {
		c.finishWrite(job, ErrNativeObservationConflict)
		return
	}
	remaining := time.Until(job.deadline)
	if remaining <= 0 {
		c.finishWrite(job, context.DeadlineExceeded)
		return
	}
	deadline := time.NewTimer(remaining)
	defer deadline.Stop()
	var canceled <-chan struct{}
	if job.typ != transport.MsgDirectEndpointWakeUnsubscribe {
		canceled = job.entry.ctx.Done()
	}
	// TryLock avoids retaining a mutex waiter after its absolute deadline.
	// Lifecycle fence contention releases writeMu before the bounded backoff,
	// so a slow admission cannot pin the shared writer past this job's budget.
	for {
		if c.daemon.writeMu.TryLock() {
			current, retry := c.writeCurrent(job)
			if !retry {
				if !current {
					c.daemon.writeMu.Unlock()
					c.finishWrite(job, ErrNativeObservationConflict)
					return
				}
				err := c.write(job.deadline, job.raw)
				c.daemon.writeMu.Unlock()
				if err != nil {
					c.writeFailed()
				}
				c.finishWrite(job, err)
				return
			}
			c.daemon.writeMu.Unlock()
		}
		backoff := time.NewTimer(time.Millisecond)
		select {
		case <-deadline.C:
			backoff.Stop()
			c.finishWrite(job, context.DeadlineExceeded)
			return
		case <-canceled:
			backoff.Stop()
			c.finishWrite(job, context.Canceled)
			return
		case <-backoff.C:
		}
	}
}

// Called only after acquiring writeMu. Normal writes recheck all local fences
// immediately before I/O; the locks are released before the socket is touched.
// An unsubscribe only retires this exact ID on the original socket, so it may
// run after local cancellation or replacement of the daemon's current socket.
func (c *directEndpointWakeConnection) writeCurrent(job *directEndpointWakeWrite) (current, retry bool) {
	if job.typ == transport.MsgDirectEndpointWakeUnsubscribe {
		if !c.mu.TryLock() {
			return false, true
		}
		defer c.mu.Unlock()
		_, pending := c.pendingWrites[job]
		return pending && time.Now().Before(job.deadline) && job.entry.unsubscribeQueued && job.entry.subscribeStarted && job.entry.ctx.Err() != nil, false
	}
	if job.entry.handle.aborted() {
		return false, false
	}
	if !c.daemon.connMu.TryLock() {
		return false, true
	}
	defer c.daemon.connMu.Unlock()
	if c.daemon.curConn != c.socket || c.daemon.nativeConn != c.native {
		return false, false
	}
	if !c.native.mu.TryLock() {
		return false, true
	}
	defer c.native.mu.Unlock()
	if !c.mu.TryLock() {
		return false, true
	}
	defer c.mu.Unlock()
	_, pending := c.pendingWrites[job]
	entry := job.entry
	if !pending || !time.Now().Before(job.deadline) || entry.ctx.Err() != nil || c.native.directWake != c || c.byHandle[entry.handle] != entry || c.byID[entry.subscription.SubscriptionID] != entry {
		return false, false
	}
	// The owner remains the final leaf fence; no lock or I/O enters it.
	if !entry.handle.owner.mu.TryLock() {
		return false, true
	}
	defer entry.handle.owner.mu.Unlock()
	if _, valid := entry.handle.owner.entries[entry.handle]; !valid || !time.Now().Before(entry.handle.binding.metadata.Deadline) || entry.handle.aborted() {
		return false, false
	}
	select {
	case <-c.done:
		return false, false
	case <-c.native.closed:
		return false, false
	default:
	}
	if job.typ == transport.MsgDirectEndpointWakeSubscribe {
		entry.subscribeStarted = true
	}
	return true, false
}

// A single connection watchdog expires queued and in-flight jobs even when
// the writer is waiting for writeMu or blocked in the OS. Socket writes use
// this same absolute deadline. There are no per-offer watchdog goroutines.
func (c *directEndpointWakeConnection) runWatchdog() {
	for {
		c.mu.Lock()
		now := time.Now()
		var next time.Time
		for job := range c.pendingWrites {
			if !now.Before(job.deadline) {
				delete(c.pendingWrites, job)
				if job.typ != transport.MsgDirectEndpointWakeUnsubscribe {
					c.removeLocked(job.entry, true, context.DeadlineExceeded)
				}
				continue
			}
			if next.IsZero() || job.deadline.Before(next) {
				next = job.deadline
			}
		}
		c.mu.Unlock()
		var timer *time.Timer
		var expired <-chan time.Time
		if !next.IsZero() {
			timer = time.NewTimer(time.Until(next))
			expired = timer.C
		}
		select {
		case <-c.writerDone:
			if timer != nil {
				timer.Stop()
			}
			return
		case <-c.watch:
		case <-expired:
		}
		if timer != nil {
			timer.Stop()
		}
	}
}
