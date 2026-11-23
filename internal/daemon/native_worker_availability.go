package daemon

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

var errNativeWorkerReadinessUnavailable = errors.New("native worker readiness unavailable")

const nativeWorkerSnapshotFreshness = 10 * time.Second
const nativeWorkerAvailabilityInterval = 15 * time.Second

func (c *NativeObservationConnection) recordNativeWorkerAttachFailure(scope sessionworker.Scope, err error) {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrNativeOriginAdmissionDeferred) || errors.Is(err, ErrNativeOriginAdmissionRejected) || errors.Is(err, sessionworker.ErrControllerCallNotStarted) {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.availabilityFailures == nil {
		c.availabilityFailures = make(map[string]string)
	}
	c.availabilityFailures[scope.InstanceID] = scope.Generation
}

// Only a consumed launch claim and a definitive local readiness observation
// establish unavailability. Admission and caller cancellation carry no evidence.
func (d *Daemon) recordNativeWorkerReadinessFailure(c *NativeObservationConnection, record NativeWorkerRecord, err error) {
	if !errors.Is(err, errNativeWorkerReadinessUnavailable) {
		return
	}
	current, lookupErr := d.nativeRegistry.Lookup(record.Scope.InstanceID)
	if lookupErr == nil && current.Scope == record.Scope && (current.LaunchState == "launched" || current.LaunchState == "launching") {
		c.recordNativeWorkerAttachFailure(record.Scope, err)
	}
}

func (p *NativeWorkerProxy) availability(now time.Time) string {
	select {
	case <-p.done:
		return "unavailable"
	default:
	}
	p.snapshotMu.Lock()
	at := p.snapshotAt
	p.snapshotMu.Unlock()
	if at.IsZero() || now.Before(at) || now.Sub(at) > nativeWorkerSnapshotFreshness {
		return "unknown"
	}
	return "connected"
}

// Read only cached observations from the exact proxy on this socket. In
// particular this publisher cannot probe a socket, attach, or launch a worker.
func (d *Daemon) nativeWorkerAvailability(conn *websocket.Conn, c *NativeObservationConnection, record NativeWorkerRecord, now time.Time) string {
	d.nativeWorkersMu.Lock()
	defer d.nativeWorkersMu.Unlock()
	link := d.nativeWorkers[record.Scope.InstanceID]
	if link != nil && link.conn == conn && link.proxy.connection == c && link.proxy.scope == record.Scope {
		return link.proxy.availability(now)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.availabilityFailures[record.Scope.InstanceID] == record.Scope.Generation {
		return "unavailable"
	}
	return "unknown"
}

func (d *Daemon) publishNativeWorkerAvailability(conn *websocket.Conn, c *NativeObservationConnection) {
	ticker := time.NewTicker(nativeWorkerAvailabilityInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.closed:
			return
		case <-d.turnCtx.Done():
			return
		case <-ticker.C:
			if err := d.sendNativeWorkerAvailability(d.turnCtx, conn, c); err != nil {
				return
			}
		}
	}
}

func (d *Daemon) sendNativeWorkerAvailability(ctx context.Context, conn *websocket.Conn, c *NativeObservationConnection) error {
	session, err := c.AuthenticatedNativeHostSession()
	if err != nil {
		return err
	}
	if d.nativeRegistry == nil || !slices.Contains(session.ProtocolFeatures, transport.NativeWorkerAvailabilityProtocol) {
		return nil
	}
	records, err := d.nativeRegistry.list(true)
	if err != nil {
		return err
	}
	for _, record := range records {
		if record.Scope.HostID != session.HostID || record.Scope.TenantID != session.TenantID || record.Scope.AccountID != session.AccountID {
			continue
		}
		state := d.nativeWorkerAvailability(conn, c, record, time.Now())
		c.mu.Lock()
		if c.session == nil {
			c.mu.Unlock()
			return ErrNativeOriginAdmissionDeferred
		}
		c.availabilitySequence++
		sequence := c.availabilitySequence
		c.mu.Unlock()
		p := transport.NativeWorkerAvailabilityPayload{InstanceID: record.Scope.InstanceID, OwnershipGeneration: record.Scope.Generation, Sequence: sequence, State: state}
		if err := p.Validate(); err != nil {
			continue
		}
		if err := c.send(ctx, transport.MsgNativeWorkerAvailability, p); err != nil {
			return err
		}
	}
	return nil
}
