package daemon

import (
	"context"
	"slices"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

const nativeWorkerSnapshotFreshness = 10 * time.Second
const nativeWorkerAvailabilityInterval = 15 * time.Second

func (c *NativeObservationConnection) recordNativeWorkerAttachFailure(scope sessionworker.Scope) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.availabilityFailures == nil {
		c.availabilityFailures = make(map[string]string)
	}
	c.availabilityFailures[scope.InstanceID] = scope.Generation
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
	records, err := d.nativeRegistry.List()
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
			return err
		}
		if err := c.send(ctx, transport.MsgNativeWorkerAvailability, p); err != nil {
			return err
		}
	}
	return nil
}
