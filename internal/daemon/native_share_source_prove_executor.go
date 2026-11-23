//go:build linux || darwin

package daemon

import (
	"context"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
)

// NativeShareSourceProveExecutor is a local, closed proof boundary. Its caller
// supplies the authenticated session snapshot and trusted connection endpoint.
// Construction grants no source authority.
type NativeShareSourceProveExecutor struct {
	store *NativeShareSourceProveStore
	now   func() time.Time
}

func NewNativeShareSourceProveExecutor(registry *NativeWorkerRegistry, now func() time.Time) (*NativeShareSourceProveExecutor, error) {
	if now == nil {
		return nil, errNativeShareSourceProve
	}
	holder, err := NewNativeShareSourceHolderStore(registry)
	if err != nil {
		return nil, err
	}
	store, err := NewNativeShareSourceProveStore(holder)
	if err != nil {
		return nil, err
	}
	return &NativeShareSourceProveExecutor{store: store, now: now}, nil
}

// Prove checks authenticated context before reserving a proof or opening keys.
// Every retry rechecks the completed Prepare and expiry, then deterministically
// regenerates the reply. Plaintext challenges and raw replies are never stored.
func (e *NativeShareSourceProveExecutor) Prove(endpoint string, session transport.HostSessionPayload, request transport.NativeShareSourceProvePayload) (transport.NativeShareSourceProvedPayload, error) {
	var empty transport.NativeShareSourceProvedPayload
	if e == nil || e.store == nil || e.now == nil || endpoint == "" || textServiceServer(endpoint) != endpoint || session.RunnerEpoch.IsZero() {
		return empty, errNativeShareSourceProve
	}
	if session.OwnershipScope != "personal" && !(session.OwnershipScope == "organization" && session.AccountID == session.TenantID) {
		return empty, errNativeShareSourceProve
	}
	subject := transport.NativeShareSourceHostSubject{
		ServerURL: endpoint, TenantID: domain.ID(session.TenantID), AccountID: domain.ID(session.AccountID), HostID: domain.ID(session.HostID),
		NativeAdmissionID: domain.ID(session.NativeAdmissionID), RunnerID: domain.ID(session.RunnerID), RunnerEpoch: session.RunnerEpoch.UTC().Format(time.RFC3339Nano), BootID: session.BootID,
	}
	if _, err := subject.CanonicalBytes(); err != nil {
		return empty, errNativeShareSourceProve
	}
	return e.store.prove(request, subject, session.HostCredentialID, session.OwnershipScope, e.now)
}

// Readiness is bounded so a busy registry cannot stall the socket handshake.
func (e *NativeShareSourceProveExecutor) nativeShareSourceProveReady() bool {
	if e == nil || e.store == nil || e.store.holder == nil || e.store.holder.registry == nil || e.now == nil {
		return false
	}
	registry := e.store.holder.registry
	if registry.db == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	return registry.db.PingContext(ctx) == nil
}

// Compose only after the daemon has acquired its serve lock and registry.
func (d *Daemon) initNativeShareSourceProve() {
	executor, err := NewNativeShareSourceProveExecutor(d.nativeRegistry, time.Now)
	if err == nil && executor.nativeShareSourceProveReady() {
		d.nativeSourceProve = executor
		return
	}
	d.Log.Warn("native share source prove unavailable")
}
