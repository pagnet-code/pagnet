//go:build linux || darwin

package daemon

import (
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
)

// NativeShareSourcePrepareExecutor is a dormant local boundary for authenticated
// source enrollment commands. The caller supplies the captured authenticated
// HostSession and its trusted endpoint, never session evidence from the command.
// Preparing a holder conveys no source, membership, grant or epoch authority.
type NativeShareSourcePrepareExecutor struct {
	store *NativeShareSourcePrepareStore
	now   func() time.Time
}

func NewNativeShareSourcePrepareExecutor(registry *NativeWorkerRegistry, now func() time.Time) (*NativeShareSourcePrepareExecutor, error) {
	if now == nil {
		return nil, errNativeShareSourcePrepare
	}
	holder, err := NewNativeShareSourceHolderStore(registry)
	if err != nil {
		return nil, err
	}
	store, err := NewNativeShareSourcePrepareStore(holder)
	if err != nil {
		return nil, err
	}
	return &NativeShareSourcePrepareExecutor{store: store, now: now}, nil
}

// Prepare checks the complete authenticated host incarnation before reserving
// a transcript or touching holder keys. Session is a value snapshot; callers
// must capture it from their authenticated connection before invoking Prepare.
// The journal releases registry locks before holder access and only signs inside
// WithKeys. Expiry after persistence suppresses the reply but retains dedupe.
func (e *NativeShareSourcePrepareExecutor) Prepare(endpoint string, session transport.HostSessionPayload, request transport.NativeShareSourcePreparePayload) (transport.NativeShareSourcePreparedPayload, error) {
	var empty transport.NativeShareSourcePreparedPayload
	if e == nil || e.store == nil || e.now == nil || endpoint == "" || textServiceServer(endpoint) != endpoint || session.RunnerEpoch.IsZero() {
		return empty, errNativeShareSourcePrepare
	}
	if session.OwnershipScope != "personal" && !(session.OwnershipScope == "organization" && session.AccountID == session.TenantID) {
		return empty, errNativeShareSourcePrepare
	}
	subject := transport.NativeShareSourceHostSubject{
		ServerURL: endpoint, TenantID: domain.ID(session.TenantID), AccountID: domain.ID(session.AccountID), HostID: domain.ID(session.HostID),
		NativeAdmissionID: domain.ID(session.NativeAdmissionID), RunnerID: domain.ID(session.RunnerID), RunnerEpoch: session.RunnerEpoch.UTC().Format(time.RFC3339Nano), BootID: session.BootID,
	}
	if _, err := subject.CanonicalBytes(); err != nil {
		return empty, errNativeShareSourcePrepare
	}
	if _, err := request.CanonicalBytes(); err != nil {
		return empty, errNativeShareSourcePrepare
	}
	if request.Enrollment.Subject != subject || request.Enrollment.HostCredentialID != session.HostCredentialID || request.Enrollment.OwnershipScope != session.OwnershipScope {
		return empty, errNativeShareSourcePrepare
	}
	// This scope is captured from authenticated session values. Request equality
	// above lets the journal use that same scope without trusting remote evidence.
	scope := transport.NativeShareSourceHolderScope{ServerURL: endpoint, TenantID: domain.ID(session.TenantID), AccountID: domain.ID(session.AccountID), HostID: domain.ID(session.HostID)}
	expiry, err := time.Parse(time.RFC3339Nano, request.Enrollment.ExpiresAt)
	if err != nil || !e.before(expiry) {
		return empty, errNativeShareSourcePrepare
	}
	prepared, err := e.store.Prepare(request)
	if err != nil {
		return empty, err
	}
	if prepared.Descriptor.Scope != scope || !e.before(expiry) {
		return empty, errNativeShareSourcePrepare
	}
	return prepared, nil
}

func (e *NativeShareSourcePrepareExecutor) before(expiry time.Time) bool {
	now := e.now()
	return !now.IsZero() && now.Before(expiry)
}
