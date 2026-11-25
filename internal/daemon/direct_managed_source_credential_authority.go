//go:build linux || darwin

package daemon

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"reflect"
	"strconv"
	"sync"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

// directManagedSourceCredentialPublicationLane serializes cancellation with local
// publication. Cancellation completes only after any acquired publication guard
// has released custody following the registry COMMIT or ROLLBACK.
type directManagedSourceCredentialPublicationLane struct {
	mu   sync.Mutex
	done chan struct{}
}

func newDirectManagedSourceCredentialPublicationLane() *directManagedSourceCredentialPublicationLane {
	return &directManagedSourceCredentialPublicationLane{done: make(chan struct{})}
}

func (lane *directManagedSourceCredentialPublicationLane) cancel() {
	lane.mu.Lock()
	defer lane.mu.Unlock()
	select {
	case <-lane.done:
	default:
		close(lane.done)
	}
}

type directManagedSourceCredentialProtocolVariant uint8

const (
	directManagedSourceCredentialProtocolV1 directManagedSourceCredentialProtocolVariant = iota + 1
	directManagedSourceCredentialProtocolV2
)

// directManagedSourceCredentialPublicationFence pins local authority only. The
// caller obtains token through the full verifier, including worker IPC, before
// entering store locks. The lane mutex is acquired last, after native.mu, and
// released first after transaction completion. This does not authenticate remote
// consent or budgets.
func (d *Daemon) directManagedSourceCredentialPublicationFence(token *nativeWorkerPublicationToken, captured ManagedEndpointPrepareScope, lane *directManagedSourceCredentialPublicationLane) DirectManagedSourceCredentialPublicationFence {
	return func(conn *sql.Conn, issue transport.DirectManagedSourceCredentialIssue, server string, session transport.HostSessionPayload) (func(), error) {
		if d == nil || d.nativeRegistry == nil || d.state == nil || conn == nil || token == nil || token.link == nil || token.proxy == nil || captured.Socket == nil || captured.Connection == nil || lane == nil || lane.done == nil {
			return nil, ErrManagedEndpointPrepareRetryable
		}
		if _, err := issue.CanonicalBytes(); err != nil {
			return nil, ErrManagedEndpointPrepareRejected
		}
		return d.credentialPublicationFence(token, captured, lane, nativeManagedSubjectFromSource(issue.PoP.Prepare.Subject), directManagedSourceSessionMatches(issue.PoP.Prepare.Subject, session), directManagedSourceCredentialProtocolV1, issue.IssuedAt, issue.InstallExpiresAt, issue.CredentialExpiresAt, issue.BudgetExpiresAt)(conn, server, session)
	}
}

func (d *Daemon) directManagedSourceCredentialPublicationFenceV2(token *nativeWorkerPublicationToken, captured ManagedEndpointPrepareScope, lane *directManagedSourceCredentialPublicationLane) DirectManagedSourceCredentialPublicationFenceV2 {
	return func(conn *sql.Conn, issue transport.DirectManagedSourceCredentialIssueV2, server string, session transport.HostSessionPayload) (func(), error) {
		if _, err := issue.CanonicalBytes(); err != nil {
			return nil, ErrManagedEndpointPrepareRejected
		}
		return d.credentialPublicationFence(token, captured, lane, nativeManagedSubjectFromSourceV2(issue.PoP.Prepare.Subject), directManagedSourceSessionMatchesV2(issue.PoP.Prepare.Subject, session), directManagedSourceCredentialProtocolV2, issue.IssuedAt, issue.InstallExpiresAt, issue.CredentialExpiresAt, issue.BudgetExpiresAt)(conn, server, session)
	}
}

func (d *Daemon) credentialPublicationFence(token *nativeWorkerPublicationToken, captured ManagedEndpointPrepareScope, lane *directManagedSourceCredentialPublicationLane, subject nativeManagedSubject, matchesSession bool, variant directManagedSourceCredentialProtocolVariant, issuedAt, installExpiresAt, credentialExpiresAt, budgetExpiresAt time.Time) func(*sql.Conn, string, transport.HostSessionPayload) (func(), error) {
	protocolValid := func(native *NativeObservationConnection, session transport.HostSessionPayload) bool {
		var required []string
		switch variant {
		case directManagedSourceCredentialProtocolV1:
			if !d.DirectManagedSourcePrepareEnabled || !d.DirectManagedSourcePoPEnabled || !d.DirectManagedSourceCredentialEnabled || !native.offeredDirectManagedSourcePrepare || !native.offeredDirectManagedSourcePoP || native.offeredDirectManagedSourceCredential != transport.DirectManagedSourceCredentialProtocol {
				return false
			}
			required = []string{transport.DirectManagedSourcePrepareProtocol, transport.DirectManagedSourcePoPProtocol, transport.DirectManagedSourceCredentialProtocol}
		case directManagedSourceCredentialProtocolV2:
			required = []string{transport.DirectManagedSourcePrepareProtocolV2, transport.DirectManagedSourcePoPProtocolV2, transport.DirectManagedSourceCredentialProtocolV2}
		default:
			return false
		}
		for _, feature := range required {
			count := 0
			for _, got := range session.ProtocolFeatures {
				if got == feature {
					count++
				}
			}
			if count != 1 {
				return false
			}
		}
		return true
	}
	return func(registryConn *sql.Conn, server string, session transport.HostSessionPayload) (release func(), err error) {
		if d == nil || d.nativeRegistry == nil || d.state == nil || registryConn == nil || token == nil || token.link == nil || token.proxy == nil || captured.Socket == nil || captured.Connection == nil || lane == nil || lane.done == nil {
			return nil, ErrManagedEndpointPrepareRetryable
		}
		if !reflect.DeepEqual(subject, token.subject) || !reflect.DeepEqual(session, captured.Session) || !matchesSession || managedPrepareServerOrigin(server) == "" {
			return nil, ErrManagedEndpointPrepareRejected
		}
		ctx := context.Background()
		// The store already owns the registry writer reservation. Never call a
		// registry API here: its single-connection pool is reserved by this caller.
		var raw []byte
		var launch string
		if err := registryConn.QueryRowContext(ctx, `SELECT payload,launch_state FROM native_workers WHERE instance_id=?`, token.instanceID).Scan(&raw, &launch); err != nil {
			return nil, ErrManagedEndpointPrepareRetryable
		}
		record, err := d.nativeRegistry.decodeRecord(token.instanceID, raw, launch)
		if err != nil {
			return nil, ErrManagedEndpointPrepareRejected
		}
		var fenced int
		if err := registryConn.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM native_worker_recoveries WHERE instance_id=? AND original_generation=?)+(SELECT COUNT(*) FROM native_worker_gc WHERE instance_id=?)`, token.instanceID, record.Scope.Generation, token.instanceID).Scan(&fenced); err != nil {
			return nil, ErrManagedEndpointPrepareRetryable
		}
		p, scope, ownership := token.proxy, record.Scope, token.ownership
		if validateOwnership(scope, record.Spec, record.Profile, &ownership) != nil || (record.OriginalOwnershipID != "" && record.OriginalOwnershipID != ownership.ID) || fenced != 0 || record.LaunchState != "launched" || record.Spec.Runtime != domain.RuntimeQwenCode || record.Spec.TenantID != scope.TenantID || scope != p.scope || managedPrepareServerOrigin(scope.ServerURL) != managedPrepareServerOrigin(server) || scope.TenantID != session.TenantID || scope.AccountID != session.AccountID || scope.HostID != session.HostID || scope.InstanceID != subject.InstanceID.String() || scope.Generation != subject.OwnershipGeneration || ownership.ID != subject.OwnershipID.String() || ownership.State != "active" || ownership.DeletionProof != nil || record.ProfileFingerprint != sessionworker.NativeProfileFingerprint(record.Spec) || p.profile != record.ProfileFingerprint || sessionworker.NativeProfileFingerprint(p.bootstrap.Native) != p.profile || ownership.ProfileFingerprint != record.ProfileFingerprint || ownership.Profile != record.Profile || record.Ownership == nil || !sameManagedPrepareOwnership(*record.Ownership, ownership) {
			return nil, ErrManagedEndpointPrepareRejected
		}
		acquireCtx, cancel := context.WithTimeout(ctx, 10*time.Millisecond)
		stateConn, err := d.state.db.Conn(acquireCtx)
		cancel()
		if err != nil {
			return nil, ErrManagedEndpointPrepareRetryable
		}
		var unlocks []func()
		stateReserved := false
		busyChanged := false
		var busy int
		// On every failed acquisition, unwind before returning; on success the store
		// owns this release until its own COMMIT/ROLLBACK, including panic unwinding.
		release = func() {
			for i := len(unlocks) - 1; i >= 0; i-- {
				unlocks[i]()
			}
			unlocks = nil
			if stateReserved {
				if _, rollbackErr := stateConn.ExecContext(ctx, "ROLLBACK"); rollbackErr != nil {
					_ = stateConn.Raw(func(any) error { return driver.ErrBadConn })
				}
				stateReserved = false
			}
			if busyChanged {
				if _, restoreErr := stateConn.ExecContext(ctx, "PRAGMA busy_timeout="+strconv.Itoa(busy)); restoreErr != nil {
					_ = stateConn.Raw(func(any) error { return driver.ErrBadConn })
				}
			}
			_ = stateConn.Close()
		}
		defer func() {
			if err != nil {
				release()
				release = nil
			}
		}()
		if err = stateConn.QueryRowContext(ctx, "PRAGMA busy_timeout").Scan(&busy); err != nil {
			return release, ErrManagedEndpointPrepareRetryable
		}
		if _, err = stateConn.ExecContext(ctx, "PRAGMA busy_timeout=0"); err != nil {
			return release, ErrManagedEndpointPrepareRetryable
		}
		busyChanged = true
		if _, err = stateConn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
			return release, ErrManagedEndpointPrepareRetryable
		}
		stateReserved = true
		var principal, runtime, profile string
		if err = stateConn.QueryRowContext(ctx, `SELECT agent_principal_id,runtime,profile FROM instances WHERE instance_id=?`, token.instanceID).Scan(&principal, &runtime, &profile); err != nil {
			return release, ErrManagedEndpointPrepareRetryable
		}
		if principal != subject.PrincipalID.String() || runtime != string(domain.RuntimeQwenCode) || profile != record.Profile {
			return release, ErrManagedEndpointPrepareRejected
		}
		for _, lock := range []interface {
			TryLock() bool
			Unlock()
		}{&d.nativeWorkersMu, &token.link.mu} {
			if !lock.TryLock() {
				return release, ErrManagedEndpointPrepareRetryable
			}
			unlocks = append(unlocks, lock.Unlock)
		}
		if !p.publicationMu.TryRLock() {
			return release, ErrManagedEndpointPrepareRetryable
		}
		unlocks = append(unlocks, p.publicationMu.RUnlock)
		for _, lock := range []interface {
			TryLock() bool
			Unlock()
		}{&d.connMu, &captured.Connection.mu, &lane.mu} {
			if !lock.TryLock() {
				return release, ErrManagedEndpointPrepareRetryable
			}
			unlocks = append(unlocks, lock.Unlock)
		}
		native := captured.Connection
		if d.nativeWorkers[token.instanceID] != token.link || token.link.proxy != p || token.link.conn != captured.Socket || p.connection != native || !sameManagedPrepareOwnership(token.link.ownership, ownership) || d.curConn != captured.Socket || d.nativeConn != native || native.session == nil || !reflect.DeepEqual(*native.session, session) || managedPrepareServerOrigin(native.serverURL) != managedPrepareServerOrigin(server) || native.hostID != session.HostID || native.bootID != session.BootID {
			return release, ErrManagedEndpointPrepareRetryable
		}
		if !protocolValid(native, session) {
			return release, ErrManagedEndpointPrepareRejected
		}
		for _, done := range []<-chan struct{}{p.done, native.closed, lane.done} {
			select {
			case <-done:
				return release, ErrManagedEndpointPrepareRetryable
			default:
			}
		}
		now := time.Now()
		if now.Before(issuedAt) || !now.Before(installExpiresAt) || !now.Before(credentialExpiresAt) || !now.Before(budgetExpiresAt) || !now.Before(subject.ExpiresAt) {
			return release, ErrManagedEndpointPrepareRejected
		}
		return release, nil
	}
}
