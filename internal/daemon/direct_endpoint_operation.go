//go:build linux || darwin

package daemon

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/pagnet-code/pagnet/transport"
)

// These errors contain no callback, filesystem, or credential details. Once the
// callback is dispatched, any failure leaves a possible mutation uncertain.
var (
	errDirectEndpointOperationRejected = errors.New("direct endpoint operation rejected")
	errDirectEndpointOperationUnknown  = errors.New("direct endpoint operation outcome unknown")
)

// Operation custody receives the derived lease context; admission custody stays unchanged.
type directEndpointOperationCustodyUse func(context.Context, func() error, endpointMaterialFence, func(endpointMaterial) error) error

// operateManagedTargetEndpoint and operateDirectManagedSourceEndpointV2 are
// daemon-private prerequisites only: they install no transport or coordinator.
func (d *Daemon) operateManagedTargetEndpoint(ctx context.Context, captured ManagedEndpointPrepareScope, s *DirectEndpointSubscription, issue transport.ManagedDirectCredentialIssue, use func(context.Context, endpointMaterial) error) error {
	if d == nil || s == nil {
		return errDirectEndpointOperationRejected
	}
	raw, err := issue.CanonicalBytes()
	if err != nil {
		return errDirectEndpointOperationRejected
	}
	subject := nativeManagedSubjectFromEndpoint(issue.PoP.Prepare.Subject)
	subject.ExpiresAt = issue.PoP.Authorization.ExpiresAt
	scope := endpointMaterialScope{s.binding.metadata.InstallationID, s.binding.metadata.CredentialID, "P", endpointMaterialLiveUse}
	return d.operateDirectEndpoint(ctx, captured, s, raw, subject, managedDirectCredentialProtocolV1, issue.IssuedAt, scope, func(opctx context.Context, verify func() error, fence endpointMaterialFence, use func(endpointMaterial) error) error {
		keys, err := newManagedEndpointKeyStoreContext(opctx, d.nativeRegistry)
		if err != nil || keys.installation != scope.installation {
			return errDirectEndpointOperationRejected
		}
		return keys.withManagedTargetEndpointMaterialContext(opctx, issue, issue.PoP.ACK.Reservation.ServerURL, captured.Session, scope, func(transport.ManagedDirectCredentialIssue, string, transport.HostSessionPayload) error {
			return verify()
		}, fence, use)
	}, d.verifyDirectEndpointToken, use)
}

func (d *Daemon) operateDirectManagedSourceEndpointV2(ctx context.Context, captured ManagedEndpointPrepareScope, s *DirectEndpointSubscription, issue transport.DirectManagedSourceCredentialIssueV2, use func(context.Context, endpointMaterial) error) error {
	if d == nil || s == nil {
		return errDirectEndpointOperationRejected
	}
	raw, err := issue.CanonicalBytes()
	if err != nil {
		return errDirectEndpointOperationRejected
	}
	subject := nativeManagedSubjectFromSourceV2(issue.PoP.Prepare.Subject)
	subject.ExpiresAt = issue.PoP.Prepare.Subject.AuthorizationExpiresAt
	scope := endpointMaterialScope{s.binding.metadata.InstallationID, s.binding.metadata.CredentialID, "S", endpointMaterialLiveUse}
	return d.operateDirectEndpoint(ctx, captured, s, raw, subject, directManagedSourceCredentialProtocolV2, issue.IssuedAt, scope, func(opctx context.Context, verify func() error, fence endpointMaterialFence, use func(endpointMaterial) error) error {
		keys, err := newDirectManagedSourceKeyStoreV2Context(opctx, d.nativeRegistry)
		if err != nil || keys.installation != scope.installation {
			return errDirectEndpointOperationRejected
		}
		return keys.withDirectManagedSourceEndpointMaterialV2Context(opctx, issue, issue.PoP.ACK.Reservation.ServerURL, captured.Session, scope, func(transport.DirectManagedSourceCredentialIssueV2, string, transport.HostSessionPayload) error {
			return verify()
		}, fence, use)
	}, d.verifyDirectEndpointToken, use)
}

// operateDirectEndpoint obtains a short fenced custody snapshot. The subscription
// generation then acts as the fine-grained cancellable lease: lifecycle writers
// revoke it without waiting for a callback. No registry, namespace, transaction,
// or lifecycle lock is held during use. use is synchronous and must not retain
// material; a nil return is trusted only while this exact lease remains live.
func (d *Daemon) operateDirectEndpoint(ctx context.Context, captured ManagedEndpointPrepareScope, s *DirectEndpointSubscription, raw []byte, subject nativeManagedSubject, variant directManagedSourceCredentialProtocolVariant, issuedAt time.Time, scope endpointMaterialScope, custody directEndpointOperationCustodyUse, verifyToken func(context.Context, ManagedEndpointPrepareScope, string, nativeManagedSubject) (*nativeWorkerPublicationToken, error), use func(context.Context, endpointMaterial) error) (err error) {
	if d == nil || ctx == nil || s == nil || s.owner != &d.directSubscriptions || custody == nil || verifyToken == nil || use == nil || !s.operationCurrentContext(ctx) {
		return errDirectEndpointOperationRejected
	}
	binding := s.binding
	sessionRaw, marshalErr := json.Marshal(captured.Session)
	if marshalErr != nil || string(sessionRaw) != binding.sessionIdentity || json.Unmarshal(sessionRaw, &captured.Session) != nil || binding.socket != captured.Socket || binding.native != captured.Connection || !reflect.DeepEqual(binding.subject, subject) || binding.issueDigest != sha256.Sum256(raw) || scope.installation != binding.metadata.InstallationID || scope.credential != binding.metadata.CredentialID || scope.role != binding.metadata.Role || scope.use != endpointMaterialLiveUse || managedPrepareServerOrigin(d.nativeServerURL()) != binding.metadata.ServerOrigin {
		return errDirectEndpointOperationRejected
	}
	opctx, cancel := context.WithDeadline(ctx, binding.metadata.Deadline)
	defer cancel()
	// Stop the watcher before returning; it never acquires custody or lifecycle locks.
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		select {
		case <-s.Done():
			cancel()
		case <-s.AbortDone():
			cancel()
		case <-opctx.Done():
		}
	}()
	defer func() { cancel(); <-watcherDone }()
	live := func() bool { return s.operationCurrentContext(opctx) }
	lane := newDirectManagedSourceCredentialPublicationLane()
	stop := context.AfterFunc(opctx, lane.cancel)
	defer stop()
	var token *nativeWorkerPublicationToken
	verify := func() error {
		if !live() {
			return errDirectEndpointOperationRejected
		}
		fresh, verifyErr := verifyToken(opctx, captured, binding.metadata.ServerOrigin, subject)
		if verifyErr != nil || fresh == nil || fresh.link != binding.link || fresh.proxy != binding.proxy || !reflect.DeepEqual(fresh.subject, subject) {
			return errDirectEndpointOperationRejected
		}
		epoch, current, authorityErr := fresh.proxy.directEndpointAuthorityContext(opctx, subject)
		if authorityErr != nil || !current || fresh.endpointEpoch != epoch {
			return errDirectEndpointOperationRejected
		}
		fresh.endpointUse = true
		token = fresh
		return nil
	}
	fence := func(conn *sql.Conn) (func(), func() error, error) {
		if !live() {
			return nil, nil, errDirectEndpointOperationRejected
		}
		release, fenceErr := d.credentialPublicationFenceContext(opctx, token, captured, lane, subject, nativeManagedSessionMatches(subject, captured.Session), variant, issuedAt, binding.metadata.Deadline, binding.metadata.Deadline, binding.metadata.Deadline)(conn, binding.metadata.ServerOrigin, captured.Session)
		return release, func() error {
			if !live() {
				return errDirectEndpointOperationRejected
			}
			return nil
		}, fenceErr
	}
	material, loadErr := loadEndpointMaterial(func(verify func() error, fence endpointMaterialFence, use func(endpointMaterial) error) error {
		return custody(opctx, verify, fence, use)
	}, verify, fence)
	defer material.clear()
	if loadErr != nil || !live() {
		return errDirectEndpointOperationRejected
	}
	// This is the dispatch boundary. Revocation after this point cannot establish
	// whether a remote mutation happened, even if the callback reports success.
	err = errDirectEndpointOperationUnknown
	defer func() {
		if recover() != nil {
			err = errDirectEndpointOperationUnknown
		}
	}()
	if callbackErr := use(opctx, material); callbackErr != nil || !live() {
		return errDirectEndpointOperationUnknown
	}
	return nil
}

// operationCurrent linearizes dispatch acceptance and response acceptance with
// generation removal. This leaf lock is never held across a callback.
func (s *DirectEndpointSubscription) operationCurrent(ctx context.Context) bool {
	if s.aborted() || ctx.Err() != nil {
		return false
	}
	s.owner.mu.Lock()
	defer s.owner.mu.Unlock()
	if _, ok := s.owner.entries[s]; !ok || ctx.Err() != nil || s.aborted() {
		return false
	}
	if !time.Now().Before(s.binding.metadata.Deadline) {
		s.owner.removeLocked(s)
		return false
	}
	return true
}

// operationCurrentContext bounds lease acceptance lock acquisition and checks
// abort both before and after taking the subscription leaf lock.
func (s *DirectEndpointSubscription) operationCurrentContext(ctx context.Context) bool {
	if s == nil || s.owner == nil || ctx == nil || s.aborted() || ctx.Err() != nil {
		return false
	}
	unlock, err := directEndpointTryLock(ctx, &s.owner.mu)
	if err != nil {
		return false
	}
	defer unlock()
	if _, ok := s.owner.entries[s]; !ok || ctx.Err() != nil || s.aborted() {
		return false
	}
	if !time.Now().Before(s.binding.metadata.Deadline) {
		s.owner.removeLocked(s)
		return false
	}
	return true
}
