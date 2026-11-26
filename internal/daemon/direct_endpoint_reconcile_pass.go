//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pagnet-code/pagnet/internal/directchannelcrypto"
	"github.com/pagnet-code/pagnet/internal/directhttp"
	"github.com/pagnet-code/pagnet/transport"
)

type directEndpointReconcilePassState string

const (
	directReconcileAwaitingPublication  directEndpointReconcilePassState = "awaiting_publication"
	directReconcilePublicationObserved  directEndpointReconcilePassState = "publication_observed"
	directReconcilePublicationPublished directEndpointReconcilePassState = "publication_published"
	directReconcileChallengeRequested   directEndpointReconcilePassState = "challenge_requested"
	directReconcileChallengeObserved    directEndpointReconcilePassState = "challenge_observed"
)

type directEndpointReconcilePass func(context.Context) (directEndpointReconcilePassState, error)
type directEndpointReconcilePassClient interface {
	directEndpointReconcileReader
	Publish(context.Context, string, string, transport.DirectChannelPublicationV2, string) (transport.DirectChannelPublicationV2, error)
	Challenge(context.Context, string, string) (transport.DirectChannelReadinessChallengeV2, error)
}

func newDirectSourceReconcilePass(d *Daemon, captured ManagedEndpointPrepareScope, s *DirectEndpointSubscription, issue transport.DirectManagedSourceCredentialIssueV2) (directEndpointReconcilePass, error) {
	return newDirectSourceReconcilePassWithClient(d, captured, s, issue, nil, time.Now)
}
func newDirectSourceReconcilePassWithClient(d *Daemon, captured ManagedEndpointPrepareScope, s *DirectEndpointSubscription, issue transport.DirectManagedSourceCredentialIssueV2, client directEndpointReconcilePassClient, now func() time.Time) (directEndpointReconcilePass, error) {
	raw, err := issue.CanonicalBytes()
	if err != nil {
		return nil, errDirectEndpointOperationRejected
	}
	owned, err := transport.DecodeDirectManagedSourceCredentialIssueV2(raw)
	if err != nil {
		return nil, errDirectEndpointOperationRejected
	}
	if d == nil || d.nativeRegistry == nil {
		return nil, errDirectEndpointOperationRejected
	}
	origin := owned.PoP.ACK.Reservation.ServerURL
	client, err = directReconcilePassClient(origin, client)
	if err != nil {
		return nil, err
	}
	observe, err := newDirectSourceReconcileObserverWithReader(d, captured, s, owned, client, now)
	if err != nil {
		return nil, err
	}
	operate, err := newDirectSourceReconcileOperation(d, captured, s, owned)
	if err != nil {
		return nil, err
	}
	return newDirectReconcilePass(s, d.nativeRegistry, origin, string(owned.CredentialID), string(owned.PoP.Prepare.Subject.DirectIntentID), "S", observe, operate, client, now), nil
}
func newDirectTargetReconcilePass(d *Daemon, captured ManagedEndpointPrepareScope, s *DirectEndpointSubscription, issue transport.ManagedDirectCredentialIssue) (directEndpointReconcilePass, error) {
	return newDirectTargetReconcilePassWithClient(d, captured, s, issue, nil, time.Now)
}
func newDirectTargetReconcilePassWithClient(d *Daemon, captured ManagedEndpointPrepareScope, s *DirectEndpointSubscription, issue transport.ManagedDirectCredentialIssue, client directEndpointReconcilePassClient, now func() time.Time) (directEndpointReconcilePass, error) {
	raw, err := issue.CanonicalBytes()
	if err != nil {
		return nil, errDirectEndpointOperationRejected
	}
	owned, err := transport.DecodeManagedDirectCredentialIssue(raw)
	if err != nil {
		return nil, errDirectEndpointOperationRejected
	}
	if d == nil || d.nativeRegistry == nil {
		return nil, errDirectEndpointOperationRejected
	}
	origin := owned.PoP.ACK.Reservation.ServerURL
	client, err = directReconcilePassClient(origin, client)
	if err != nil {
		return nil, err
	}
	observe, err := newDirectTargetReconcileObserverWithReader(d, captured, s, owned, client, now)
	if err != nil {
		return nil, err
	}
	operate, err := newDirectTargetReconcileOperation(d, captured, s, owned)
	if err != nil {
		return nil, err
	}
	return newDirectReconcilePass(s, d.nativeRegistry, origin, string(owned.CredentialID), string(owned.PoP.Prepare.Subject.DirectIntentID), "P", observe, operate, client, now), nil
}
func directReconcilePassClient(origin string, client directEndpointReconcilePassClient) (directEndpointReconcilePassClient, error) {
	pinned, err := directhttp.New(origin)
	if err != nil {
		return nil, sanitizeDirectReconcileReadError(err)
	}
	if client != nil {
		return client, nil
	}
	return pinned, nil
}

// Each invocation starts with accepted authenticated GET evidence and performs
// at most one remote mutation (PUT or POST). There is no scheduler, activation
// hook or automatic retry.
func newDirectReconcilePass(s *DirectEndpointSubscription, registry *NativeWorkerRegistry, origin, credentialID, intent, role string, observe directEndpointReconcileObserver, operate directEndpointMaterialOperation, client directEndpointReconcilePassClient, now func() time.Time) directEndpointReconcilePass {
	var active sync.Mutex
	return func(ctx context.Context) (state directEndpointReconcilePassState, err error) {
		defer func() {
			if recover() != nil {
				err = errDirectEndpointOperationUnknown
			}
			if err != nil {
				state = ""
			}
		}()
		if ctx == nil || s == nil || registry == nil || observe == nil || operate == nil || client == nil || now == nil {
			return "", errDirectEndpointOperationRejected
		}
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if !active.TryLock() {
			return "", errDirectEndpointLocalBusy
		}
		defer active.Unlock()
		if s.binding.metadata.ServerOrigin != origin {
			return "", errDirectEndpointOperationRejected
		}
		if err := s.operationCurrentContextError(ctx); err != nil {
			return "", err
		}
		passctx, cancel := context.WithDeadline(ctx, s.binding.metadata.Deadline)
		watcherDone := make(chan struct{})
		go func() {
			defer close(watcherDone)
			select {
			case <-s.Done():
				cancel()
			case <-s.AbortDone():
				cancel()
			case <-passctx.Done():
			}
		}()
		defer func() { cancel(); <-watcherDone }()
		observed, err := observe(passctx)
		if err != nil {
			return "", err
		}
		if err := s.operationCurrentContextError(passctx); err != nil {
			return "", err
		}
		if (observed.Enrollment.Challenge == nil && (observed.Enrollment.Proof != nil || observed.Enrollment.Activation != nil)) || (observed.Enrollment.PublicationHash == nil && observed.Enrollment.Challenge != nil) || (observed.Enrollment.Activation != nil && observed.Enrollment.Proof == nil) {
			return "", errDirectEndpointReconcileBinding
		}
		if role == "P" && observed.Enrollment.PublicationHash == nil {
			return directReconcileAwaitingPublication, nil
		}
		expires, err := time.Parse(time.RFC3339Nano, observed.Binding.Descriptor.ExpiresAt)
		if err != nil {
			return "", errDirectEndpointReconcileBinding
		}
		workctx, stopWork := context.WithDeadline(passctx, expires)
		defer stopWork()
		if err := s.operationCurrentContextError(workctx); err != nil {
			return "", err
		}
		var material *directchannelcrypto.Material
		var wire []byte
		if role == "S" {
			material, wire, err = acquireDirectSourceReconcileMaterial(workctx, s, observed.Binding, observed.Enrollment, registry, now, operate)
		} else {
			material, wire, err = acquireDirectTargetReconcileMaterial(workctx, s, observed.Binding, observed.Enrollment, observed.Publication, registry, now, operate)
		}
		if err != nil {
			return "", err
		}
		defer material.Clear()
		binding, err := enrollmentBinding(s, observed.Binding.Protocol, observed.Binding.DescriptorBytes, observed.Binding.LocalFingerprint, observed.Binding.PeerFingerprint)
		if err != nil {
			return "", err
		}
		if observed.Enrollment.PublicationHash != nil {
			journal, err := newDirectEnrollmentJournalContext(workctx, registry)
			if err != nil {
				return "", err
			}
			row, err := journal.observePublicationContext(workctx, s, binding, sha256.Sum256(wire))
			clear(row.Root)
			if err != nil {
				return "", err
			}
			if err := s.operationCurrentContextError(workctx); err != nil {
				return "", err
			}
			material.Clear()
			return reconcileDirectReadinessChallenge(workctx, s, registry, observed, wire, binding, row, credentialID, intent, role, client, now, operate)
		}
		readiness, err := material.ReadinessKey()
		if err != nil {
			return "", errDirectEnrollment
		}
		defer clear(readiness)
		verifier := base64.RawURLEncoding.EncodeToString(readiness)
		clear(readiness)
		material.Clear()
		return publishDirectReconcilePublication(workctx, s, registry, observed, wire, binding, credentialID, intent, verifier, client, now, operate)
	}
}

func publishDirectReconcilePublication(ctx context.Context, s *DirectEndpointSubscription, registry *NativeWorkerRegistry, observed directEndpointReconcileObservation, wire []byte, binding directEnrollmentBinding, credentialID, intent, verifier string, client directEndpointReconcilePassClient, now func() time.Time, operate directEndpointMaterialOperation) (directEndpointReconcilePassState, error) {
	var stagedErr error
	var invoked bool
	var called, repeated atomic.Bool
	operationErr := operate(ctx, func(opctx context.Context, custody endpointMaterial) error {
		if !called.CompareAndSwap(false, true) {
			repeated.Store(true)
			return nil
		}
		attempt := func() error {
			if err := s.operationCurrentContextError(opctx); err != nil {
				return err
			}
			if err := validateDirectReconcileMaterialEvidenceContext(opctx, s, observed.Binding, observed.Enrollment, now(), "S"); err != nil {
				return err
			}
			if observed.Enrollment.PublicationHash != nil || len(custody.secret) != 32 {
				return errDirectEndpointOperationRejected
			}
			publication, err := transport.DecodeDirectChannelPublicationV2(wire)
			if err != nil || !observed.Binding.publicationMatches(publication) {
				return errDirectEndpointReconcileBinding
			}
			credentialBytes := make([]byte, len(credentialID)+1+base64.RawURLEncoding.EncodedLen(32))
			defer clear(credentialBytes)
			copy(credentialBytes, credentialID)
			credentialBytes[len(credentialID)] = ':'
			base64.RawURLEncoding.Encode(credentialBytes[len(credentialID)+1:], custody.secret)
			credential := string(credentialBytes)
			clear(credentialBytes)
			journal, err := newDirectEnrollmentJournalContext(opctx, registry)
			if err != nil {
				return err
			}
			recovered, err := journal.observeAbsentContext(opctx, s, binding, "publication")
			clear(recovered.Root)
			if err != nil {
				return err
			}
			if err := validateDirectReconcileMaterialEvidenceContext(opctx, s, observed.Binding, observed.Enrollment, now(), "S"); err != nil {
				return err
			}
			dispatch, err := journal.markDispatchContext(opctx, s, binding, "publication")
			clear(dispatch.Root)
			if err != nil {
				return err
			}
			if !bytes.Equal(dispatch.Publication, wire) || dispatch.PublicationHash != sha256.Sum256(wire) {
				return errDirectEnrollment
			}
			if err := s.operationCurrentContextError(opctx); err != nil {
				return err
			}
			if err := validateDirectReconcileMaterialEvidenceContext(opctx, s, observed.Binding, observed.Enrollment, now(), "S"); err != nil {
				return err
			}
			invoked = true
			response, err := client.Publish(opctx, credential, intent, publication, verifier)
			if err != nil {
				return sanitizeDirectReconcileMutationError(err)
			}
			responseBytes, err := response.CanonicalBytes()
			if err != nil || !bytes.Equal(responseBytes, wire) {
				return &directhttp.Error{Kind: directhttp.Protocol, UnknownCommit: true}
			}
			return nil
		}
		stagedErr = attempt()
		return nil
	})
	if operationErr != nil {
		return "", operationErr
	}
	if err := s.operationCurrentContextError(ctx); err != nil {
		if invoked {
			return "", errDirectEndpointOperationUnknown
		}
		return "", err
	}
	if !called.Load() || repeated.Load() {
		if invoked {
			return "", errDirectEndpointOperationUnknown
		}
		return "", errDirectEndpointOperationRejected
	}
	if stagedErr != nil {
		return "", stagedErr
	}
	if !invoked {
		return "", errDirectEndpointOperationRejected
	}
	return directReconcilePublicationPublished, nil
}
func sanitizeDirectReconcileMutationError(err error) error {
	var wire *directhttp.Error
	if errors.As(err, &wire) {
		switch wire.Kind {
		case directhttp.Invalid, directhttp.Unauthorized, directhttp.Unavailable, directhttp.Conflict, directhttp.TooLarge, directhttp.ServiceUnavailable, directhttp.Protocol, directhttp.Transport:
			status := wire.Status
			if status < 100 || status > 599 {
				status = 0
			}
			return &directhttp.Error{Kind: wire.Kind, Status: status, UnknownCommit: wire.UnknownCommit}
		}
	}
	return errDirectEndpointOperationUnknown
}
