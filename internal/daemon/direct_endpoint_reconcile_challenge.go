//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sync/atomic"
	"time"

	"github.com/pagnet-code/pagnet/internal/directhttp"
	"github.com/pagnet-code/pagnet/transport"
)

var errDirectEndpointReconcileChallengeExpired = errors.New("direct endpoint readiness challenge expired")

// Expiry relative to observation time is intentionally permitted here. An
// authenticated GET may reveal an expired immutable challenge; retain it before
// reporting expiry so a later absence can never authorize renewal.
func validateDirectReconcileChallengeBinding(b directEndpointReconcileBinding, publication []byte, role string, c transport.DirectChannelReadinessChallengeV2, observedAt time.Time) ([]byte, time.Time, error) {
	reject := func() ([]byte, time.Time, error) { return nil, time.Time{}, errDirectEndpointReconcileBinding }
	if (role != "S" && role != "P") || observedAt.IsZero() {
		return reject()
	}
	descriptor, err := b.Descriptor.CanonicalBytes()
	if err != nil || !bytes.Equal(descriptor, b.DescriptorBytes) || sha256.Sum256(descriptor) != b.DescriptorHash {
		return reject()
	}
	p, err := transport.DecodeDirectChannelPublicationV2(publication)
	if err != nil || !b.publicationMatches(p) {
		return reject()
	}
	raw, err := c.CanonicalBytes()
	if err != nil {
		return reject()
	}
	local := b.Descriptor.S
	if role == "P" {
		local = b.Descriptor.P
	}
	channel, err := transport.DirectChannelIDV2(b.Descriptor)
	if err != nil {
		return reject()
	}
	publicationHash := sha256.Sum256(publication)
	issued, _ := time.Parse(time.RFC3339Nano, c.IssuedAt)
	expires, _ := time.Parse(time.RFC3339Nano, c.ExpiresAt)
	descriptorExpiry, _ := time.Parse(time.RFC3339Nano, b.Descriptor.ExpiresAt)
	if c.Role != role || c.PrincipalID != local.PrincipalID || c.EndpointID != local.EndpointID || c.CredentialID != local.CredentialID || c.DirectIntentID != b.Descriptor.DirectIntentID || c.ChannelID != channel || c.ParentGrantID != b.Descriptor.ParentGrantID || c.GrantGeneration != b.Descriptor.GrantGeneration || c.ChannelGeneration != b.Descriptor.ChannelGeneration || c.EpochID != b.Descriptor.EpochID || c.DescriptorHash != base64.RawURLEncoding.EncodeToString(b.DescriptorHash[:]) || c.PublicationHash != base64.RawURLEncoding.EncodeToString(publicationHash[:]) || issued.After(observedAt) || expires.After(descriptorExpiry) {
		return reject()
	}
	return raw, expires, nil
}

func reconcileDirectReadinessChallenge(ctx context.Context, s *DirectEndpointSubscription, registry *NativeWorkerRegistry, observed directEndpointReconcileObservation, publication []byte, binding directEnrollmentBinding, local directEnrollmentRecord, credentialID, intent, role string, client directEndpointReconcilePassClient, now func() time.Time, operate directEndpointMaterialOperation) (directEndpointReconcilePassState, error) {
	if err := validateDirectReconcileMaterialEvidenceContext(ctx, s, observed.Binding, observed.Enrollment, now(), role); err != nil {
		return "", err
	}
	e := observed.Enrollment
	if e.Challenge != nil {
		raw, expires, err := validateDirectReconcileChallengeBinding(observed.Binding, publication, role, e.Challenge.Challenge, e.ObservedAt)
		transcript := sha256.Sum256(raw)
		if err != nil || e.Challenge.TranscriptHash != base64.RawURLEncoding.EncodeToString(transcript[:]) {
			return "", errDirectEndpointReconcileBinding
		}
		journal, err := newDirectEnrollmentJournalContext(ctx, registry)
		if err != nil {
			return "", err
		}
		row, err := journal.observeChallengeContext(ctx, s, binding, raw)
		clear(row.Root)
		if err != nil {
			return "", err
		}
		if err := s.operationCurrentContextError(ctx); err != nil {
			return "", err
		}
		if !now().Before(expires) {
			return "", errDirectEndpointReconcileChallengeExpired
		}
		return directReconcileChallengeObserved, nil
	}
	if e.Proof != nil || e.Activation != nil {
		return "", errDirectEndpointReconcileBinding
	}
	if len(local.Challenge) != 0 || len(local.Proof) != 0 || local.ProofReceivedAt != "" || len(local.Activation) != 0 || local.ProofStarted {
		return "", errDirectEnrollment
	}
	return requestDirectReconcileChallenge(ctx, s, registry, observed, publication, binding, credentialID, intent, role, client, now, operate)
}

func requestDirectReconcileChallenge(ctx context.Context, s *DirectEndpointSubscription, registry *NativeWorkerRegistry, observed directEndpointReconcileObservation, publication []byte, binding directEnrollmentBinding, credentialID, intent, role string, client directEndpointReconcilePassClient, now func() time.Time, operate directEndpointMaterialOperation) (directEndpointReconcilePassState, error) {
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
			if err := validateDirectReconcileMaterialEvidenceContext(opctx, s, observed.Binding, observed.Enrollment, now(), role); err != nil {
				return err
			}
			if observed.Enrollment.PublicationHash == nil || observed.Enrollment.Challenge != nil || observed.Enrollment.Proof != nil || observed.Enrollment.Activation != nil || len(custody.secret) != 32 {
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
			recovered, err := journal.observeAbsentContext(opctx, s, binding, "challenge")
			clear(recovered.Root)
			if err != nil {
				return err
			}
			if err := validateDirectReconcileMaterialEvidenceContext(opctx, s, observed.Binding, observed.Enrollment, now(), role); err != nil {
				return err
			}
			dispatch, err := journal.markDispatchContext(opctx, s, binding, "challenge")
			clear(dispatch.Root)
			if err != nil {
				return err
			}
			if !bytes.Equal(dispatch.Publication, publication) || len(dispatch.Challenge) != 0 || len(dispatch.Proof) != 0 || dispatch.ProofReceivedAt != "" || len(dispatch.Activation) != 0 {
				return errDirectEnrollment
			}
			if err := s.operationCurrentContextError(opctx); err != nil {
				return err
			}
			if err := validateDirectReconcileMaterialEvidenceContext(opctx, s, observed.Binding, observed.Enrollment, now(), role); err != nil {
				return err
			}
			invoked = true
			challenge, err := client.Challenge(opctx, credential, intent)
			if err != nil {
				return sanitizeDirectReconcileMutationError(err)
			}
			receivedAt := now()
			_, expires, err := validateDirectReconcileChallengeBinding(observed.Binding, publication, role, challenge, receivedAt)
			if err != nil || !receivedAt.Before(expires) {
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
	return directReconcileChallengeRequested, nil
}
