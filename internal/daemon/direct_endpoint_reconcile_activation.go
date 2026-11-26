//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"sync/atomic"
	"time"

	"github.com/pagnet-code/pagnet/internal/directhttp"
)

func reconcileDirectActivation(ctx context.Context, s *DirectEndpointSubscription, registry *NativeWorkerRegistry, observed directEndpointReconcileObservation, publication []byte, binding directEnrollmentBinding, local directEnrollmentRecord, credentialID, intent, role string, client directEndpointReconcilePassClient, now func() time.Time, operate directEndpointMaterialOperation) (directEndpointReconcilePassState, error) {
	if err := validateDirectReconcileMaterialEvidenceContext(ctx, s, observed.Binding, observed.Enrollment, now(), role); err != nil {
		return "", err
	}
	if _, _, err := validateDirectReconcileEnrollmentReadiness(observed.Binding, publication, role, observed.Enrollment, now()); err != nil {
		return "", err
	}
	e := observed.Enrollment
	if e.Proof == nil || e.Challenge == nil || e.PublicationHash == nil {
		return "", errDirectEndpointReconcileBinding
	}
	if e.Activation != nil {
		value := directhttp.Activation{ChannelID: e.Authority.ChannelID, ActivatedAt: e.Activation.ActivatedAt, ExpiresAt: e.Activation.ExpiresAt}
		if err := validateDirectReconcileActivation(observed.Binding, e, value, e.ObservedAt); err != nil {
			return "", err
		}
		journal, err := newDirectEnrollmentJournalContext(ctx, registry)
		if err != nil {
			return "", err
		}
		row, err := journal.observeActivationContext(ctx, s, binding, value.ChannelID, value.ActivatedAt.UTC().Format(time.RFC3339Nano), value.ExpiresAt.UTC().Format(time.RFC3339Nano))
		clear(row.Root)
		if err != nil {
			return "", err
		}
		if err := s.operationCurrentContextError(ctx); err != nil {
			return "", err
		}
		return directReconcileActivationObserved, nil
	}
	if len(local.Activation) != 0 || len(local.ActivationHash) != 0 {
		return "", errDirectEnrollment
	}
	return requestDirectReconcileActivation(ctx, s, registry, observed, publication, binding, credentialID, intent, role, client, now, operate)
}

func directReconcileActivationJournalMatches(row directEnrollmentRecord, observed directEndpointReconcileObservation, publication, challenge []byte) bool {
	receipt := observed.Enrollment.Proof
	if receipt == nil {
		return false
	}
	digest := sha256.Sum256(row.Proof)
	return row.State == "material" && row.PublicationObserved && bytes.Equal(row.Publication, publication) && bytes.Equal(row.Challenge, challenge) && len(row.Proof) > 0 && row.ProofReceivedAt == receipt.ReceivedAt.UTC().Format(time.RFC3339Nano) && receipt.Digest == base64.RawURLEncoding.EncodeToString(digest[:]) && len(row.Activation) == 0 && len(row.ActivationHash) == 0
}

func requestDirectReconcileActivation(ctx context.Context, s *DirectEndpointSubscription, registry *NativeWorkerRegistry, observed directEndpointReconcileObservation, publication []byte, binding directEnrollmentBinding, credentialID, intent, role string, client directEndpointReconcilePassClient, now func() time.Time, operate directEndpointMaterialOperation) (directEndpointReconcilePassState, error) {
	var stagedErr error
	var invoked bool
	var called, repeated atomic.Bool
	operationErr := operate(ctx, func(opctx context.Context, custody endpointMaterial) error {
		if !called.CompareAndSwap(false, true) {
			repeated.Store(true)
			return nil
		}
		attempt := func() error {
			validate := func() ([]byte, error) {
				if err := s.operationCurrentContextError(opctx); err != nil {
					return nil, err
				}
				if err := validateDirectReconcileMaterialEvidenceContext(opctx, s, observed.Binding, observed.Enrollment, now(), role); err != nil {
					return nil, err
				}
				challenge, _, err := validateDirectReconcileEnrollmentReadiness(observed.Binding, publication, role, observed.Enrollment, now())
				if err != nil {
					return nil, err
				}
				if observed.Enrollment.PublicationHash == nil || observed.Enrollment.Challenge == nil || observed.Enrollment.Proof == nil || observed.Enrollment.Activation != nil {
					return nil, errDirectEndpointReconcileBinding
				}
				return challenge, nil
			}
			challenge, err := validate()
			if err != nil {
				return err
			}
			if len(custody.secret) != 32 {
				return errDirectEndpointOperationRejected
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
			recovered, err := journal.observeAbsentContext(opctx, s, binding, "activation")
			clear(recovered.Root)
			if err != nil {
				return err
			}
			if !directReconcileActivationJournalMatches(recovered, observed, publication, challenge) {
				return errDirectEnrollment
			}
			if _, err := validate(); err != nil {
				return err
			}
			dispatch, err := journal.markDispatchContext(opctx, s, binding, "activation")
			clear(dispatch.Root)
			if err != nil {
				return err
			}
			if !directReconcileActivationJournalMatches(dispatch, observed, publication, challenge) {
				return errDirectEnrollment
			}
			if _, err := validate(); err != nil {
				return err
			}
			invoked = true
			response, err := client.Activate(opctx, credential, intent)
			if err != nil {
				return sanitizeDirectReconcileMutationError(err)
			}
			if validateDirectReconcileActivation(observed.Binding, observed.Enrollment, response, now()) != nil {
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
	return directReconcileActivationRequested, nil
}
