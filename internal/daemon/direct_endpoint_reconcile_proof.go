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

	"github.com/pagnet-code/pagnet/internal/directchannelcrypto"
	"github.com/pagnet-code/pagnet/internal/directhttp"
	"github.com/pagnet-code/pagnet/transport"
)

var errDirectEndpointReconcileProofMissing = errors.New("direct endpoint retained readiness proof missing")

func reconcileDirectReadinessProof(ctx context.Context, s *DirectEndpointSubscription, registry *NativeWorkerRegistry, observed directEndpointReconcileObservation, publication, challenge []byte, expires time.Time, binding directEnrollmentBinding, local directEnrollmentRecord, material *directchannelcrypto.Material, credentialID, intent, role string, client directEndpointReconcilePassClient, now func() time.Time, operate directEndpointMaterialOperation) (directEndpointReconcilePassState, error) {
	if observed.Enrollment.Proof != nil {
		if len(local.Challenge) == 0 || len(local.Proof) == 0 {
			return "", errDirectEndpointReconcileProofMissing
		}
		if !bytes.Equal(local.Challenge, challenge) {
			return "", errDirectEnrollment
		}
		receipt := observed.Enrollment.Proof
		digest := sha256.Sum256(local.Proof)
		if receipt.Digest != base64.RawURLEncoding.EncodeToString(digest[:]) {
			return "", errDirectEndpointReconcileBinding
		}
		if err := verifyDirectReconcileStoredProof(material, publication, challenge, local.Proof, receipt.ReceivedAt); err != nil {
			return "", err
		}
		material.Clear()
		journal, err := newDirectEnrollmentJournalContext(ctx, registry)
		if err != nil {
			return "", err
		}
		row, err := journal.observeProofContext(ctx, s, binding, digest, receipt.ReceivedAt.UTC().Format(time.RFC3339Nano))
		clear(row.Root)
		if err != nil {
			return "", err
		}
		if err := s.operationCurrentContextError(ctx); err != nil {
			return "", err
		}
		return reconcileDirectActivation(ctx, s, registry, observed, publication, binding, row, credentialID, intent, role, client, now, operate)
	}
	if local.ProofReceivedAt != "" || len(local.Activation) != 0 {
		return "", errDirectEnrollment
	}
	if !now().Before(expires) {
		return "", errDirectEndpointReconcileChallengeExpired
	}
	proofctx, cancel := context.WithDeadline(ctx, expires)
	defer cancel()
	if err := s.operationCurrentContextError(proofctx); err != nil {
		return "", err
	}
	selected := bytes.Clone(local.Proof)
	if len(selected) == 0 {
		var err error
		selected, err = material.ReadinessProof(challenge, credentialID, now())
		if err != nil {
			return "", errDirectEndpointReconcileBinding
		}
	}
	if err := verifyDirectReconcileStoredProof(material, publication, challenge, selected, now()); err != nil {
		return "", err
	}
	material.Clear()
	return submitDirectReconcileProof(proofctx, s, registry, observed, publication, challenge, selected, binding, credentialID, intent, role, client, now, operate)
}

func verifyDirectReconcileStoredProof(material *directchannelcrypto.Material, publication, challenge, proof []byte, at time.Time) error {
	p, err := transport.DecodeDirectChannelPublicationV2(publication)
	if err != nil {
		return errDirectEndpointReconcileBinding
	}
	c, err := transport.DecodeDirectChannelReadinessChallengeV2(challenge)
	if err != nil {
		return errDirectEndpointReconcileBinding
	}
	value, err := transport.DecodeDirectChannelReadinessProofV2(proof)
	if err != nil {
		return errDirectEnrollment
	}
	canonical, err := value.CanonicalBytes()
	if err != nil || !bytes.Equal(canonical, proof) {
		return errDirectEnrollment
	}
	readiness, err := material.ReadinessKey()
	if err != nil {
		return errDirectEnrollment
	}
	defer clear(readiness)
	if transport.VerifyDirectChannelReadinessProofV2(p, c, value, readiness, at) != nil {
		return errDirectEndpointReconcileBinding
	}
	return nil
}

func submitDirectReconcileProof(ctx context.Context, s *DirectEndpointSubscription, registry *NativeWorkerRegistry, observed directEndpointReconcileObservation, publication, challenge, proof []byte, binding directEnrollmentBinding, credentialID, intent, role string, client directEndpointReconcilePassClient, now func() time.Time, operate directEndpointMaterialOperation) (directEndpointReconcilePassState, error) {
	var stagedErr error
	var invoked bool
	var called, repeated atomic.Bool
	operationErr := operate(ctx, func(opctx context.Context, custody endpointMaterial) error {
		if !called.CompareAndSwap(false, true) {
			repeated.Store(true)
			return nil
		}
		attempt := func() error {
			validate := func() error {
				if err := s.operationCurrentContextError(opctx); err != nil {
					return err
				}
				raw, expires, err := validateDirectReconcileEnrollmentReadiness(observed.Binding, publication, role, observed.Enrollment, now())
				if err != nil {
					return err
				}
				if observed.Enrollment.Proof != nil || !bytes.Equal(raw, challenge) {
					return errDirectEndpointReconcileBinding
				}
				if !now().Before(expires) {
					return errDirectEndpointReconcileChallengeExpired
				}
				return validateDirectReconcileMaterialEvidenceContext(opctx, s, observed.Binding, observed.Enrollment, now(), role)
			}
			if err := validate(); err != nil {
				return err
			}
			if len(custody.secret) != 32 {
				return errDirectEndpointOperationRejected
			}
			value, err := transport.DecodeDirectChannelReadinessProofV2(proof)
			if err != nil {
				return errDirectEnrollment
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
			bound, err := journal.bindProofContext(opctx, s, binding, challenge, proof)
			clear(bound.Root)
			if err != nil {
				return err
			}
			recovered, err := journal.observeAbsentContext(opctx, s, binding, "proof")
			clear(recovered.Root)
			if err != nil {
				return err
			}
			if err := validate(); err != nil {
				return err
			}
			dispatch, err := journal.markDispatchContext(opctx, s, binding, "proof")
			clear(dispatch.Root)
			if err != nil {
				return err
			}
			if !bytes.Equal(dispatch.Publication, publication) || !bytes.Equal(dispatch.Challenge, challenge) || !bytes.Equal(dispatch.Proof, proof) || dispatch.ProofReceivedAt != "" {
				return errDirectEnrollment
			}
			if err := validate(); err != nil {
				return err
			}
			invoked = true
			response, err := client.Prove(opctx, credential, intent, value)
			if err != nil {
				return sanitizeDirectReconcileMutationError(err)
			}
			raw, err := response.CanonicalBytes()
			if err != nil || !bytes.Equal(raw, proof) {
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
	return directReconcileProofSubmitted, nil
}
