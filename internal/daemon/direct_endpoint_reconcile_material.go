//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"time"

	"github.com/pagnet-code/pagnet/internal/directchannelcrypto"
	"github.com/pagnet-code/pagnet/internal/directhttp"
	"github.com/pagnet-code/pagnet/transport"
)

var errDirectEndpointReconcileSourceRootMissing = errors.New("direct endpoint reconcile source root missing")

// directEndpointMaterialOperation must invoke use synchronously, at most once,
// with custody owned by the operation. Success must include acceptance against
// the exact subscription's live lease after use returns. No production adapter
// is installed here. The callback must not retain endpoint custody.
type directEndpointMaterialOperation func(context.Context, func(context.Context, endpointMaterial) error) error

func acquireDirectSourceReconcileMaterial(ctx context.Context, s *DirectEndpointSubscription, b directEndpointReconcileBinding, e directhttp.Enrollment, registry *NativeWorkerRegistry, now func() time.Time, operate directEndpointMaterialOperation) (*directchannelcrypto.Material, []byte, error) {
	return acquireDirectEndpointReconcileMaterial(ctx, s, b, e, nil, registry, now, operate, "S")
}

func acquireDirectTargetReconcileMaterial(ctx context.Context, s *DirectEndpointSubscription, b directEndpointReconcileBinding, e directhttp.Enrollment, publication []byte, registry *NativeWorkerRegistry, now func() time.Time, operate directEndpointMaterialOperation) (*directchannelcrypto.Material, []byte, error) {
	return acquireDirectEndpointReconcileMaterial(ctx, s, b, e, bytes.Clone(publication), registry, now, operate, "P")
}

// Each attempt opens a fresh journal. An uncertain COMMIT ends this attempt;
// only a fresh attempt may discover committed material or a confirmed rollback.
// Once means one committed candidate; a rolled back candidate may be replaced.
func acquireDirectEndpointReconcileMaterial(ctx context.Context, s *DirectEndpointSubscription, b directEndpointReconcileBinding, e directhttp.Enrollment, publication []byte, registry *NativeWorkerRegistry, now func() time.Time, operate directEndpointMaterialOperation, role string) (result *directchannelcrypto.Material, wire []byte, err error) {
	var pending *directchannelcrypto.Material
	accepted := false
	defer func() {
		if recover() != nil {
			err = errDirectEndpointOperationUnknown
		}
		if !accepted || err != nil {
			if pending != nil {
				pending.Clear()
			}
			result, wire = nil, nil
		}
	}()
	if ctx == nil || s == nil || s.owner == nil || registry == nil || now == nil || operate == nil {
		return nil, nil, errDirectEndpointOperationRejected
	}
	var stagedErr error
	called := false
	repeated := false
	err = operate(ctx, func(opctx context.Context, custody endpointMaterial) error {
		if called {
			repeated = true
			return nil
		}
		called = true
		// Keep local failures separate so the operation accepts the exact lease.
		stagedErr = func() error {
			if err := s.operationCurrentContextError(opctx); err != nil {
				return err
			}
			if err := validateDirectReconcileMaterialEvidenceContext(opctx, s, b, e, now(), role); err != nil {
				return err
			}
			if role == "P" {
				p, decodeErr := transport.DecodeDirectChannelPublicationV2(publication)
				if decodeErr != nil || !b.publicationMatches(p) || !reconcilePublicationHash(e, publication) {
					return errDirectEndpointReconcileBinding
				}
			}
			binding, bindingErr := enrollmentBinding(s, b.Protocol, b.DescriptorBytes, b.LocalFingerprint, b.PeerFingerprint)
			if bindingErr != nil {
				return bindingErr
			}
			journal, journalErr := newDirectEnrollmentJournalContext(opctx, registry)
			if journalErr != nil {
				return journalErr
			}
			retained, reserveErr := journal.reserveContext(opctx, s, binding)
			defer func() { clear(retained.Root) }()
			if reserveErr != nil {
				return reserveErr
			}
			// A source can only recover an already published root from local retention.
			if role == "S" && e.PublicationHash != nil && retained.State != "material" {
				return errDirectEndpointReconcileSourceRootMissing
			}
			row, materialErr := journal.materialContext(opctx, s, binding, func() ([]byte, []byte, error) {
				// This generator runs inside the journal transaction: local crypto only.
				var candidate *directchannelcrypto.Material
				var raw []byte
				var cryptoErr error
				if role == "S" {
					candidate, raw, cryptoErr = directchannelcrypto.Prepare(b.DescriptorBytes, b.Descriptor, custody.private, now())
				} else {
					raw = publication
					candidate, cryptoErr = directchannelcrypto.Accept(raw, b.Descriptor, custody.private, now())
				}
				if candidate != nil {
					defer candidate.Clear()
				}
				if cryptoErr != nil {
					return nil, nil, cryptoErr
				}
				return bytes.Clone(candidate.Key[:]), raw, nil
			})
			defer func() { clear(row.Root) }()
			if materialErr != nil {
				return materialErr
			}
			p, decodeErr := transport.DecodeDirectChannelPublicationV2(row.Publication)
			if decodeErr != nil || len(row.Root) != 32 || !b.publicationMatches(p) || (e.PublicationHash != nil && !reconcilePublicationHash(e, row.Publication)) || (role == "P" && !bytes.Equal(publication, row.Publication)) {
				return errDirectEnrollment
			}
			if err := s.operationCurrentContextError(opctx); err != nil {
				return err
			}
			if err := validateDirectReconcileMaterialEvidenceContext(opctx, s, b, e, now(), role); err != nil {
				return err
			}
			pending = &directchannelcrypto.Material{Descriptor: b.Descriptor, Hash: b.DescriptorHash, Role: role, PublicationHash: sha256.Sum256(row.Publication)}
			copy(pending.Key[:], row.Root)
			wire = bytes.Clone(row.Publication)
			return nil
		}()
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	if err := s.operationCurrentContextError(ctx); err != nil {
		return nil, nil, err
	}
	if !called || repeated {
		return nil, nil, errDirectEndpointOperationRejected
	}
	if stagedErr != nil {
		return nil, nil, stagedErr
	}
	if pending == nil {
		return nil, nil, errDirectEndpointOperationRejected
	}
	accepted = true
	return pending, wire, nil
}

func reconcilePublicationHash(e directhttp.Enrollment, raw []byte) bool {
	hash := sha256.Sum256(raw)
	return e.PublicationHash != nil && *e.PublicationHash == base64.RawURLEncoding.EncodeToString(hash[:])
}

// Recheck public binding evidence inside the accepted material-use operation.
// Authentication of GET responses and the original issue binding are prerequisites.
func validateDirectReconcileMaterialEvidence(s *DirectEndpointSubscription, b directEndpointReconcileBinding, e directhttp.Enrollment, now time.Time, role string) error {
	return validateDirectReconcileMaterialEvidenceContext(context.Background(), s, b, e, now, role)
}

func validateDirectReconcileMaterialEvidenceContext(ctx context.Context, s *DirectEndpointSubscription, b directEndpointReconcileBinding, e directhttp.Enrollment, now time.Time, role string) error {
	if err := directReconcileBindingCurrentContext(ctx, s); err != nil {
		return err
	}

	raw, err := b.Descriptor.CanonicalBytes()
	hash := sha256.Sum256(raw)
	d := b.Descriptor
	expires, _ := time.Parse(time.RFC3339Nano, d.ExpiresAt)
	channel, _ := transport.DirectChannelIDV2(d)
	a := e.Authority
	local, peer := d.S, d.P
	protocol := directManagedSourceCredentialProtocolV2
	if role == "P" {
		local, peer = d.P, d.S
		protocol = managedDirectCredentialProtocolV1
	}
	localKey, le := base64.RawURLEncoding.Strict().DecodeString(local.PublicKey)
	peerKey, pe := base64.RawURLEncoding.Strict().DecodeString(peer.PublicKey)
	if err != nil || now.IsZero() || transport.ValidateDirectChannelDescriptorV2(d, now) != nil || !bytes.Equal(raw, b.DescriptorBytes) || hash != b.DescriptorHash || b.Protocol != protocol || s.binding.metadata.Role != role || le != nil || pe != nil || sha256.Sum256(localKey) != b.LocalFingerprint || sha256.Sum256(peerKey) != b.PeerFingerprint || e.DescriptorHash != base64.RawURLEncoding.EncodeToString(hash[:]) || a != b.Authority || a.ParentGrantID != d.ParentGrantID || a.GrantGeneration != d.GrantGeneration || a.ChannelID != channel || a.ChannelGeneration != d.ChannelGeneration || a.EpochID != d.EpochID || !a.ExpiresAt.Equal(expires) || e.ObservedAt.IsZero() || e.ObservedAt.After(now) || !e.ObservedAt.Before(expires) {
		return errDirectEndpointReconcileBinding
	}
	if _, err := enrollmentBinding(s, b.Protocol, raw, b.LocalFingerprint, b.PeerFingerprint); err != nil {
		return err
	}
	return directReconcileBindingCurrentContext(ctx, s)
}
