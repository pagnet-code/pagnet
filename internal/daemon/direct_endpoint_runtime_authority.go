//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"encoding/base64"
	"sync"
	"time"

	"github.com/pagnet-code/pagnet/transport"
)

type directRuntimeAuthority func(context.Context, directRuntimeBinding, func(context.Context, string) error) error

// newDirectTargetRuntimeAuthority is dormant: it neither attaches a controller
// nor enables delivery. Admission and recovery must construct a fresh adapter,
// authenticating the publication and revalidating the durable consent revision.
func newDirectTargetRuntimeAuthority(ctx context.Context, d *Daemon, captured ManagedEndpointPrepareScope, sub *DirectEndpointSubscription, issue transport.ManagedDirectCredentialIssue, store *directChannelConsentStore, revision int64) (directRuntimeAuthority, error) {
	return newDirectTargetRuntimeAuthorityWithReader(ctx, d, captured, sub, issue, store, revision, nil)
}

func newDirectTargetRuntimeAuthorityWithReader(ctx context.Context, d *Daemon, captured ManagedEndpointPrepareScope, sub *DirectEndpointSubscription, issue transport.ManagedDirectCredentialIssue, store *directChannelConsentStore, revision int64, reader directEndpointReconcileReader) (directRuntimeAuthority, error) {
	if ctx == nil || store == nil || revision <= 0 {
		return nil, errDirectRuntimeRejected
	}
	raw, err := issue.CanonicalBytes()
	if err != nil {
		return nil, errDirectRuntimeRejected
	}
	captured, err = ownDirectReconcileOperationScope(d, captured, sub, raw, "P", store.installation)
	if err != nil {
		return nil, err
	}
	owned, err := transport.DecodeManagedDirectCredentialIssue(raw)
	if err != nil {
		return nil, errDirectRuntimeRejected
	}
	var observe directEndpointReconcileObserver
	if reader == nil {
		observe, err = newDirectTargetReconcileObserver(d, captured, sub, owned)
	} else {
		observe, err = newDirectTargetReconcileObserverWithReader(d, captured, sub, owned, reader, time.Now)
	}
	if err != nil {
		return nil, err
	}
	check := func(ctx context.Context) (directRuntimeBinding, error) {
		observed, err := observe(ctx)
		if err != nil {
			return directRuntimeBinding{}, err
		}
		binding, err := directRuntimeBindingFromObservation(sub, observed, revision)
		if err != nil {
			return directRuntimeBinding{}, err
		}
		consent, err := deriveDirectChannelConsentBinding(sub, captured, store.installation, observed.Binding, time.Now())
		if err != nil {
			return directRuntimeBinding{}, err
		}
		record, err := store.Get(ctx, consent.Key)
		if err != nil {
			return directRuntimeBinding{}, err
		}
		if err = validateDirectChannelConsentEligibility(record, revision, sub, captured, store.installation, observed.Binding, time.Now()); err != nil {
			return directRuntimeBinding{}, err
		}
		if err = d.registerDirectChannelConsentLease(ctx, store, consent.Key, revision, sub, captured, observed.Binding); err != nil {
			return directRuntimeBinding{}, err
		}
		return binding, nil
	}
	expected, err := check(ctx)
	if err != nil {
		return nil, err
	}
	var active sync.Mutex
	return func(ctx context.Context, binding directRuntimeBinding, use func(context.Context, string) error) error {
		if ctx == nil || use == nil || !active.TryLock() {
			return errDirectRuntimeRejected
		}
		defer active.Unlock()
		if !directRuntimeAuthorityBindingEqual(expected, binding) {
			return errDirectRuntimeRejected
		}
		current, err := check(ctx)
		if err != nil {
			return err
		}
		if !directRuntimeAuthorityBindingEqual(expected, current) {
			return errDirectRuntimeRejected
		}
		snapshot, err := transport.DecodeManagedDirectCredentialIssue(raw)
		if err != nil {
			return errDirectRuntimeRejected
		}
		return d.operateManagedTargetEndpoint(ctx, captured, sub, snapshot, func(opctx context.Context, material endpointMaterial) error {
			if len(material.secret) != 32 || !sub.operationCurrentContext(opctx) {
				return errDirectRuntimeRejected
			}
			// use must not retain, log or cache the string: Go strings cannot be
			// cleared. Custody and the subscription lease remain scoped to this
			// synchronous operateManagedTargetEndpoint callback.
			encoded := make([]byte, base64.RawURLEncoding.EncodedLen(len(material.secret)))
			defer clear(encoded)
			base64.RawURLEncoding.Encode(encoded, material.secret)
			return use(opctx, string(snapshot.CredentialID)+":"+string(encoded))
		})
	}, nil
}

func directRuntimeBindingFromObservation(sub *DirectEndpointSubscription, observed directEndpointReconcileObservation, revision int64) (directRuntimeBinding, error) {
	p, err := transport.DecodeDirectChannelPublicationV2(observed.Publication)
	if err != nil || !observed.Binding.publicationMatches(p) || !reconcilePublicationHash(observed.Enrollment, observed.Publication) {
		return directRuntimeBinding{}, errDirectRuntimeRejected
	}
	d := p.Descriptor
	channel, err := transport.DirectChannelIDV2(d)
	if err != nil {
		return directRuntimeBinding{}, errDirectRuntimeRejected
	}
	descriptorHash, err := transport.DescriptorHashV2(d)
	if err != nil {
		return directRuntimeBinding{}, errDirectRuntimeRejected
	}
	publicationHash, err := transport.PublicationHashV2(p)
	if err != nil || sub == nil || !consentText(sub.binding.subject.NativeSessionID) || !consentText(sub.binding.subject.NativeGeneration) {
		return directRuntimeBinding{}, errDirectRuntimeRejected
	}
	return directRuntimeBinding{Publication: p,
		Context:       transport.DirectDeliveryContextV2{ChannelID: channel, DescriptorHash: descriptorHash, PublicationHash: publicationHash, ParentGrantID: d.ParentGrantID, GrantGeneration: d.GrantGeneration},
		Recipient:     transport.DirectDeliveryPartyV2{Role: "P", PrincipalID: d.P.PrincipalID, EndpointID: d.P.EndpointID, CredentialID: d.P.CredentialID},
		NativeSession: sub.binding.subject.NativeSessionID, NativeGeneration: sub.binding.subject.NativeGeneration, ConsentRevision: revision}, nil
}

func directRuntimeAuthorityBindingEqual(a, b directRuntimeBinding) bool {
	araw, ae := a.Publication.CanonicalBytes()
	braw, be := b.Publication.CanonicalBytes()
	return ae == nil && be == nil && bytes.Equal(araw, braw) && a.Context == b.Context && a.Recipient == b.Recipient && a.NativeSession == b.NativeSession && a.NativeGeneration == b.NativeGeneration && a.ConsentRevision == b.ConsentRevision
}
