//go:build linux || darwin

package daemon

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/pagnet-code/pagnet/transport"
)

// directEndpointAttachmentController is a dormant, explicit one-candidate
// composition. It owns the public issue and authenticated connection snapshot;
// it never discovers candidates, enables consent, or retries failed work.
type directEndpointAttachmentController struct {
	mu         sync.Mutex
	d          *Daemon
	captured   ManagedEndpointPrepareScope
	wake       *directEndpointWakeConnection
	store      *directChannelConsentStore
	key        directChannelConsentKey
	admit      func(context.Context) (*DirectEndpointSubscription, error)
	observe    func(*DirectEndpointSubscription) (directEndpointReconcileObserver, error)
	pass       func(*DirectEndpointSubscription, directChannelConsentRecord, int64) (directEndpointReconcilePass, error)
	attachment *directEndpointWakeAttachment
	revision   int64
}

func newDirectSourceEndpointAttachmentController(d *Daemon, captured ManagedEndpointPrepareScope, wake *directEndpointWakeConnection, store *directChannelConsentStore, issue transport.DirectManagedSourceCredentialIssueV2) (*directEndpointAttachmentController, error) {
	return newDirectSourceEndpointAttachmentControllerWithClient(d, captured, wake, store, issue, nil)
}

func newDirectSourceEndpointAttachmentControllerWithClient(d *Daemon, captured ManagedEndpointPrepareScope, wake *directEndpointWakeConnection, store *directChannelConsentStore, issue transport.DirectManagedSourceCredentialIssueV2, client directEndpointReconcilePassClient) (*directEndpointAttachmentController, error) {
	raw, err := issue.CanonicalBytes()
	if err != nil {
		return nil, errDirectChannelConsent
	}
	owned, err := transport.DecodeDirectManagedSourceCredentialIssueV2(raw)
	if err != nil {
		return nil, errDirectChannelConsent
	}
	subject := owned.PoP.Prepare.Subject
	c, err := newDirectEndpointAttachmentController(d, captured, wake, store, owned.PoP.ACK.Reservation.ServerURL, "S", string(subject.DirectIntentID), string(subject.PrincipalID))
	if err != nil {
		return nil, err
	}
	c.admit = func(ctx context.Context) (*DirectEndpointSubscription, error) {
		return d.admitDirectManagedSourceEndpointV2(ctx, c.captured, owned)
	}
	c.observe = func(s *DirectEndpointSubscription) (directEndpointReconcileObserver, error) {
		return newDirectSourceReconcileObserverWithReader(d, c.captured, s, owned, client, time.Now)
	}
	c.pass = func(s *DirectEndpointSubscription, record directChannelConsentRecord, revision int64) (directEndpointReconcilePass, error) {
		return newDirectSourceReconcilePassWithConsentAndClient(d, c.captured, s, owned, store.installation, record, revision, client, time.Now)
	}
	return c, nil
}

func newDirectTargetEndpointAttachmentController(d *Daemon, captured ManagedEndpointPrepareScope, wake *directEndpointWakeConnection, store *directChannelConsentStore, issue transport.ManagedDirectCredentialIssue) (*directEndpointAttachmentController, error) {
	return newDirectTargetEndpointAttachmentControllerWithClient(d, captured, wake, store, issue, nil)
}

func newDirectTargetEndpointAttachmentControllerWithClient(d *Daemon, captured ManagedEndpointPrepareScope, wake *directEndpointWakeConnection, store *directChannelConsentStore, issue transport.ManagedDirectCredentialIssue, client directEndpointReconcilePassClient) (*directEndpointAttachmentController, error) {
	raw, err := issue.CanonicalBytes()
	if err != nil {
		return nil, errDirectChannelConsent
	}
	owned, err := transport.DecodeManagedDirectCredentialIssue(raw)
	if err != nil {
		return nil, errDirectChannelConsent
	}
	subject := owned.PoP.Prepare.Subject
	c, err := newDirectEndpointAttachmentController(d, captured, wake, store, owned.PoP.ACK.Reservation.ServerURL, "P", string(subject.DirectIntentID), string(subject.PrincipalID))
	if err != nil {
		return nil, err
	}
	c.admit = func(ctx context.Context) (*DirectEndpointSubscription, error) {
		return d.admitManagedTargetEndpoint(ctx, c.captured, owned)
	}
	c.observe = func(s *DirectEndpointSubscription) (directEndpointReconcileObserver, error) {
		return newDirectTargetReconcileObserverWithReader(d, c.captured, s, owned, client, time.Now)
	}
	c.pass = func(s *DirectEndpointSubscription, record directChannelConsentRecord, revision int64) (directEndpointReconcilePass, error) {
		return newDirectTargetReconcilePassWithConsentAndClient(d, c.captured, s, owned, store.installation, record, revision, client, time.Now)
	}
	return c, nil
}

func newDirectEndpointAttachmentController(d *Daemon, captured ManagedEndpointPrepareScope, wake *directEndpointWakeConnection, store *directChannelConsentStore, server, role, intent, principal string) (*directEndpointAttachmentController, error) {
	if d == nil || store == nil || store.registry == nil || d.nativeRegistry != store.registry || wake == nil || wake.daemon != d || captured.Socket == nil || captured.Connection == nil || wake.socket != captured.Socket || wake.native != captured.Connection {
		return nil, errDirectChannelConsent
	}
	raw, err := json.Marshal(captured.Session)
	var session transport.HostSessionPayload
	if err != nil || json.Unmarshal(raw, &session) != nil {
		return nil, errDirectChannelConsent
	}
	captured.Session = session
	key := directChannelConsentKey{Server: server, Tenant: captured.Session.TenantID, Account: captured.Session.AccountID, Host: captured.Session.HostID, Intent: intent, Role: role, Principal: principal}
	if !store.validKey(key) || !consentKeyValid(key) {
		return nil, errDirectChannelConsent
	}
	return &directEndpointAttachmentController{d: d, captured: captured, wake: wake, store: store, key: key}, nil
}

// attach gates even preflight GETs on an exact enabled revision. The lease
// closes the disable/preflight race and revokes the exact admission before any
// later pass can dispatch. Duplicate requests reuse only the same live revision.
func (c *directEndpointAttachmentController) attach(ctx context.Context, expectedRevision int64) (attachment *directEndpointWakeAttachment, err error) {
	if c == nil || ctx == nil || expectedRevision <= 0 {
		return nil, errDirectChannelConsent
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	var sub *DirectEndpointSubscription
	complete := false
	defer func() {
		if recover() != nil {
			attachment, err = nil, errDirectChannelConsent
		}
		if !complete && sub != nil {
			sub.Remove()
		}
		if err != nil {
			attachment, err = nil, errDirectChannelConsent
		}
	}()
	record, err := c.store.Get(ctx, c.key)
	if err != nil || !record.Enabled || record.Binding == nil || record.Revision != expectedRevision || ctx.Err() != nil {
		return nil, errDirectChannelConsent
	}
	if c.attachment != nil {
		select {
		case <-c.attachment.Done():
		default:
			if c.revision == expectedRevision && c.attachment.handle.Valid() {
				return c.attachment, nil
			}
		}
		// A controller never replaces an attachment with a new consent revision.
		return nil, errDirectChannelConsent
	}
	sub, err = c.admit(ctx)
	if err != nil || sub == nil {
		return nil, errDirectChannelConsent
	}
	if err := c.validateLocalConsent(record, sub, time.Now()); err != nil {
		return nil, err
	}
	observe, err := c.observe(sub)
	if err != nil {
		return nil, err
	}
	observed, err := observe(ctx)
	if err != nil {
		return nil, err
	}
	if err = validateDirectChannelConsentEligibility(record, expectedRevision, sub, c.captured, c.store.installation, observed.Binding, time.Now()); err != nil {
		return nil, err
	}
	if err = c.d.registerDirectChannelConsentLease(ctx, c.store, c.key, expectedRevision, sub, c.captured, observed.Binding); err != nil {
		return nil, err
	}
	pass, err := c.pass(sub, record, expectedRevision)
	if err != nil || ctx.Err() != nil {
		return nil, errDirectChannelConsent
	}
	attachment, err = c.wake.attach(sub, func(ctx context.Context) error {
		_, err := pass(ctx)
		if err != nil {
			sub.Remove()
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	go func(a *directEndpointWakeAttachment, s *DirectEndpointSubscription) {
		<-a.Done()
		s.Remove()
	}(attachment, sub)
	c.attachment, c.revision = attachment, expectedRevision
	complete = true
	return attachment, nil
}

// status exposes no transport, custody, or authentication error details.
func (c *directEndpointAttachmentController) status() error {
	if c == nil {
		return errDirectChannelConsent
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.attachment == nil {
		return errDirectChannelConsent
	}
	select {
	case <-c.attachment.Done():
		return errDirectChannelConsent
	default:
		return nil
	}
}

// validateLocalConsent rejects stale local opt-in metadata before authenticated
// HTTP. Remote descriptor fields still require the full post-observation check.
func (c *directEndpointAttachmentController) validateLocalConsent(record directChannelConsentRecord, sub *DirectEndpointSubscription, now time.Time) error {
	if sub == nil || record.Binding == nil {
		return errDirectChannelConsent
	}
	admitted, binding := sub.binding, record.Binding
	subject, metadata := admitted.subject, admitted.metadata
	session, err := json.Marshal(c.captured.Session)
	expiry, expiryErr := time.Parse(time.RFC3339Nano, binding.ExpiresAt)
	if err != nil || expiryErr != nil || !now.Before(expiry) || record.Key != c.key || binding.Key != c.key ||
		binding.Instance != string(subject.InstanceID) || binding.Origin != string(subject.OriginID) || binding.OwnershipGeneration != subject.OwnershipGeneration || binding.NativeGeneration != subject.NativeGeneration ||
		c.store.installation != string(metadata.InstallationID) || string(session) != admitted.sessionIdentity || c.captured.Socket != admitted.socket || c.captured.Connection != admitted.native || !nativeManagedSessionMatches(subject, c.captured.Session) {
		return errDirectChannelConsent
	}
	return nil
}
