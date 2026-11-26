//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/internal/directhttp"
	"github.com/pagnet-code/pagnet/internal/nativedirect"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

type directReservationInbox interface {
	Inbox(context.Context, string, transport.DirectInboxRequestV2) (transport.DirectInboxPageV2, error)
}
type directReservationWorker interface {
	reserveDirectASK(context.Context, nativedirect.NativeDirectASKSource, json.RawMessage) (*sessionworker.DirectASKReservation, error)
	lookupDirectASK(context.Context, nativedirect.NativeDirectASKSource, json.RawMessage) (*sessionworker.DirectASKReservation, error)
}
type directReservationDependencies struct {
	Binding   directRuntimeBinding
	Now       func() time.Time
	Client    directReservationInbox
	Authority directRuntimeAuthority // each invocation constructs fresh current authority
	Open      func(context.Context, transport.DirectChannelMessageV2, []byte) ([]byte, error)
	Source    func(context.Context) (nativedirect.NativeDirectASKSource, error)
	Worker    directReservationWorker
}

// directReservationCoordinator is deliberately unregistered. An explicit wake
// may call ReceiveOne; there is no loop, ACK, reply, or native execution path.
// Durable rows are evidence only. Recovery requires a newly authenticated live
// subscription/controller and fresh publication and consent authority.
type directReservationCoordinator struct {
	store *directReservationStore
	deps  directReservationDependencies
	mu    sync.Mutex
}

func newDirectTargetReservationCoordinator(ctx context.Context, d *Daemon, captured ManagedEndpointPrepareScope, sub *DirectEndpointSubscription, issue transport.ManagedDirectCredentialIssue, consent *directChannelConsentStore, revision int64) (*directReservationCoordinator, error) {
	return newDirectTargetReservationCoordinatorWithReader(ctx, d, captured, sub, issue, consent, revision, nil)
}
func newDirectTargetReservationCoordinatorWithReader(ctx context.Context, d *Daemon, captured ManagedEndpointPrepareScope, sub *DirectEndpointSubscription, issue transport.ManagedDirectCredentialIssue, consent *directChannelConsentStore, revision int64, reader directEndpointReconcileReader) (*directReservationCoordinator, error) {
	if ctx == nil || d == nil || sub == nil || sub.binding.proxy == nil || sub.binding.leaseID == "" {
		return nil, errDirectReservationRejected
	}
	raw, err := issue.CanonicalBytes()
	if err != nil {
		return nil, errDirectReservationRejected
	}
	issue, err = transport.DecodeManagedDirectCredentialIssue(raw)
	if err != nil {
		return nil, err
	}
	captured, err = ownDirectReconcileOperationScope(d, captured, sub, raw, "P", string(sub.binding.metadata.InstallationID))
	if err != nil {
		return nil, err
	}
	observe, err := newDirectTargetReconcileObserverWithReader(d, captured, sub, issue, reader, time.Now)
	if err != nil {
		return nil, err
	}
	observed, err := observe(ctx)
	if err != nil {
		return nil, err
	}
	binding, err := directRuntimeBindingFromObservation(sub, observed, revision)
	if err != nil {
		return nil, err
	}
	if binding.Publication.Descriptor.ChannelGeneration != strconv.FormatUint(issue.ChannelGeneration, 10) {
		return nil, errDirectReservationRejected
	}
	client, err := directhttp.New(sub.binding.metadata.ServerOrigin)
	if err != nil {
		return nil, err
	}
	operate, err := newDirectTargetReconcileOperation(d, captured, sub, issue)
	if err != nil {
		return nil, err
	}
	deps := directReservationDependencies{Binding: binding, Now: time.Now, Client: client, Worker: sub.binding.proxy}
	deps.Authority = func(ctx context.Context, b directRuntimeBinding, use func(context.Context, string) error) error {
		a, e := newDirectTargetRuntimeAuthorityWithReader(ctx, d, captured, sub, issue, consent, revision, reader)
		if e != nil {
			return e
		}
		return a(ctx, b, use)
	}
	deps.Open = func(ctx context.Context, ask transport.DirectChannelMessageV2, wire []byte) ([]byte, error) {
		current, e := observe(ctx)
		if e != nil {
			return nil, e
		}
		b, e := directRuntimeBindingFromObservation(sub, current, revision)
		if e != nil || !directRuntimeAuthorityBindingEqual(binding, b) {
			return nil, errDirectReservationRejected
		}
		return openDirectTargetMessageAsk(ctx, sub, current.Binding, current.Enrollment, current.Publication, d.nativeRegistry, time.Now, operate, ask.Header.MessageID, ask.Header.RootID, wire)
	}
	deps.Source = func(ctx context.Context) (nativedirect.NativeDirectASKSource, error) {
		token, e := d.verifyDirectEndpointToken(ctx, captured, sub.binding.metadata.ServerOrigin, sub.binding.subject)
		if e != nil {
			return nativedirect.NativeDirectASKSource{}, e
		}
		if token == nil || token.proxy != sub.binding.proxy || token.link != sub.binding.link {
			return nativedirect.NativeDirectASKSource{}, errDirectReservationRejected
		}
		result, e := token.proxy.verifyEndpointOwnership(ctx, token.ownership)
		if e != nil {
			return nativedirect.NativeDirectASKSource{}, e
		}
		if result == nil {
			return nativedirect.NativeDirectASKSource{}, errDirectReservationRejected
		}
		s := result.Snapshot
		if s.Scope != token.proxy.scope || s.NativeSessionID != binding.NativeSession || s.NativeGeneration != binding.NativeGeneration {
			return nativedirect.NativeDirectASKSource{}, errDirectReservationRejected
		}
		return nativedirect.NativeDirectASKSource{Protocol: nativedirect.Protocol, ServerOrigin: sub.binding.metadata.ServerOrigin, Scope: s.Scope, Ownership: token.ownership, NativeSessionID: s.NativeSessionID, NativeGeneration: s.NativeGeneration, NativeStartIdentity: s.NativeStartIdentity, NativePID: s.PID, EndpointIssueID: hex.EncodeToString(sub.binding.issueDigest[:]), EndpointLeaseID: sub.binding.leaseID, EndpointGeneration: strconv.FormatUint(issue.ChannelGeneration, 10), ConsentRevision: revision, Deadline: sub.binding.metadata.Deadline}, nil
	}
	return &directReservationCoordinator{store: &directReservationStore{registry: d.nativeRegistry}, deps: deps}, nil
}

// ReceiveOne performs a single authenticated non-destructive query. The returned
// key identifies journal evidence, never a live subscription or execution grant.
func (c *directReservationCoordinator) ReceiveOne(ctx context.Context) (string, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	b := c.deps.Binding
	q := transport.DirectInboxRequestV2{Version: 2, Domain: transport.DirectChannelDomainV2 + "/delivery/inbox-request", Context: b.Context, Recipient: b.Recipient, Limit: 1}
	var page transport.DirectInboxPageV2
	err := c.deps.Authority(ctx, b, func(opctx context.Context, credential string) error {
		var e error
		page, e = c.deps.Client.Inbox(opctx, credential, q)
		return e
	})
	if err != nil {
		return "", false, err
	}
	if _, err = page.CanonicalBytes(); err != nil || page.Context != q.Context || page.Recipient != q.Recipient || len(page.Deliveries) > 1 {
		return "", false, errDirectReservationRejected
	}
	if len(page.Deliveries) == 0 {
		return "", false, nil
	}
	return c.accept(ctx, page.Deliveries[0])
}
func (c *directReservationCoordinator) accept(ctx context.Context, delivery transport.DirectDeliveryV2) (string, bool, error) {
	b := c.deps.Binding
	raw, err := delivery.CanonicalBytes()
	if err != nil {
		return "", false, errDirectReservationRejected
	}
	delivery, err = transport.DecodeDirectDeliveryV2(raw)
	if err != nil {
		return "", false, errDirectReservationRejected
	}
	if !directRuntimeUnexpired(delivery.Admission, c.deps.Now()) || delivery.DeliveryState != "pending" || delivery.Admission.Binding.Context != b.Context || delivery.Admission.Binding.Recipient != b.Recipient || delivery.Admission.ValidateForPublication(b.Publication) != nil {
		return "", false, errDirectReservationRejected
	}
	ask, err := transport.DecodeDirectChannelMessageV2(delivery.Wire)
	if err != nil || ask.Header.Kind != "ASK" || ask.Header.ParentMessageID != "" || ask.Header.ParentWireHash != "" || transport.ValidateDirectChannelMessageForDescriptorV2(ask, b.Publication.Descriptor) != nil {
		return "", false, errDirectReservationRejected
	}
	var source nativedirect.NativeDirectASKSource
	var localErr error
	called := false
	err = c.deps.Authority(ctx, b, func(opctx context.Context, _ string) error {
		if called {
			localErr = errDirectReservationRejected
			return nil
		}
		called = true
		plaintext, e := c.deps.Open(opctx, ask, delivery.Wire)
		defer clear(plaintext)
		if e != nil {
			localErr = e
			return nil
		}
		if len(plaintext) == 0 || len(plaintext) > 65536 || !utf8.Valid(plaintext) {
			localErr = errDirectReservationRejected
			return nil
		}
		source, e = c.deps.Source(opctx)
		if e != nil {
			localErr = e
			return nil
		}
		digest := sha256.Sum256(plaintext)
		source.AdmissionID = uuid.NewString()
		source.Receipt = delivery.Admission
		source.InputDigest = hex.EncodeToString(digest[:])
		expiry, _ := time.Parse(time.RFC3339Nano, delivery.Admission.ExpiresAt)
		descriptor, _ := time.Parse(time.RFC3339Nano, b.Publication.Descriptor.ExpiresAt)
		source.Deadline = directEndpointDeadline(source.Deadline, expiry, descriptor).UTC()
		if deadline, ok := opctx.Deadline(); ok && deadline.Before(source.Deadline) {
			source.Deadline = deadline.UTC()
		}
		localErr = source.ValidateWire(delivery.Wire)
		if localErr == nil && !c.deps.Now().Before(source.Deadline) {
			localErr = errDirectReservationRejected
		}
		return nil
	})
	if err != nil {
		return "", false, err
	}
	if localErr != nil {
		return "", false, localErr
	}
	if !called {
		return "", false, errDirectReservationRejected
	}
	record, err := c.store.claim(ctx, source, delivery.Wire)
	if err != nil {
		return "", false, err
	}
	key, err := directReservationKey(record.Source)
	if err != nil {
		return "", false, err
	}
	err = c.recover(ctx, key)
	return key, true, err
}

func (c *directReservationCoordinator) Recover(ctx context.Context, key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.recover(ctx, key)
}

// The attempt marker commits before IPC. Local RPC outcome is captured inside
// Authority because its custody wrapper intentionally masks callback errors.
func (c *directReservationCoordinator) recover(ctx context.Context, key string) error {
	record, err := c.store.load(ctx, key)
	if err != nil {
		return err
	}
	b := c.deps.Binding
	if record.Source.ConsentRevision != b.ConsentRevision || record.Source.Receipt.Binding.Context != b.Context || record.Source.Receipt.Binding.Recipient != b.Recipient || record.Source.Receipt.ValidateForPublication(b.Publication) != nil {
		return errDirectReservationRejected
	}
	var localErr error
	called := false
	err = c.deps.Authority(ctx, b, func(opctx context.Context, _ string) error {
		if called {
			localErr = errDirectReservationRejected
			return nil
		}
		called = true
		localErr = func() error {
			fresh, e := c.deps.Source(opctx)
			if e != nil {
				return e
			}
			// A fresh lease authenticates recovery but never replaces saved provenance.
			fresh.AdmissionID = record.Source.AdmissionID
			fresh.Receipt = record.Source.Receipt
			fresh.InputDigest = record.Source.InputDigest
			fresh.Deadline = record.Source.Deadline
			fresh.EndpointLeaseID = record.Source.EndpointLeaseID
			want, _ := record.Source.CanonicalBytes()
			got, e := fresh.CanonicalBytes()
			if e != nil || !bytes.Equal(want, got) {
				return errDirectReservationRejected
			}
			if record.Stage != "prepared" {
				result, e := c.deps.Worker.lookupDirectASK(opctx, record.Source, record.Wire)
				if e != nil {
					return e
				}
				if result != nil {
					return c.commitResult(opctx, key, record, result)
				}
			}
			if !c.deps.Now().Before(record.Source.Deadline) {
				return errDirectReservationRecovery
			}
			opctx, cancel := context.WithDeadline(opctx, record.Source.Deadline)
			defer cancel()
			prior := record.Stage
			record.Stage = "attempted"
			record.Result = nil
			if e = c.store.save(opctx, key, prior, record); e != nil {
				return e
			}
			result, e := c.deps.Worker.reserveDirectASK(opctx, record.Source, record.Wire)
			if e != nil {
				// Even explicit local non-dispatch retains attempted provenance: a future
				// fresh attachment must first look up the exact original record.
				if errors.Is(e, sessionworker.ErrControllerCallNotStarted) {
					return e
				}
				return errDirectReservationRecovery
			}
			return c.commitResult(opctx, key, record, result)
		}()
		return nil
	})
	if err != nil {
		return err
	}
	if !called {
		return errDirectReservationRejected
	}
	return localErr
}
func (c *directReservationCoordinator) commitResult(ctx context.Context, key string, record directReservationRecord, result *sessionworker.DirectASKReservation) error {
	if result == nil {
		return errDirectReservationRecovery
	}
	want, _ := record.Source.CanonicalBytes()
	got, err := result.Source.CanonicalBytes()
	if err != nil || !bytes.Equal(want, got) || !bytes.Equal(record.Wire, result.Wire) || (result.State != "reserved" && result.State != "unknown") {
		return errDirectReservationRecovery
	}
	prior := record.Stage
	record.Stage = result.State
	record.Result = result
	if err = c.store.save(ctx, key, prior, record); err != nil {
		return err
	}
	if result.State == "unknown" {
		return errDirectReservationRecovery
	}
	return nil
}
