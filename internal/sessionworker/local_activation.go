package sessionworker

import (
	"context"
	"encoding/json"
	"errors"
	"sync"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/domain"
	fabricidentity "github.com/pagnet-code/pagnet/fabric/identity"
	"github.com/pagnet-code/pagnet/internal/nativeauthority"
)

type LocalActivationRequest struct {
	ID                string                    `json:"id"`
	Authority         AuthorityScope            `json:"authority"`
	SourceCommandID   string                    `json:"sourceCommandId"`
	NativeGeneration  string                    `json:"nativeGeneration"`
	ActualRuntime     domain.RuntimeName        `json:"actualRuntime"`
	OriginalSource    LocalIntentSource         `json:"originalSource"`
	CurrentController fabricidentity.Controller `json:"currentController"`
	CurrentBinding    fabricidentity.Binding    `json:"currentBinding"`
}
type LocalActivationOrigin struct {
	ID               string                 `json:"id"`
	NativeGeneration string                 `json:"nativeGeneration"`
	Origin           *fabricidentity.Origin `json:"origin,omitempty"`
	Error            string                 `json:"error,omitempty"`
}
type localActivationTicket struct {
	request     LocalActivationRequest
	issuedLease int64
	done        chan activationReply
}
type localActivationBroker struct {
	mu      sync.Mutex
	scope   AuthorityScope
	lease   int64
	current *nativeauthority.LocalControl
	ticket  *localActivationTicket
	closed  bool
	persist func(LocalActivationRequest, fabricidentity.Origin) error
}

func newLocalActivationBroker(scope AuthorityScope) *localActivationBroker {
	return &localActivationBroker{scope: scope}
}

// bindCurrent is called only after exact verified local admission has FULL
// committed under current registry/fence and the current authenticated IPC lease.
// An existing ticket retains original source A, never the newest delivery source.
func (b *localActivationBroker) bindCurrent(lease int64, i nativeauthority.VerifiedIntent) error {
	return b.bindControl(lease, nativeauthority.LocalControl{CurrentBinding: i.CurrentBinding, CurrentController: i.CurrentController})
}
func (b *localActivationBroker) bindControl(lease int64, i nativeauthority.LocalControl) error {
	if nativeauthority.ValidateLocalControl(b.scope, i) != nil {
		return ErrFenced
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed || lease <= 0 || lease < b.lease {
		return ErrFenced
	}
	if b.current != nil && i.CurrentController.Epoch() < b.current.CurrentController.Epoch() {
		return ErrFenced
	}
	if lease != b.lease || b.current == nil || i.CurrentController.Epoch() != b.current.CurrentController.Epoch() {
		if b.ticket != nil {
			b.ticket.issuedLease = 0
		}
	}
	b.lease = lease
	copy := i
	b.current = &copy
	return nil
}
func (b *localActivationBroker) disconnect(lease int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.lease == lease {
		b.current = nil
		if b.ticket != nil {
			b.ticket.issuedLease = 0
		}
	}
}
func (b *localActivationBroker) await(ctx context.Context, source *LocalIntentSource, generation string, runtime domain.RuntimeName) (json.RawMessage, error) {
	if source == nil || nativeauthority.ValidateOriginalAdmission(b.scope, source.Admission) != nil || source.Commitment.CommandID == "" || generation == "" {
		return nil, ErrFenced
	}
	b.mu.Lock()
	if b.closed || b.ticket != nil {
		b.mu.Unlock()
		return nil, ErrFenced
	}
	ticket := &localActivationTicket{request: LocalActivationRequest{ID: uuid.NewString(), Authority: b.scope, SourceCommandID: source.Commitment.CommandID, NativeGeneration: generation, ActualRuntime: runtime, OriginalSource: *source}, done: make(chan activationReply, 1)}
	b.ticket = ticket
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		if b.ticket == ticket {
			b.ticket = nil
		}
		b.mu.Unlock()
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case reply := <-ticket.done:
		return reply.origin, reply.err
	}
}
func (b *localActivationBroker) poll(lease int64) (*LocalActivationRequest, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed || lease != b.lease || b.current == nil {
		return nil, ErrFenced
	}
	if b.ticket == nil {
		return nil, nil
	}
	b.ticket.issuedLease = lease
	b.ticket.request.CurrentController = b.current.CurrentController
	b.ticket.request.CurrentBinding = b.current.CurrentBinding
	copy := b.ticket.request
	return &copy, nil
}
func (b *localActivationBroker) complete(lease int64, r LocalActivationOrigin) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	t := b.ticket
	if b.closed || b.current == nil || lease != b.lease || t == nil || t.issuedLease != lease || r.ID != t.request.ID || r.NativeGeneration != t.request.NativeGeneration {
		return ErrFenced
	}
	if len(r.Error) > 4096 || (r.Error != "" && r.Origin != nil) {
		return ErrConflict
	}
	if r.Error != "" {
		t.done <- activationReply{err: errors.New("local native authority declined activation")}
		b.ticket = nil
		return nil
	}
	if r.Origin == nil || nativeauthority.ValidateOriginalOrigin(b.scope, t.request.OriginalSource.Admission, *r.Origin, t.request.NativeGeneration) != nil {
		return ErrConflict
	}
	if r.Origin.RegisteredControllerEpoch > t.request.CurrentController.Epoch() || r.Origin.RegisteredControllerEpoch < t.request.OriginalSource.Admission.OriginalControllerEpoch || t.request.CurrentController.Epoch() != b.current.CurrentController.Epoch() {
		return ErrFenced
	}
	origin, e := json.Marshal(r.Origin)
	if e != nil || len(origin) > 64<<10 {
		return ErrConflict
	}
	if b.persist == nil {
		return ErrFenced
	}
	if e = b.persist(t.request, *r.Origin); e != nil {
		return e
	}
	t.done <- activationReply{origin: origin}
	b.ticket = nil
	return nil
}
func (b *localActivationBroker) close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	b.current = nil
	if b.ticket != nil {
		b.ticket.done <- activationReply{err: context.Canceled}
		b.ticket = nil
	}
}
