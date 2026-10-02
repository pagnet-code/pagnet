package sessionworker

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/domain"
)

// ActivationRequest is created by the worker before a native process exists.
// Registering an origin for a previous attempt never authorizes this generation.
type ActivationRequest struct {
	ID               string             `json:"id"`
	Scope            Scope              `json:"scope"`
	SourceCommandID  string             `json:"sourceCommandId"`
	NativeGeneration string             `json:"nativeGeneration"`
	ActualRuntime    domain.RuntimeName `json:"actualRuntime"`
	Admission        Admission          `json:"admission"`
	CurrentAdmission Admission          `json:"currentAdmission"`
}

type ActivationOrigin struct {
	ID               string          `json:"id"`
	NativeGeneration string          `json:"nativeGeneration"`
	Origin           json.RawMessage `json:"origin,omitempty"`
	Error            string          `json:"error,omitempty"`
}

type activationReply struct {
	origin json.RawMessage
	err    error
}

type activationTicket struct {
	request ActivationRequest
	lease   int64
	issued  bool
	done    chan activationReply
}

func (o *SessionOwner) awaitActivationOrigin(ctx context.Context, commandID, generation string) (json.RawMessage, error) {
	if commandID == "" || len(commandID) > 256 {
		return nil, errors.New("native activation source command is missing")
	}
	o.relay.mu.Lock()
	if o.relay.closed || o.relay.activation != nil {
		o.relay.mu.Unlock()
		return nil, errors.New("native activation admission unavailable")
	}
	ticket := &activationTicket{request: ActivationRequest{ID: uuid.NewString(), Scope: o.journal.scope, SourceCommandID: commandID, NativeGeneration: generation, ActualRuntime: o.spec.Runtime}, done: make(chan activationReply, 1)}
	o.relay.activation = ticket
	o.relay.mu.Unlock()
	defer func() {
		o.relay.mu.Lock()
		if o.relay.activation == ticket {
			o.relay.activation = nil
		}
		o.relay.mu.Unlock()
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case reply := <-ticket.done:
		return reply.origin, reply.err
	}
}

func (b *relayBroker) pollActivation(lease int64) (*ActivationRequest, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed || lease != b.lease {
		return nil, ErrFenced
	}
	if b.admission == nil {
		return nil, errors.New("fresh control-plane admission is required")
	}
	if b.activation == nil || b.activation.issued {
		return nil, nil
	}
	b.activation.issued = true
	b.activation.lease = lease
	if b.activation.request.Admission.RunnerID == "" {
		b.activation.request.Admission = *b.admission
	}
	b.activation.request.CurrentAdmission = *b.admission
	copy := b.activation.request
	return &copy, nil
}

func (b *relayBroker) completeActivation(lease int64, result ActivationOrigin) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed || lease != b.lease || b.admission == nil {
		return ErrFenced
	}
	ticket := b.activation
	if ticket == nil || !ticket.issued || ticket.lease != lease || result.ID != ticket.request.ID || result.NativeGeneration != ticket.request.NativeGeneration {
		return errors.New("native activation attempt does not match")
	}
	if len(result.Error) > 4096 || (result.Error != "" && len(result.Origin) > 0) {
		return errors.New("invalid native authority failure")
	}
	if result.Error != "" {
		ticket.done <- activationReply{err: errors.New(result.Error)}
		b.activation = nil
		return nil
	}
	if len(result.Origin) > 8192 {
		return errors.New("native activation origin exceeds bound")
	}
	var origin struct {
		NativeAdmissionID string             `json:"nativeAdmissionId"`
		ID                string             `json:"id"`
		CommandID         string             `json:"commandId"`
		TenantID          string             `json:"tenantId"`
		HostID            string             `json:"hostId"`
		InstanceID        string             `json:"instanceId"`
		Runtime           domain.RuntimeName `json:"runtime"`
		NativeGeneration  string             `json:"nativeGeneration"`
		RunnerID          string             `json:"runnerId"`
		RunnerEpoch       time.Time          `json:"runnerEpoch"`
		BootID            string             `json:"bootId"`
		CreatedAt         time.Time          `json:"createdAt"`
	}
	if json.Unmarshal(result.Origin, &origin) != nil || origin.NativeAdmissionID != ticket.request.Admission.NativeAdmissionID || origin.ID == "" || origin.CreatedAt.IsZero() || origin.CommandID != ticket.request.SourceCommandID || origin.TenantID != b.spec.TenantID || origin.HostID != b.scope.HostID || origin.InstanceID != b.scope.InstanceID || origin.Runtime != b.spec.Runtime || origin.NativeGeneration != ticket.request.NativeGeneration || origin.RunnerID != ticket.request.Admission.RunnerID || !origin.RunnerEpoch.Equal(ticket.request.Admission.RunnerEpoch) || origin.BootID != ticket.request.Admission.BootID {
		return errors.New("authority origin does not match native activation scope")
	}
	// Current admission must still be the one that authorized this exact request.
	if *b.admission != ticket.request.CurrentAdmission {
		return ErrFenced
	}
	ticket.done <- activationReply{origin: append(json.RawMessage(nil), result.Origin...)}
	b.activation = nil
	return nil
}
