// Package dispatch selects a private binding for exactly the requested endpoint.
// It performs no discovery, alternate-target selection or transport replay.
package dispatch

import (
	"bytes"
	"context"
	"sync"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/node"
)

// Selection contains no credentials. Resolver is trusted private configuration,
// not a caller-selected protocol name or an inferred descriptive capability.
type Selection struct {
	BindingID        string
	EndpointRevision fabric.Revision
	Fingerprint      [32]byte
	Adapter          fabric.EndpointAdapter
}
type BindingResolver interface {
	Select(context.Context, fabric.ExecutionContext, fabric.EndpointDescriptor, *fabric.OfferDescriptor) (Selection, error)
}

// Admission must validate current authority/binding and fence the bounded
// downstream admission through its actual durable ACK. It does not claim atomic
// distributed effects. An ambiguous result is returned, never retried here.
type Admission interface {
	WithDispatch(context.Context, fabric.ExecutionContext, []byte, []byte, fabric.EndpointDescriptor, *fabric.OfferDescriptor, Selection, func(context.Context) (fabric.InvocationStream, error)) (fabric.InvocationStream, error)
}
type Config struct {
	Audience    string
	Descriptors fabric.DescriptorStore
	Bindings    BindingResolver
	Admission   Admission
}
type Dispatcher struct{ config Config }

func New(c Config) (*Dispatcher, error) {
	if c.Audience == "" || c.Descriptors == nil || c.Bindings == nil || c.Admission == nil {
		return nil, fabric.NewError(fabric.CodeUnauthenticated, "Exact dispatch requires trusted registry, binding and admission composition")
	}
	return &Dispatcher{config: c}, nil
}

func (d *Dispatcher) Invoke(ctx context.Context, caller fabric.ExecutionContext, request fabric.InvokeRequest) (fabric.InvocationStream, error) {
	if ctx == nil {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Missing invocation context")
	}
	if err := caller.VerifyAuthenticated(d.config.Audience); err != nil {
		return nil, err
	}
	if err := request.Validate(); err != nil {
		return nil, err
	}
	authenticated, original, finalized, ok := node.FinalizedRequestFromContext(ctx)
	if !ok || authenticated.PrincipalView() != caller.PrincipalView() || authenticated.VerifyAuthenticated(d.config.Audience) != nil {
		return nil, fabric.NewError(fabric.CodeUnauthenticated, "Missing exact engine invocation admission")
	}
	if _, err := caller.DecodeVerifiedEnvelope(original, d.config.Audience); err != nil {
		return nil, err
	}
	var envelope fabric.Envelope
	if fabric.DecodeJSON(finalized, &envelope) != nil || envelope.Validate() != nil || !matches(envelope, request) {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Finalized invocation and selected request differ")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var offer *fabric.OfferDescriptor
	endpointRef := request.Target
	endpointRevision := request.ExpectedRevision
	if request.Target.IsOffer() {
		value, err := d.config.Descriptors.GetOffer(ctx, request.Target, request.ExpectedRevision)
		if err != nil {
			return nil, err
		}
		if value.Ref != request.Target || request.ExpectedRevision != "" && value.Revision != request.ExpectedRevision {
			return nil, fabric.NewError(fabric.CodeStaleReference, "Selected offer revision is stale")
		}
		offer = &value
		endpointRef = request.Target.Endpoint()
		endpointRevision = ""
	}
	endpoint, err := d.config.Descriptors.GetEndpoint(ctx, endpointRef, endpointRevision)
	if err != nil {
		return nil, err
	}
	if endpoint.Ref != endpointRef || endpointRevision != "" && endpoint.Revision != endpointRevision {
		return nil, fabric.NewError(fabric.CodeStaleReference, "Selected endpoint revision is stale")
	}
	selection, err := d.config.Bindings.Select(ctx, caller, endpoint, offer)
	if err != nil {
		return nil, err
	}
	if selection.Adapter == nil || selection.BindingID == "" || selection.EndpointRevision != endpoint.Revision || selection.Fingerprint == ([32]byte{}) || offer != nil && selection.BindingID != offer.BindingID {
		return nil, fabric.NewError(fabric.CodeStaleReference, "Selected private binding is unavailable or stale")
	}
	published := false
	supportsIdempotency := false
	for _, binding := range endpoint.Bindings {
		published = published || binding.ID == selection.BindingID
		if binding.ID == selection.BindingID {
			supportsIdempotency = binding.Idempotency
		}
	}
	if !published {
		return nil, fabric.NewError(fabric.CodeStaleReference, "Selected binding is not published by this endpoint")
	}
	if request.IdempotencyKey != "" && !supportsIdempotency {
		return nil, fabric.NewError(fabric.CodeUnsupported, "Selected binding does not support invocation idempotency")
	}
	var gate sync.Mutex
	active, called := true, false
	misused := false
	var stepError error
	var produced *admissionStream
	defer func() { gate.Lock(); active = false; gate.Unlock() }()
	stream, err := d.config.Admission.WithDispatch(ctx, caller, original, finalized, endpoint, offer, selection, func(admitted context.Context) (result fabric.InvocationStream, callError error) {
		gate.Lock()
		defer gate.Unlock()
		if !active || called {
			misused = true
			return nil, fabric.NewError(fabric.CodeProtocolError, "Dispatch admission callback already closed or used")
		}
		defer func() { stepError = callError }()
		called = true
		if ctx.Err() != nil || admitted == nil || admitted.Err() != nil {
			return nil, fabric.NewError(fabric.CodeCancelled, "Dispatch admission context ended")
		}
		boundCaller, boundOriginal, boundFinal, ok := node.FinalizedRequestFromContext(admitted)
		if !ok || boundCaller.PrincipalView() != caller.PrincipalView() || !bytes.Equal(boundOriginal, original) || !bytes.Equal(boundFinal, finalized) {
			return nil, fabric.NewError(fabric.CodeUnauthenticated, "Admission lost exact engine request capability")
		}
		lifetime, cancel := context.WithCancel(admitted)
		stop := context.AfterFunc(ctx, cancel)
		cleanup := func() { stop(); cancel() }
		if ctx.Err() != nil || lifetime.Err() != nil || request.Deadline != nil && !time.Now().Before(*request.Deadline) {
			cleanup()
			return nil, fabric.NewError(fabric.CodeCancelled, "Dispatch admission context ended")
		}
		upstream, err := selection.Adapter.Invoke(lifetime, caller, endpoint, request)
		if err != nil || upstream == nil {
			cleanup()
			if upstream != nil {
				_ = upstream.Close()
			}
			if err == nil {
				err = fabric.NewError(fabric.CodeProtocolError, "Endpoint returned no invocation stream")
			}
			return nil, err
		}
		produced = &admissionStream{InvocationStream: upstream, cleanup: cleanup}
		return produced, nil
	})
	gate.Lock()
	active = false
	used := called
	owned := produced
	if err == nil && stepError != nil {
		err = stepError
	}
	if err == nil && misused {
		err = fabric.NewError(fabric.CodeProtocolError, "Dispatch admission callback was reused")
	}
	gate.Unlock()
	if err != nil {
		if owned != nil {
			_ = owned.Close()
		}
		if stream != nil && stream != owned {
			_ = stream.Close()
		}
		return nil, err
	}
	if !used || owned == nil || stream != owned {
		if owned != nil {
			_ = owned.Close()
		}
		if stream != nil {
			_ = stream.Close()
		}
		return nil, fabric.NewError(fabric.CodeProtocolError, "Dispatch admission returned no exact endpoint result")
	}
	return stream, nil
}

func matches(envelope fabric.Envelope, request fabric.InvokeRequest) bool {
	if envelope.Operation != fabric.OperationInvoke || envelope.Target == nil || *envelope.Target != request.Target || envelope.ID != request.InvocationID || envelope.ExpectedRevision != request.ExpectedRevision || envelope.Context.IdempotencyKey != request.IdempotencyKey || !bytes.Equal(envelope.Payload, request.Input) {
		return false
	}
	if (envelope.Context.Deadline == nil) != (request.Deadline == nil) {
		return false
	}
	if request.Deadline != nil && (!envelope.Context.Deadline.Equal(*request.Deadline) || !time.Now().Before(*request.Deadline)) {
		return false
	}
	return true
}

var _ fabric.InvocationDispatcher = (*Dispatcher)(nil)

type admissionStream struct {
	fabric.InvocationStream
	cleanup func()
	once    sync.Once
	err     error
}

func (s *admissionStream) Close() error {
	s.once.Do(func() { s.cleanup(); s.err = s.InvocationStream.Close() })
	return s.err
}
func (s *admissionStream) Next(ctx context.Context) (fabric.InvocationFrame, error) {
	frame, err := s.InvocationStream.Next(ctx)
	if err != nil || frame.Kind == fabric.FrameComplete || frame.Kind == fabric.FrameError {
		_ = s.Close()
	}
	return frame, err
}

// ReplayAssociation forwards actual retained source metadata; a fresh stream
// remains explicitly unassociated. Admission never invents a replay relation.
func (s *admissionStream) ReplayAssociation() *fabric.ReplayAssociation {
	if source, ok := s.InvocationStream.(fabric.ReplayAssociatedStream); ok {
		if a := source.ReplayAssociation(); a != nil {
			if a.Validate() != nil {
				// Preserve an invalid association as a rejection, never as a fresh
				// stream, without copying oversized adapter-owned metadata.
				return &fabric.ReplayAssociation{}
			}
			owned := a.Clone()
			return &owned
		}
	}
	return nil
}
