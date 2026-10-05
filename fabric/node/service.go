// Package node composes canonical operations without application reasoning.
package node

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math"
	"sync/atomic"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/events"
	"github.com/pagnet-code/pagnet/fabric/extension"
	"github.com/pagnet-code/pagnet/fabric/telemetry"
)

type SearchReader interface {
	Search(context.Context, fabric.DiscoverRequest) (fabric.DiscoverResult, error)
}

// Config is supplied by trusted composition. It does not select a cloud, model,
// authorization policy, or endpoint automatically.
type OperationInterceptors interface {
	ExecuteStage(context.Context, fabric.ExecutionContext, []byte, string, string, extension.Placement, extension.Downstream) (extension.Outcome, error)
	ExecuteReadProjection(context.Context, fabric.ExecutionContext, []byte, string, string, extension.Placement, json.RawMessage, extension.Downstream) (extension.Outcome, error)
}

// ReadResultValidator is current authority/disclosure validation supplied by
// trusted composition. It runs after cache shortcuts and response interception,
// so an extension cannot substitute stale or unauthorized registry data.
type ReadResultValidator func(context.Context, fabric.ExecutionContext, fabric.Envelope, Result) error

type Config struct {
	Audience               string
	Authenticator          fabric.Authenticator
	Search                 SearchReader
	Descriptors            fabric.DescriptorStore
	Dispatcher             fabric.InvocationDispatcher
	Interceptors           OperationInterceptors
	ValidateReadResult     ReadResultValidator
	InvocationPlacement    extension.Placement
	Events                 events.EventBus
	EventSource            string
	Tracing                telemetry.Provider
	ReplayVerifier         fabric.ReplayVerifier
	ResumeDispatchVerifier ResumeDispatchVerifier
}

type Service struct {
	config    Config
	eventLoss atomic.Uint64
}

func New(config Config) (*Service, error) {
	if config.Authenticator == nil || config.Audience == "" {
		return nil, fabric.NewError(fabric.CodeUnauthenticated, "Node requires an explicit authenticator and audience")
	}
	if config.Interceptors != nil && config.InvocationPlacement != "" && config.InvocationPlacement != extension.PlacementSource && config.InvocationPlacement != extension.PlacementDestination {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Invalid trusted node invocation placement")
	}
	if config.Events != nil && (config.EventSource == "" || len(config.EventSource) > 4096) {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Event observation requires an explicit node source")
	}
	return &Service{config: config}, nil
}

// Result carries exactly one operation result. Streams remain pull-driven;
// bindings encode frames without collecting the entire invocation response.
type Result struct {
	Discover                  *fabric.DiscoverResult
	Describe                  *fabric.DescribeResult
	Stream                    fabric.InvocationStream
	Replay                    *fabric.ReplayAssociation
	DeferredID                string
	DeferredNotificationError *fabric.Error
}

// Execute authenticates the ORIGINAL exact bytes before interpreting them.
// Every operation uses the same explicit caller-decides invocation model.
func (s *Service) Execute(ctx context.Context, exact []byte, peerEvidence any) (result Result, failure error) {
	if ctx == nil {
		return Result{}, fabric.NewError(fabric.CodeInvalidInput, "Missing operation context")
	}
	// Bound/validate before any authenticator allocates hashes or parses claims.
	var assertion fabric.Envelope
	if err := fabric.DecodeJSON(exact, &assertion); err != nil {
		return Result{}, err
	}
	trusted, err := s.config.Authenticator.Authenticate(ctx, fabric.AuthenticationRequest{ExactEnvelope: exact, Audience: s.config.Audience, PeerEvidence: peerEvidence})
	if err != nil {
		return Result{}, fabric.NewError(fabric.CodeUnauthenticated, "Request authentication failed")
	}
	envelope, err := trusted.DecodeVerifiedEnvelope(exact, s.config.Audience)
	if err != nil {
		return Result{}, err
	}
	ctx = context.WithValue(ctx, callerContextKey{}, trusted)
	ctx = context.WithValue(ctx, originalRequestKey{}, append([]byte(nil), exact...))
	var span telemetry.Span
	if s.config.Tracing != nil {
		target := ""
		if envelope.Target != nil {
			target = envelope.Target.String()
		}
		ctx, span = s.config.Tracing.Start(ctx, telemetry.Specification{Name: "pagnet." + string(envelope.Operation), InvocationID: envelope.ID, Target: target, Incoming: envelope.Trace})
	}
	if s.config.Events != nil || span != nil {
		s.publishLifecycle(ctx, envelope, "started")
		defer func() {
			disposition := "completed"
			if failure != nil {
				disposition = "failed"
			} else if result.DeferredID != "" {
				disposition = "deferred"
			} else if result.Stream != nil {
				result.Stream = &observedStream{InvocationStream: result.Stream, node: s, envelope: envelope, lifetime: ctx, span: span}
				return
			}
			s.publishLifecycle(ctx, envelope, disposition)
			if span != nil {
				span.End(disposition)
			}
		}()
	}
	if envelope.Context.Deadline != nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, *envelope.Context.Deadline)
		// Unary operations end here. Stream completion owns its context below.
		if envelope.Operation != fabric.OperationInvoke {
			defer cancel()
		} else {
			result, err := s.dispatchInvoke(ctx, trusted, exact, envelope)
			if err != nil {
				cancel()
				return Result{}, err
			}
			if result.Stream == nil {
				cancel()
			} else {
				result.Stream = &cancelStream{InvocationStream: result.Stream, cancel: cancel}
			}
			return result, nil
		}
	}
	if err := ctx.Err(); err != nil {
		return Result{}, contextError(err)
	}
	switch envelope.Operation {
	case fabric.OperationDiscover:
		return s.dispatchRead(ctx, trusted, exact, envelope)
	case fabric.OperationDescribe:
		return s.dispatchRead(ctx, trusted, exact, envelope)
	case fabric.OperationInvoke:
		return s.dispatchInvoke(ctx, trusted, exact, envelope)
	default:
		return Result{}, fabric.NewError(fabric.CodeUnsupported, "Unsupported operation")
	}
}

// CallerFromContext exposes only the verified in-process identity to trusted
// discovery/policy composition. Query parameters never establish this identity.
type callerContextKey struct{}
type originalRequestKey struct{}
type finalizedRequestKey struct{}

// FinalizedRequestFromContext exposes the exact engine-selected operation to
// trusted admission/adapter composition, alongside its separately authenticated
// original. Its private key cannot be installed by a wire/MCP assertion.
func FinalizedRequestFromContext(ctx context.Context) (fabric.ExecutionContext, []byte, []byte, bool) {
	caller, original, ok := OriginalRequestFromContext(ctx)
	if !ok {
		return fabric.ExecutionContext{}, nil, nil, false
	}
	finalized, ok := ctx.Value(finalizedRequestKey{}).([]byte)
	if !ok {
		return fabric.ExecutionContext{}, nil, nil, false
	}
	return caller, original, append([]byte(nil), finalized...), true
}

func CallerFromContext(ctx context.Context) (fabric.ExecutionContext, bool) {
	if ctx == nil {
		return fabric.ExecutionContext{}, false
	}
	c, ok := ctx.Value(callerContextKey{}).(fabric.ExecutionContext)
	return c, ok
}

// OriginalRequestFromContext is for trusted operation-stage composition only.
// The private key is installed AFTER authentication. Search parameters, tool
// arguments and serialized context assertions cannot create this capability.
// The returned bytes are an owned copy of the verified original, not a mutable
// reference into ingress storage or credentials for a downstream adapter.
func OriginalRequestFromContext(ctx context.Context) (fabric.ExecutionContext, []byte, bool) {
	caller, ok := CallerFromContext(ctx)
	if !ok {
		return fabric.ExecutionContext{}, nil, false
	}
	exact, ok := ctx.Value(originalRequestKey{}).([]byte)
	if !ok {
		return fabric.ExecutionContext{}, nil, false
	}
	return caller, append([]byte(nil), exact...), true
}

func (s *Service) dispatchInvoke(ctx context.Context, caller fabric.ExecutionContext, original []byte, envelope fabric.Envelope) (Result, error) {
	if s.config.Interceptors == nil {
		return s.invoke(ctx, caller, envelope)
	}
	placement := s.config.InvocationPlacement
	if placement == "" {
		placement = extension.PlacementSource
	}
	var replay *fabric.ReplayAssociation
	outcome, err := s.config.Interceptors.ExecuteStage(ctx, caller, original, s.config.Audience, "invoke.dispatch", placement, func(ctx context.Context, c fabric.ExecutionContext, current fabric.Envelope) (extension.Outcome, error) {
		result, err := s.invoke(ctx, c, current)
		if result.Replay != nil {
			owned := result.Replay.Clone()
			replay = &owned
		}
		return extension.Outcome{Stream: result.Stream}, err
	})
	if err != nil {
		return Result{}, publicError(err)
	}
	if outcome.DeferredID != "" {
		if outcome.Stream != nil || len(outcome.Response) != 0 {
			return Result{}, fabric.NewError(fabric.CodeProtocolError, "Contradictory pipeline result")
		}
		return Result{DeferredID: outcome.DeferredID, DeferredNotificationError: outcome.DeferredNotificationError}, nil
	}
	if outcome.Stream != nil {
		return Result{Stream: outcome.Stream, Replay: replay}, nil
	}
	if len(outcome.Response) != 0 {
		return Result{Stream: newUnaryStream(envelope.ID, outcome.Response)}, nil
	}
	return Result{}, fabric.NewError(fabric.CodeProtocolError, "Invocation pipeline returned no result")
}

func (s *Service) discover(ctx context.Context, envelope fabric.Envelope) (Result, error) {
	var request fabric.DiscoverRequest
	if err := fabric.DecodeJSON(envelope.Payload, &request); err != nil {
		return Result{}, err
	}
	if err := request.Validate(); err != nil {
		return Result{}, err
	}
	if s.config.Search == nil {
		return Result{}, fabric.NewError(fabric.CodeUnsupported, "Discovery backend is not configured")
	}
	result, err := s.config.Search.Search(ctx, request)
	if err != nil {
		return Result{}, publicError(err)
	}
	if len(result.Candidates) > request.Limit {
		return Result{}, fabric.NewError(fabric.CodeProtocolError, "Discovery backend exceeded candidate bound")
	}
	seen := make(map[fabric.EndpointRef]bool, len(result.Candidates))
	for _, candidate := range result.Candidates {
		if _, err := fabric.ParseEndpointRef(candidate.Document.Ref.String()); err != nil {
			return Result{}, fabric.NewError(fabric.CodeProtocolError, "Search returned an invalid reference")
		}
		if seen[candidate.Document.Ref] || math.IsNaN(candidate.Score) || math.IsInf(candidate.Score, 0) {
			return Result{}, fabric.NewError(fabric.CodeProtocolError, "Search returned duplicate candidates or invalid scores")
		}
		seen[candidate.Document.Ref] = true
	}
	return Result{Discover: &result}, nil
}

func (s *Service) describe(ctx context.Context, envelope fabric.Envelope) (Result, error) {
	var request fabric.DescribeRequest
	if err := fabric.DecodeJSON(envelope.Payload, &request); err != nil {
		return Result{}, err
	}
	if err := request.Validate(); err != nil {
		return Result{}, err
	}
	if s.config.Descriptors == nil {
		return Result{}, fabric.NewError(fabric.CodeUnsupported, "Descriptor store is not configured")
	}
	result := fabric.DescribeResult{Descriptions: make([]fabric.Description, 0, len(request.Selections))}
	for _, selection := range request.Selections {
		if err := ctx.Err(); err != nil {
			return Result{}, contextError(err)
		}
		item := fabric.Description{Ref: selection.Ref}
		if selection.Ref.IsOffer() {
			offer, err := s.config.Descriptors.GetOffer(ctx, selection.Ref, selection.ExpectedRevision)
			if err != nil {
				item.Error = publicError(err)
			} else if offer.Ref != selection.Ref || selection.ExpectedRevision != "" && offer.Revision != selection.ExpectedRevision {
				item.Error = fabric.NewError(fabric.CodeProtocolError, "Descriptor store returned a different offer or revision")
			} else {
				item.Offer = &offer
			}
		} else {
			endpoint, err := s.config.Descriptors.GetEndpoint(ctx, selection.Ref, selection.ExpectedRevision)
			if err != nil {
				item.Error = publicError(err)
			} else if endpoint.Ref != selection.Ref || selection.ExpectedRevision != "" && endpoint.Revision != selection.ExpectedRevision {
				item.Error = fabric.NewError(fabric.CodeProtocolError, "Descriptor store returned a different endpoint or revision")
			} else {
				item.Endpoint = &endpoint
				limit := selection.OffersLimit
				if limit == 0 {
					limit = 20
				}
				item.Offers, item.NextOffersCursor, err = s.config.Descriptors.ListOffers(ctx, selection.Ref, endpoint.Revision, selection.OffersCursor, limit)
				if err != nil {
					item.Endpoint = nil
					item.Error = publicError(err)
				} else if len(item.Offers) > limit {
					item.Endpoint = nil
					item.Offers = nil
					item.Error = fabric.NewError(fabric.CodeProtocolError, "Descriptor store exceeded offer page bound")
				} else {
					for _, offer := range item.Offers {
						if !offer.Ref.IsOffer() || offer.Ref.Endpoint() != selection.Ref {
							item.Endpoint = nil
							item.Offers = nil
							item.Error = fabric.NewError(fabric.CodeProtocolError, "Descriptor store returned a foreign offer")
							break
						}
					}
				}
			}
		}
		result.Descriptions = append(result.Descriptions, item)
	}
	return Result{Describe: &result}, nil
}

func (s *Service) invoke(ctx context.Context, trusted fabric.ExecutionContext, envelope fabric.Envelope) (Result, error) {
	if envelope.Operation != fabric.OperationInvoke {
		return Result{}, fabric.NewError(fabric.CodeProtocolError, "Expected invocation envelope")
	}
	if err := envelope.Validate(); err != nil {
		return Result{}, err
	}
	if err := ctx.Err(); err != nil {
		return Result{}, contextError(err)
	}
	if s.config.Dispatcher == nil {
		return Result{}, fabric.NewError(fabric.CodeUnsupported, "Invocation dispatcher is not configured")
	}
	request := fabric.InvokeRequest{InvocationID: envelope.ID, Target: *envelope.Target, ExpectedRevision: envelope.ExpectedRevision,
		Input: append(json.RawMessage(nil), envelope.Payload...), Deadline: envelope.Context.Deadline, IdempotencyKey: envelope.Context.IdempotencyKey}
	if err := request.Validate(); err != nil {
		return Result{}, err
	}
	finalized, err := json.Marshal(envelope)
	if err != nil {
		return Result{}, fabric.NewError(fabric.CodeProtocolError, "Invalid finalized invocation")
	}
	var bounded fabric.Envelope
	if fabric.DecodeJSON(finalized, &bounded) != nil {
		return Result{}, fabric.NewError(fabric.CodeInvalidInput, "Finalized invocation exceeds wire bounds")
	}
	// Freeze input from the same bounded final representation. JSON marshaling
	// may compact/escape RawMessage; the original authenticated bytes remain
	// separately retained, including numbers that exceed IEEE-754 precision.
	request.Input = append(json.RawMessage(nil), bounded.Payload...)
	ctx = context.WithValue(ctx, finalizedRequestKey{}, finalized)
	stream, err := s.config.Dispatcher.Invoke(ctx, trusted, request)
	if err != nil {
		return Result{}, publicError(err)
	}
	var checked *fabric.CheckedStream
	var replay *fabric.ReplayAssociation
	var metadata *fabric.ReplayAssociation
	if associated, ok := stream.(fabric.ReplayAssociatedStream); ok {
		metadata = associated.ReplayAssociation()
	}
	if metadata != nil {
		if err := metadata.Validate(); err != nil {
			_ = stream.Close()
			return Result{}, publicError(err)
		}
		a := metadata.Clone()
		_, original, ok := OriginalRequestFromContext(ctx)
		if !ok || request.IdempotencyKey == "" {
			_ = stream.Close()
			return Result{}, fabric.NewError(fabric.CodeUnauthenticated, "Replay requires authenticated original and explicit idempotency key")
		}
		current := fabric.ReplayRequest{Principal: envelope.Principal, RequestID: envelope.ID, Target: request.Target, ExpectedRevision: request.ExpectedRevision,
			OriginalRequestSHA: sha256.Sum256(original), FinalizedRequestSHA: sha256.Sum256(finalized), InputSHA: sha256.Sum256(request.Input), IdempotencySHA: sha256.Sum256([]byte(request.IdempotencyKey))}
		verified, verifyErr := fabric.VerifyReplayCorrelation(ctx, trusted, current, a, s.config.ReplayVerifier)
		if verifyErr != nil {
			_ = stream.Close()
			return Result{}, publicError(verifyErr)
		}
		replay = verified.Association()
		checked, err = fabric.NewCheckedReplayStream(ctx, envelope.ID, stream, verified)
	} else {
		checked, err = fabric.NewCheckedStream(ctx, envelope.ID, stream)
	}
	if err != nil {
		if stream != nil {
			_ = stream.Close()
		}
		return Result{}, err
	}
	return Result{Stream: checked, Replay: replay}, nil
}

type cancelStream struct {
	fabric.InvocationStream
	cancel context.CancelFunc
}

func (s *cancelStream) Close() error { s.cancel(); return s.InvocationStream.Close() }

func (s *cancelStream) Next(ctx context.Context) (fabric.InvocationFrame, error) {
	f, err := s.InvocationStream.Next(ctx)
	if err != nil || f.Kind == fabric.FrameComplete || f.Kind == fabric.FrameError {
		s.cancel()
	}
	return f, err
}

func publicError(err error) *fabric.Error {
	var structured *fabric.Error
	if errors.As(err, &structured) {
		copy := fabric.NewError(structured.Code, structured.Message)
		if len(copy.Code) > 256 {
			copy.Code = fabric.CodeProtocolError
		}
		switch structured.Effect {
		case fabric.EffectUnknown, fabric.EffectNotStarted, fabric.EffectCompleted:
			copy.Effect = structured.Effect
		}
		return copy
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return contextError(err)
	}
	return fabric.NewError(fabric.CodeTargetUnavailable, "Configured component failed")
}

func contextError(err error) *fabric.Error {
	if errors.Is(err, context.DeadlineExceeded) {
		return fabric.NewError(fabric.CodeDeadlineExceeded, "Operation deadline exceeded")
	}
	return fabric.NewError(fabric.CodeCancelled, "Operation cancelled")
}

func (s *cancelStream) WithOriginalCapture(ctx context.Context, next func(context.Context) error) error {
	return fabric.WithOriginalSourceCapture(ctx, s.InvocationStream, next)
}
func (s *cancelStream) OriginalSourceOwnership(ctx context.Context) (fabric.OriginalSourceOwnership, error) {
	return fabric.OriginalStreamOwnership(ctx, s.InvocationStream)
}
