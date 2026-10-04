package extension

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
)

// Outcome contains either a bounded unary result, a pull stream, or a durable
// suspension identity. Resume capabilities never form part of caller results.
type Outcome struct {
	Response   json.RawMessage
	Stream     fabric.InvocationStream
	DeferredID string
}
type Downstream func(context.Context, fabric.ExecutionContext, fabric.Envelope) (Outcome, error)
type MatchResolver func(context.Context, fabric.ExecutionContext, fabric.Envelope, string, Placement) (MatchContext, error)

// FinalValidator runs after all request mutations and on every redirected
// dispatch, immediately before endpoint admission. It must verify current
// descriptor, authority and finalized input; it does not execute an endpoint.
type FinalValidator func(context.Context, fabric.ExecutionContext, fabric.Envelope) error

type PipelineState struct {
	Format         string          `json:"format"`
	PlanRevision   string          `json:"planRevision"`
	Envelope       fabric.Envelope `json:"envelope"`
	Stage          string          `json:"stage"`
	Placement      Placement       `json:"placement"`
	Cursor         int             `json:"cursor"`
	Chain          []string        `json:"chain"`
	Entered        []string        `json:"entered"`
	Redirects      uint32          `json:"redirects"`
	VisitedTargets []string        `json:"visitedTargets,omitempty"`
	DeferralID     string          `json:"deferralId,omitempty"`
}

// ContinuationRecorder is trusted durable infrastructure, not approval logic.
// It must atomically persist the complete snapshot/constraints before returning,
// deduplicate DeferralID and deliver any secret only through its private binding.
type ContinuationRecorder interface {
	Save(context.Context, fabric.ExecutionContext, []byte, PipelineState, Deferral, CompiledRegistration) (string, error)
}
type Engine struct {
	plan          *Plan
	handlers      map[string]Handler
	executor      *Executor
	resolver      MatchResolver
	validate      FinalValidator
	continuations ContinuationRecorder
	maxRedirects  uint32
}

func NewEngine(plan *Plan, bindings *HandlerRegistry, executor *Executor, resolver MatchResolver, validator FinalValidator, continuations ContinuationRecorder, maxRedirects uint32) (*Engine, error) {
	if plan == nil || bindings == nil || executor == nil || resolver == nil || validator == nil || maxRedirects < 1 || maxRedirects > 64 {
		return nil, invalidRegistration()
	}
	bindings.mu.RLock()
	defer bindings.mu.RUnlock()
	handlers := make(map[string]Handler, len(bindings.bindings))
	for id, handler := range bindings.bindings {
		handlers[id] = handler
	}
	for _, chain := range plan.chains {
		for _, r := range chain {
			if handlers[r.Registration.Binding] == nil {
				return nil, fabric.NewError(fabric.CodeTargetUnavailable, "Extension binding is not installed")
			}
		}
	}
	return &Engine{plan: plan, handlers: handlers, executor: executor, resolver: resolver, validate: validator, continuations: continuations, maxRedirects: maxRedirects}, nil
}

// ExecuteStage starts from exact authenticated bytes. The configured downstream
// selects no alternate target; discover/describe stages receive read-only ports
// in node composition. Invocations reenter this dispatch stage on REDIRECT.
func (e *Engine) ExecuteStage(ctx context.Context, caller fabric.ExecutionContext, original []byte, audience, stage string, placement Placement, downstream Downstream) (Outcome, error) {
	if ctx == nil || downstream == nil || !fabric.ValidNamespacedName(stage) || placement == PlacementRelay {
		return Outcome{}, fabric.NewError(fabric.CodeInvalidInput, "Invalid plaintext execution stage")
	}
	envelope, err := caller.DecodeVerifiedEnvelope(original, audience)
	if err != nil {
		return Outcome{}, err
	}
	if placement != PlacementSource && placement != PlacementDestination {
		return Outcome{}, invalidRegistration()
	}
	state := PipelineState{Format: "pagnet.pipeline.v1", PlanRevision: e.plan.Revision(), Envelope: envelope, Stage: stage, Placement: placement}
	if envelope.Target != nil {
		state.VisitedTargets = []string{envelope.Target.String()}
	}
	return e.runWithDeadline(ctx, caller, append([]byte(nil), original...), state, downstream, false)
}

// ResumeStage accepts only a freshly claimed, authenticated infrastructure
// snapshot. The owner invokes it once AFTER ContinuationStore claim validation;
// it must not be called for an old or uncertain claim. Same-plan validation
// prevents continuing under silently changed extension configuration.
func (e *Engine) ResumeStage(ctx context.Context, permit *ResumePermit, caller fabric.ExecutionContext, original []byte, state PipelineState, downstream Downstream) (Outcome, error) {
	if ctx == nil || downstream == nil || state.Format != "pagnet.pipeline.v1" || state.PlanRevision != e.plan.Revision() || state.DeferralID == "" || state.Cursor < 0 || state.Cursor > len(state.Chain) || len(state.Entered) > 4096 || len(state.VisitedTargets) > 65 || state.Redirects > e.maxRedirects {
		return Outcome{}, fabric.NewError(fabric.CodeStaleContinuation, "Continuation pipeline is stale")
	}
	// Original authentication is restored by the trusted continuation authority,
	// not by interpreting caller-controlled serialized ExecutionContext fields.
	if _, err := caller.DecodeVerifiedEnvelope(original, caller.Audience()); err != nil {
		return Outcome{}, err
	}
	if state.Envelope.Validate() != nil {
		return Outcome{}, fabric.NewError(fabric.CodeProtocolError, "Invalid continuation envelope")
	}
	if err := permit.consume(caller, original, state); err != nil {
		return Outcome{}, err
	}
	return e.runWithDeadline(ctx, caller, append([]byte(nil), original...), state, downstream, true)
}
func (e *Engine) runWithDeadline(ctx context.Context, caller fabric.ExecutionContext, original []byte, state PipelineState, downstream Downstream, resuming bool) (Outcome, error) {
	lifetime, cancel := context.WithCancel(ctx)
	if state.Envelope.Context.Deadline != nil {
		var deadlineCancel context.CancelFunc
		lifetime, deadlineCancel = context.WithDeadline(lifetime, *state.Envelope.Context.Deadline)
		prior := cancel
		cancel = func() { deadlineCancel(); prior() }
	}
	outcome, err := e.run(lifetime, caller, original, state, downstream, resuming)
	if err != nil || outcome.Stream == nil {
		cancel()
		return outcome, err
	}
	outcome.Stream = &lifetimeStream{upstream: outcome.Stream, cancel: cancel}
	return outcome, nil
}
func (e *Engine) run(ctx context.Context, caller fabric.ExecutionContext, original []byte, state PipelineState, downstream Downstream, resuming bool) (Outcome, error) {
	stack, err := e.resolveEntered(state.Entered)
	if err != nil {
		return Outcome{}, err
	}
	var chain []CompiledRegistration
	if resuming {
		chain, err = e.resolveEntered(state.Chain)
	} else {
		chain, err = e.selectChain(ctx, caller, state)
	}
	if err != nil {
		return e.unwind(ctx, state.Envelope, stack, Outcome{}, err)
	}
	for {
		if ctx.Err() != nil {
			return e.unwind(ctx, state.Envelope, stack, Outcome{}, ctx.Err())
		}
		redirected := false
		for index := state.Cursor; index < len(chain); index++ {
			registration := chain[index]
			r := registration.Registration
			if !containsPhase(r.Phases, PhaseRequest) {
				stack = append(stack, registration)
				continue
			}
			request := e.request(state.Envelope, state.Stage, registration, PhaseRequest)
			decision, err := e.call(ctx, registration, request, false)
			if err != nil {
				return e.unwind(ctx, state.Envelope, stack, Outcome{}, err)
			}
			switch decision.Action {
			case Continue:
				stack = append(stack, registration)
			case Modify:
				modified, err := ApplyPatch(state.Envelope, registration.ExtensionID, decision.Patch)
				if err != nil {
					return e.unwind(ctx, state.Envelope, stack, Outcome{}, err)
				}
				state.Envelope = modified
				stack = append(stack, registration)
			case Reject:
				return e.unwind(ctx, state.Envelope, stack, Outcome{}, decision.Failure)
			case Respond:
				return e.unwind(ctx, state.Envelope, stack, Outcome{Response: append(json.RawMessage(nil), decision.Response...)}, nil)
			case Redirect:
				target := decision.Redirect.Ref.String()
				if state.Redirects >= e.maxRedirects || contains(state.VisitedTargets, target) {
					return e.unwind(ctx, state.Envelope, stack, Outcome{}, fabric.NewError(fabric.CodeRedirectLoop, "Redirect limit or cycle"))
				}
				stack = append(stack, registration)
				state.Redirects++
				state.VisitedTargets = append(state.VisitedTargets, target)
				ref := decision.Redirect.Ref
				state.Envelope.Target = &ref
				state.Envelope.ExpectedRevision = decision.Redirect.ExpectedRevision
				state.Cursor = 0
				state.Stage = "invoke.dispatch"
				chain, err = e.selectChain(ctx, caller, state)
				if err != nil {
					return e.unwind(ctx, state.Envelope, stack, Outcome{}, err)
				}
				redirected = true
			case Defer:
				if e.continuations == nil {
					return e.unwind(ctx, state.Envelope, stack, Outcome{}, fabric.NewError(fabric.CodeUnsupported, "Continuation store is not configured"))
				}
				stack = append(stack, registration)
				state.Cursor = index + 1
				state.Chain = registrationIDs(chain)
				state.Entered = registrationIDs(stack)
				// An authenticated invocation/plan/interceptor/position identifies exactly
				// one suspension. Ambiguous persistence retries cannot invent another ID.
				originalDigest := sha256.Sum256(original)
				framed, _ := json.Marshal([]any{"pagnet.fabric.continuation.v1", caller.PrincipalView(), caller.Audience(), hex.EncodeToString(originalDigest[:]), state.Envelope.ID, state.PlanRevision, r.ID, state.Stage, state.Cursor, state.Redirects, state.Entered})
				hash := sha256.Sum256(framed)
				state.DeferralID = hex.EncodeToString(hash[:])
				id, err := e.continuations.Save(ctx, caller, original, state, *decision.Deferral, registration)
				if err != nil {
					return Outcome{}, err
				}
				if id == "" {
					return Outcome{}, fabric.NewError(fabric.CodeProtocolError, "Missing durable continuation")
				}
				return Outcome{DeferredID: id}, nil
			}
			if redirected {
				break
			}
		}
		if redirected {
			continue
		}
		break
	}
	if err := e.validate(ctx, caller, state.Envelope); err != nil {
		return e.unwind(ctx, state.Envelope, stack, Outcome{}, err)
	}
	if ctx.Err() != nil {
		return e.unwind(ctx, state.Envelope, stack, Outcome{}, ctx.Err())
	}
	outcome, err := downstream(ctx, caller, state.Envelope)
	if outcome.Stream != nil {
		if err != nil || len(outcome.Response) != 0 || outcome.DeferredID != "" {
			_ = outcome.Stream.Close()
			return e.unwind(ctx, state.Envelope, stack, Outcome{}, fabric.NewError(fabric.CodeProtocolError, "Contradictory endpoint result"))
		}
		// No content is buffered for response/error/completion hooks. A consumer's
		// Next controls both upstream demand and inline chunk observation.
		checked, checkErr := fabric.NewCheckedStream(ctx, state.Envelope.ID, outcome.Stream)
		if checkErr != nil {
			_ = outcome.Stream.Close()
			return Outcome{}, checkErr
		}
		stream := newInterceptedStream(ctx, e, state.Envelope, state.Stage, stack, checked)
		return Outcome{Stream: stream}, nil
	}
	return e.unwind(ctx, state.Envelope, stack, outcome, err)
}
func (e *Engine) selectChain(ctx context.Context, caller fabric.ExecutionContext, state PipelineState) ([]CompiledRegistration, error) {
	match, err := e.resolver(ctx, caller, state.Envelope, state.Stage, state.Placement)
	if err != nil {
		return nil, err
	}
	// The resolver cannot accidentally change system stage/placement/operation.
	match.Operation = state.Envelope.Operation
	match.Stage = state.Stage
	match.Placement = state.Placement
	match.ExecutingInterceptors = caller.ProvenanceView().ExtensionChain
	return e.plan.Select(match), nil
}
func (e *Engine) resolveEntered(ids []string) ([]CompiledRegistration, error) {
	result := make([]CompiledRegistration, 0, len(ids))
	for _, id := range ids {
		r, ok := e.plan.byID[id]
		if !ok {
			return nil, fabric.NewError(fabric.CodeStaleContinuation, "Continuation interceptor is unavailable")
		}
		result = append(result, cloneRegistration(r))
	}
	return result, nil
}
func registrationIDs(chain []CompiledRegistration) []string {
	result := make([]string, len(chain))
	for i, r := range chain {
		result[i] = r.Registration.ID
	}
	return result
}
func (e *Engine) request(envelope fabric.Envelope, stage string, r CompiledRegistration, phase Phase) InterceptRequest {
	return InterceptRequest{ProtocolVersion: fabric.CurrentProtocolVersion, InterceptorID: r.Registration.ID, Operation: envelope.Operation, Stage: stage, Phase: phase, Envelope: envelope}
}
func (e *Engine) call(ctx context.Context, r CompiledRegistration, request InterceptRequest, started bool) (Decision, error) {
	if ctx.Err() != nil {
		return Decision{}, ctx.Err()
	}
	decision, err := e.executor.Call(ctx, r, e.handlers[r.Registration.Binding], request)
	if ctx.Err() != nil {
		return Decision{}, ctx.Err()
	}
	if err == nil {
		err = ValidateDecision(request, decision, started, time.Now())
	}
	if err != nil {
		if r.Registration.FailureMode == FailOpen {
			return Decision{Action: Continue}, nil
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return Decision{}, fabric.NewError(fabric.CodeInterceptorTimeout, "Interceptor timed out")
		}
		return Decision{}, fabric.NewError(fabric.CodeProtocolError, "Interceptor failed")
	}
	return decision, nil
}
func (e *Engine) unwind(ctx context.Context, envelope fabric.Envelope, stack []CompiledRegistration, outcome Outcome, failure error) (Outcome, error) {
	if ctx.Err() != nil {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		ctx = cleanup
	}
	for index := len(stack) - 1; index >= 0; index-- {
		r := stack[index]
		phase := PhaseResponse
		if failure != nil {
			phase = PhaseError
		}
		if !containsPhase(r.Registration.Phases, phase) {
			continue
		}
		request := e.request(envelope, r.Registration.Match.Stage, r, phase)
		request.Response = outcome.Response
		if failure != nil {
			var structured *fabric.Error
			if errors.As(failure, &structured) {
				copy := *structured
				request.Failure = &copy
			} else {
				request.Failure = fabric.NewError(fabric.CodeProtocolError, "Downstream failed")
			}
		}
		decision, err := e.call(ctx, r, request, false)
		if err != nil {
			failure = err
			outcome = Outcome{}
			continue
		}
		if decision.Action == Reject {
			failure = decision.Failure
			outcome = Outcome{}
		}
	}
	if failure != nil {
		return Outcome{}, failure
	}
	return outcome, nil
}
