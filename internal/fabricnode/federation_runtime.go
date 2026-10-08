package fabricnode

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/federation"
)

// FederationRuntime owns bounded destination executions independently of relay
// delivery. It never makes current caller evidence from receipts or starts work
// after an ambiguous attempt. Its Node is the genuine configured local service.
type FederationRuntime struct {
	boundary   *RemoteBoundary
	node       *Node
	admissions *federation.AdmissionLedger
	outputs    *FinalOutputs
	ctx        context.Context
	cancel     context.CancelFunc
	mu         sync.Mutex
	active     int
	max        int
	closed     bool
	done       chan struct{}
	wg         sync.WaitGroup

	// Per-invocation execution contexts for the in-flight stop port: an
	// invocation's pipeline runs under its own cancel scope so a committed
	// stop intent can genuinely stop it (a completed invocation has no live
	// effect to stop).
	stopMu sync.Mutex
	stops  map[string]*federationExecStop
}

// federationExecStop is one invocation's execution stop scope; pointer
// identity distinguishes which Start registered a given entry.
type federationExecStop struct {
	cancel context.CancelFunc
}
type FederationRuntimeConfig struct {
	Boundary   *RemoteBoundary
	Node       *Node
	Admissions *federation.AdmissionLedger
	Outputs    *FinalOutputs
	Lifetime   context.Context
	MaxActive  int
}
type FederationStart struct {
	Association *federation.Association
	Error       error
}

func NewFederationRuntime(c FederationRuntimeConfig) (*FederationRuntime, error) {
	if c.Boundary == nil || c.Node == nil || c.Node.Store != c.Boundary.local.store || c.Node.Service == nil || c.Admissions == nil || c.Outputs == nil || c.Outputs.boundary != c.Boundary || c.Lifetime == nil || c.Lifetime.Err() != nil || c.MaxActive < 1 || c.MaxActive > 256 {
		return nil, localDenied()
	}
	ctx, cancel := context.WithCancel(c.Lifetime)
	return &FederationRuntime{boundary: c.Boundary, node: c.Node, admissions: c.Admissions, outputs: c.Outputs, ctx: ctx, cancel: cancel, max: c.MaxActive, done: make(chan struct{}), stops: map[string]*federationExecStop{}}, nil
}

// Start accepts only an actual decrypted source-root bundle. Network context
// governs waiting/delivery, not the owned original destination pipeline. A
// slot and durable original attempts precede every paid endpoint effect.
func (r *FederationRuntime) Start(delivery context.Context, bundle federation.ForwardBundle) (FederationStart, error) {
	if r == nil || delivery == nil || delivery.Err() != nil {
		return FederationStart{}, localDenied()
	}
	raw, e := federation.EncodeForwardBundle(bundle)
	if e != nil {
		return FederationStart{}, e
	}
	owned, e := federation.DecodeForwardBundle(raw)
	clear(raw)
	if e != nil {
		return FederationStart{}, e
	}
	r.mu.Lock()
	if r.closed || r.active >= r.max {
		r.mu.Unlock()
		return FederationStart{}, fabric.NewError(fabric.CodeTargetUnavailable, "Federation original execution capacity exhausted")
	}
	r.active++
	r.wg.Add(1)
	r.mu.Unlock()
	invocationID := owned.Proof.Frame.InvocationID
	execCtx, execCancel := context.WithCancel(r.ctx)
	execStop := &federationExecStop{cancel: execCancel}
	registered := false
	r.stopMu.Lock()
	if _, exists := r.stops[invocationID]; !exists {
		r.stops[invocationID] = execStop
		registered = true
	}
	r.stopMu.Unlock()
	ready := make(chan FederationStart, 1)
	go func() {
		defer r.wg.Done()
		defer func() { r.mu.Lock(); r.active--; r.mu.Unlock() }()
		defer func() {
			execCancel()
			if registered {
				r.stopMu.Lock()
				if r.stops[invocationID] == execStop {
					delete(r.stops, invocationID)
				}
				r.stopMu.Unlock()
			}
		}()
		var once sync.Once
		report := func(v FederationStart) { once.Do(func() { ready <- v }) }
		phase := "authenticate source"
		err := r.boundary.WithForwardRequest(execCtx, owned, func(ctx context.Context, caller fabric.ExecutionContext, evidence any) error {
			phase = "retain admission"
			admitted, _, e := r.admissions.Admit(ctx, r.boundary.config, owned, caller)
			if e != nil {
				return e
			}
			phase = "reserve final output"
			fresh, e := r.outputs.Reserve(ctx, caller.PrincipalView(), owned.Proof.Frame.InvocationID, owned.Forwarded, caller.AuthenticationEvidence().(*remoteRequestBinding).assertion)
			if e != nil {
				return e
			}
			if !fresh {
				return &fabric.Error{Code: "federation.RETAINED_EXECUTION", Message: "Original execution already exists; use a fresh authenticated control request", Effect: fabric.EffectUnknown}
			}
			phase = "claim original execution"
			attempt, fresh, e := r.admissions.MarkAttempt(ctx, r.boundary.config, admitted, caller)
			if e != nil {
				return e
			}
			if !fresh {
				return &fabric.Error{Code: "federation.EXECUTION_UNKNOWN", Message: "Original paid attempt is retained; it cannot be resent", Effect: fabric.EffectUnknown}
			}
			phase = "execute original node pipeline"
			result, e := r.node.Service.Execute(ctx, owned.Forwarded, evidence)
			if e != nil {
				return e
			}
			if result.Stream == nil {
				return fabric.NewError(fabric.CodeProtocolError, "Original invocation returned no source stream")
			}
			phase = "capture final pipeline"
			return r.outputs.DrainWithSource(ctx, result.Stream, func(ref FinalOutputReference) error {
				private, e := json.Marshal(ref)
				if e != nil || len(private) > 4096 {
					return localDenied()
				}
				association := federation.Association{Protocol: "pagnet.final-output.v1", BindingDigest: ref.Commitment, PrivateReference: private}
				if e = r.admissions.Associate(ctx, r.boundary.config, admitted, caller, attempt, association); e != nil {
					report(FederationStart{Error: e})
					return nil // capture the original pipeline; never resend an ambiguous association
				}
				report(FederationStart{Association: &association})
				return nil
			})
		})
		if err != nil {
			report(FederationStart{Error: fmt.Errorf("%s: %w", phase, err)})
		} else {
			report(FederationStart{})
		}
	}()
	select {
	case value := <-ready:
		return value, value.Error
	case <-delivery.Done():
		return FederationStart{}, delivery.Err()
	}
}

// Close cancels owned pipelines and joins their original finalization/unwind;
// caller timeout cannot turn incomplete cleanup into a successful close.
func (r *FederationRuntime) Close(ctx context.Context) error {
	if r == nil {
		return nil
	}
	if ctx == nil {
		return localDenied()
	}
	r.mu.Lock()
	if !r.closed {
		r.closed = true
		r.cancel()
		go func() { r.wg.Wait(); close(r.done) }()
	}
	done := r.done
	r.mu.Unlock()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// StopInvocation stops the in-flight execution pipeline for one retained
// invocation, when one is still running in this runtime. It returns whether a
// live pipeline was stopped; a completed invocation has nothing to stop. It
// never reports business completion or the stop intent's outcome — the
// committed head state carries the stop intent, the pipeline settles its own
// honest result.
func (r *FederationRuntime) StopInvocation(invocationID string) bool {
	if r == nil || invocationID == "" {
		return false
	}
	r.stopMu.Lock()
	defer r.stopMu.Unlock()
	stop, ok := r.stops[invocationID]
	if !ok {
		return false
	}
	stop.cancel()
	return true
}
