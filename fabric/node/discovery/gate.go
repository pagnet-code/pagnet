// Package discovery composes authenticated candidate filtering with extensions.
// It grants no authority and executes no discovered endpoints.
package discovery

import (
	"bytes"
	"context"
	"encoding/json"
	"math"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/extension"
	"github.com/pagnet-code/pagnet/fabric/node"
	"github.com/pagnet-code/pagnet/fabric/search/hybrid"
)

type Scope struct {
	Key            string
	PolicyRevision fabric.Revision
}
type ScopeProvider func(context.Context, fabric.ExecutionContext, fabric.DiscoverRequest) (Scope, error)
type DocumentValidator func(context.Context, fabric.ExecutionContext, fabric.SearchDocument) error
type Config struct {
	Engine           *extension.Engine
	Audience         string
	Placement        extension.Placement
	Scope            ScopeProvider
	ValidateDocument DocumentValidator
}
type Projection struct {
	Request    fabric.DiscoverRequest `json:"request"`
	Candidates []fabric.Candidate     `json:"candidates"`
}

func denied() error {
	return fabric.NewError(fabric.CodeInterceptorRejected, "Discovery candidate projection is not authorized")
}
func equal(a, b any) bool {
	x, e := json.Marshal(a)
	y, f := json.Marshal(b)
	return e == nil && f == nil && bytes.Equal(x, y)
}
func validScope(s Scope) bool {
	return s.Key != "" && len(s.Key) <= 1024 && s.PolicyRevision != "" && len(s.PolicyRevision) <= 256
}

// New requires trusted current-policy and fresh-registry validators. Scope keys
// never come from wire labels. The caller context is installed by node ingress.
func New(c Config) (hybrid.CandidateGate, error) {
	if c.Engine == nil || c.Audience == "" || c.Scope == nil || c.ValidateDocument == nil || (c.Placement != extension.PlacementSource && c.Placement != extension.PlacementDestination) {
		return nil, denied()
	}
	return func(ctx context.Context, r fabric.DiscoverRequest, cs []fabric.Candidate) (hybrid.GateResult, error) {
		caller, original, ok := node.OriginalRequestFromContext(ctx)
		if !ok {
			return hybrid.GateResult{}, denied()
		}
		envelope, err := caller.DecodeVerifiedEnvelope(original, c.Audience)
		if err != nil || envelope.Operation != fabric.OperationDiscover {
			return hybrid.GateResult{}, denied()
		}
		var wire fabric.DiscoverRequest
		if fabric.DecodeJSON(envelope.Payload, &wire) != nil || wire.Validate() != nil || r.Validate() != nil || r.Limit > 100 || len(cs) > 200 {
			return hybrid.GateResult{}, denied()
		}
		// Providers may use a larger finite retrieval horizon than the wire page.
		// Query, selected scope, filters, and cursor remain authenticated and exact.
		wire.Limit = r.Limit
		if !equal(wire, r) {
			return hybrid.GateResult{}, denied()
		}
		scope, err := c.Scope(ctx, caller, r)
		if err != nil {
			return hybrid.GateResult{}, err
		}
		if !validScope(scope) {
			return hybrid.GateResult{}, denied()
		}
		originals := map[string]fabric.Candidate{}
		for _, candidate := range cs {
			key := candidate.Document.Ref.String()
			if _, exists := originals[key]; exists || math.IsNaN(candidate.Score) || math.IsInf(candidate.Score, 0) {
				return hybrid.GateResult{}, denied()
			}
			if err = c.ValidateDocument(ctx, caller, candidate.Document); err != nil {
				return hybrid.GateResult{}, err
			}
			originals[key] = candidate
		}
		check := func(payload json.RawMessage) (Projection, error) {
			var p Projection
			if fabric.DecodeJSON(payload, &p) != nil || !equal(p.Request, r) || len(p.Candidates) > len(cs) {
				return p, denied()
			}
			seen := map[string]bool{}
			for _, candidate := range p.Candidates {
				key := candidate.Document.Ref.String()
				expected, exists := originals[key]
				if !exists || seen[key] || !equal(expected, candidate) {
					return p, denied()
				}
				seen[key] = true
			}
			return p, nil
		}
		payload, err := json.Marshal(Projection{Request: r, Candidates: cs})
		if err != nil {
			return hybrid.GateResult{}, denied()
		}
		out, err := c.Engine.ExecuteReadProjection(ctx, caller, original, c.Audience, "discover.candidates", c.Placement, payload, func(_ context.Context, _ fabric.ExecutionContext, current fabric.Envelope) (extension.Outcome, error) {
			p, e := check(current.Payload)
			if e != nil {
				return extension.Outcome{}, e
			}
			raw, e := json.Marshal(p)
			return extension.Outcome{Response: raw}, e
		})
		if err != nil {
			return hybrid.GateResult{}, err
		}
		if out.Stream != nil || out.DeferredID != "" {
			if out.Stream != nil {
				_ = out.Stream.Close()
			}
			return hybrid.GateResult{}, denied()
		}
		selected, err := check(out.Response)
		if err != nil {
			return hybrid.GateResult{}, err
		}
		fresh, err := c.Scope(ctx, caller, r)
		if err != nil {
			return hybrid.GateResult{}, err
		}
		if fresh != scope {
			return hybrid.GateResult{}, denied()
		}
		for _, candidate := range selected.Candidates {
			if err = c.ValidateDocument(ctx, caller, candidate.Document); err != nil {
				return hybrid.GateResult{}, err
			}
		}
		return hybrid.GateResult{ScopeKey: scope.Key, PolicyRevision: scope.PolicyRevision, Candidates: selected.Candidates}, nil
	}, nil
}
