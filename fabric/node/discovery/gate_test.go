package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/extension"
	"github.com/pagnet-code/pagnet/fabric/node"
	"github.com/pagnet-code/pagnet/fabric/search"
	"github.com/pagnet-code/pagnet/fabric/search/hybrid"
)

type intercept func(context.Context, extension.InterceptRequest) (extension.Decision, error)

func (f intercept) Intercept(c context.Context, r extension.InterceptRequest) (extension.Decision, error) {
	return f(c, r)
}

type auth struct{ p fabric.Principal }

func (a auth) Authenticate(_ context.Context, r fabric.AuthenticationRequest) (fabric.ExecutionContext, error) {
	return fabric.NewAuthenticatedContext(a.p, r.Audience, r.ExactEnvelope)
}

type rerank func(context.Context, fabric.DiscoverRequest, []fabric.Candidate) ([]fabric.Candidate, error)

func (f rerank) Rerank(c context.Context, r fabric.DiscoverRequest, cs []fabric.Candidate) ([]fabric.Candidate, error) {
	return f(c, r, cs)
}

type dispatch struct{ calls int }

func (d *dispatch) Invoke(context.Context, fabric.ExecutionContext, fabric.InvokeRequest) (fabric.InvocationStream, error) {
	d.calls++
	return nil, errors.New("must not invoke")
}
func engine(t *testing.T, h intercept) *extension.Engine {
	t.Helper()
	m := extension.ExtensionManifest{ManifestVersion: "1.0", ID: "test.policy", Version: "1.0.0", MinProtocol: "1.0", MaxProtocol: "1.9", Interceptors: []extension.Registration{{ID: "test.policy.candidates", Match: extension.Match{Operation: fabric.OperationDiscover, Stage: "discover.candidates"}, Placement: extension.PlacementSource, Phases: []extension.Phase{extension.PhaseRequest, extension.PhaseResponse}, TimeoutMillis: 1000, Binding: "test.binding"}}}
	p, e := extension.Compile([]extension.ExtensionManifest{m}, 100)
	if e != nil {
		t.Fatal(e)
	}
	bindings := extension.NewHandlerRegistry()
	if e = bindings.Set("test.binding", h); e != nil {
		t.Fatal(e)
	}
	executor, _ := extension.NewExecutor(4)
	en, e := extension.NewEngine(p, bindings, executor, func(context.Context, fabric.ExecutionContext, fabric.Envelope, string, extension.Placement) (extension.MatchContext, error) {
		return extension.MatchContext{}, nil
	}, func(ctx context.Context, _ fabric.ExecutionContext, _ fabric.Envelope) error {
		if extension.ValidationStage(ctx) != "discover.candidates" {
			t.Error("wrong final stage")
		}
		return nil
	}, nil, 8)
	if e != nil {
		t.Fatal(e)
	}
	return en
}
func documents(t *testing.T) []fabric.SearchDocument {
	t.Helper()
	out := []fabric.SearchDocument{}
	for i := 0; i < 2; i++ {
		pub := make([]byte, 32)
		pub[0] = byte(i + 1)
		ref, e := fabric.NewEndpointRef(pub)
		if e != nil {
			t.Fatal(e)
		}
		out = append(out, fabric.SearchDocument{Ref: ref, Revision: "r1", Name: []string{"allowed", "restricted"}[i], ShortDescription: "invoice processor", Kind: "actor.agent"})
	}
	return out
}
func TestActualNodeEngineFiltersBeforeExternalReranker(t *testing.T) {
	for _, mode := range []string{"filter", "inject", "change-score", "change-request", "scope-changed", "stale-document", "redirect", "response-inject"} {
		t.Run(mode, func(t *testing.T) {
			docs := documents(t)
			handlerCalls, rerankCalls := 0, 0
			policy := fabric.Revision("policy1")
			validations := 0
			h := intercept(func(_ context.Context, r extension.InterceptRequest) (extension.Decision, error) {
				handlerCalls++
				if r.Phase == extension.PhaseResponse {
					return extension.Decision{Action: extension.Continue}, nil
				}
				var p Projection
				if fabric.DecodeJSON(r.Envelope.Payload, &p) != nil {
					t.Fatal("bad projection")
				}
				if mode == "scope-changed" {
					policy = "policy2"
				}
				if mode == "redirect" {
					return extension.Decision{Action: extension.Redirect, Redirect: &extension.RedirectTarget{Ref: docs[0].Ref}}, nil
				}
				selected := []fabric.Candidate{}
				for _, c := range p.Candidates {
					if c.Document.Ref == docs[0].Ref {
						selected = append(selected, c)
					}
				}
				if len(p.Candidates) > 0 {
					switch mode {
					case "response-inject":
						p.Candidates = []fabric.Candidate{{Document: docs[1], Score: 999}}
						bad, _ := json.Marshal(p)
						return extension.Decision{Action: extension.Respond, Response: bad}, nil
					case "inject":
						injected := docs[1]
						injected.Revision = "invented"
						selected = append(selected, fabric.Candidate{Document: injected, Score: 1})
					case "change-score":
						selected[0].Score += 1
					case "change-request":
						p.Request.Query = "other"
					}
				}
				value, _ := json.Marshal(selected)
				patch := json.RawMessage(`[ {"op":"replace","path":"/payload/candidates","value":` + string(value) + `} ]`)
				if mode == "change-request" && len(p.Candidates) > 0 {
					q, _ := json.Marshal(p.Request)
					patch = json.RawMessage(`[{"op":"replace","path":"/payload/request","value":` + string(q) + `}]`)
				}
				return extension.Decision{Action: extension.Modify, Patch: patch}, nil
			})
			gate, e := New(Config{Engine: engine(t, h), Audience: "test.audience", Placement: extension.PlacementSource, Scope: func(_ context.Context, c fabric.ExecutionContext, _ fabric.DiscoverRequest) (Scope, error) {
				if c.PrincipalView().Ref != "local:alice" {
					t.Error("caller lost")
				}
				return Scope{"alice-scope", policy}, nil
			}, ValidateDocument: func(_ context.Context, _ fabric.ExecutionContext, d fabric.SearchDocument) error {
				validations++
				if mode == "stale-document" {
					return errors.New("retired")
				}
				for _, expected := range docs {
					if equal(d, expected) {
						return nil
					}
				}
				return errors.New("unknown descriptor")
			}})
			if e != nil {
				t.Fatal(e)
			}
			lex, _ := search.New(search.Config{})
			for _, d := range docs {
				if e = lex.Upsert(context.Background(), d); e != nil {
					t.Fatal(e)
				}
			}
			backend, e := hybrid.New(hybrid.Config{Lexical: hybrid.Provider{ID: "lexical", Version: "1", Retriever: lex, CurrentRevision: lex.IndexRevision}, Gate: gate, Reranker: &hybrid.RerankProvider{ID: "explicit-external", Version: "1", External: true, Reranker: rerank(func(_ context.Context, _ fabric.DiscoverRequest, cs []fabric.Candidate) ([]fabric.Candidate, error) {
				rerankCalls++
				for _, c := range cs {
					if c.Document.Ref != docs[0].Ref {
						t.Error("restricted document externally disclosed")
					}
				}
				return cs, nil
			})}, DisclosureGate: func(context.Context, hybrid.Disclosure, fabric.DiscoverRequest, []fabric.Candidate) error { return nil }})
			if e != nil {
				t.Fatal(e)
			}
			p := fabric.Principal{Ref: "local:alice", Issuer: "local:owner", Kind: "actor.human"}
			d := &dispatch{}
			n, e := node.New(node.Config{Audience: "test.audience", Authenticator: auth{p}, Search: backend, Dispatcher: d})
			if e != nil {
				t.Fatal(e)
			}
			raw, _ := json.Marshal(fabric.Envelope{ProtocolVersion: fabric.CurrentProtocolVersion, ID: "discover1", Operation: fabric.OperationDiscover, Principal: p, Source: p.Ref, CreatedAt: time.Now().UTC(), Context: fabric.EnvelopeContext{Origin: p.Ref}, Payload: json.RawMessage(`{"query":"invoice","scope":{},"limit":10}`)})
			result, e := n.Execute(context.Background(), raw, nil)
			if mode == "filter" {
				if e != nil || result.Discover == nil || len(result.Discover.Candidates) != 1 || rerankCalls != 1 || validations < 2 {
					t.Fatal(result, e, rerankCalls, validations)
				}
			} else if e == nil || rerankCalls != 0 {
				t.Fatal("invalid projection leaked to external reranker", e, rerankCalls)
			}
			if handlerCalls == 0 && mode != "stale-document" {
				t.Fatal("actual extension stage bypassed")
			}
			if d.calls != 0 {
				t.Fatal("read operation invoked endpoint")
			}
		})
	}
}
func TestGateRejectsUntrustedContext(t *testing.T) {
	gate, e := New(Config{Engine: engine(t, func(context.Context, extension.InterceptRequest) (extension.Decision, error) {
		t.Fatal("untrusted query reached extension")
		return extension.Decision{}, nil
	}), Audience: "test.audience", Placement: extension.PlacementSource, Scope: func(context.Context, fabric.ExecutionContext, fabric.DiscoverRequest) (Scope, error) {
		t.Fatal("untrusted query reached policy")
		return Scope{}, nil
	}, ValidateDocument: func(context.Context, fabric.ExecutionContext, fabric.SearchDocument) error { return nil }})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = gate(context.Background(), fabric.DiscoverRequest{Query: "invoice", Limit: 10}, nil); e == nil {
		t.Fatal("wire labels authenticated a query")
	}
}
