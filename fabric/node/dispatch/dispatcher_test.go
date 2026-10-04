package dispatch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/extension"
	"github.com/pagnet-code/pagnet/fabric/node"
)

// These fixtures exercise real node/engine/dispatcher composition. Endpoint
// effects are counted fixtures, not a claim of live native/provider execution.
type authenticator struct{ principal fabric.Principal }

func (a authenticator) Authenticate(_ context.Context, r fabric.AuthenticationRequest) (fabric.ExecutionContext, error) {
	if r.PeerEvidence != "owned-peer" {
		return fabric.ExecutionContext{}, errors.New("unverified peer")
	}
	return fabric.NewAuthenticatedContext(a.principal, r.Audience, r.ExactEnvelope)
}

type descriptors struct {
	endpoint         fabric.EndpointDescriptor
	offer            fabric.OfferDescriptor
	headers, schemas int
}

func (s *descriptors) GetEndpoint(context.Context, fabric.EndpointRef, fabric.Revision) (fabric.EndpointDescriptor, error) {
	s.headers++
	return s.endpoint, nil
}
func (s *descriptors) GetOffer(context.Context, fabric.EndpointRef, fabric.Revision) (fabric.OfferDescriptor, error) {
	s.schemas++
	return s.offer, nil
}
func (s *descriptors) ListOffers(context.Context, fabric.EndpointRef, fabric.Revision, string, int) ([]fabric.OfferSummary, string, error) {
	panic("dispatch must not enumerate sibling schemas")
}

type resolver struct {
	before    func()
	selection Selection
	calls     int
}

func (r *resolver) Select(context.Context, fabric.ExecutionContext, fabric.EndpointDescriptor, *fabric.OfferDescriptor) (Selection, error) {
	r.calls++
	if r.before != nil {
		r.before()
	}
	return r.selection, nil
}

type admission struct {
	mode            string
	original, final []byte
	delayed         func(context.Context) (fabric.InvocationStream, error)
	captured        context.Context
	calls           int
}

func (a *admission) WithDispatch(ctx context.Context, _ fabric.ExecutionContext, o, f []byte, _ fabric.EndpointDescriptor, _ *fabric.OfferDescriptor, _ Selection, next func(context.Context) (fabric.InvocationStream, error)) (fabric.InvocationStream, error) {
	a.calls++
	a.original = append([]byte(nil), o...)
	a.final = append([]byte(nil), f...)
	a.delayed = next
	a.captured = ctx
	switch a.mode {
	case "substitute":
		if _, err := next(ctx); err != nil {
			return nil, err
		}
		return &frames{id: "fabricated"}, nil
	case "discard-error":
		if _, err := next(ctx); err != nil {
			return nil, err
		}
		return nil, errors.New("admission failed after dispatch")
	case "missing":
		return nil, nil
	case "detached":
		return next(context.WithoutCancel(ctx))
	case "lost-context":
		return next(context.Background())
	case "double":
		s, e := next(ctx)
		if e != nil {
			return nil, e
		}
		_, e = next(ctx)
		if e == nil {
			return nil, errors.New("callback replay accepted")
		}
		return s, nil
	default:
		return next(ctx)
	}
}

type adapter struct {
	stream  *frames
	calls   int
	request fabric.InvokeRequest
	ctx     context.Context
	err     error
}

func (a *adapter) Invoke(ctx context.Context, _ fabric.ExecutionContext, _ fabric.EndpointDescriptor, r fabric.InvokeRequest) (fabric.InvocationStream, error) {
	a.calls++
	a.request = r
	a.ctx = ctx
	if a.err != nil {
		return nil, a.err
	}
	a.stream = &frames{id: r.InvocationID}
	return a.stream, nil
}

type frames struct {
	closed int
	id     string
	n      uint64
}

func (s *frames) Next(context.Context) (fabric.InvocationFrame, error) {
	if s.n > 1 {
		return fabric.InvocationFrame{}, io.EOF
	}
	k := fabric.FrameStart
	if s.n == 1 {
		k = fabric.FrameComplete
	}
	f := fabric.InvocationFrame{InvocationID: s.id, Sequence: s.n, Kind: k}
	s.n++
	return f, nil
}
func (s *frames) Close() error { s.closed++; return nil }

type handler func(context.Context, extension.InterceptRequest) (extension.Decision, error)

func (h handler) Intercept(c context.Context, r extension.InterceptRequest) (extension.Decision, error) {
	return h(c, r)
}
func setup(t *testing.T) (*node.Service, *Dispatcher, fabric.Envelope, *descriptors, *resolver, *admission, *adapter) {
	t.Helper()
	ref, e := fabric.NewEndpointRef(make([]byte, 32))
	if e != nil {
		t.Fatal(e)
	}
	offer, e := ref.WithOfferID(make([]byte, 32))
	if e != nil {
		t.Fatal(e)
	}
	p := fabric.Principal{Ref: "local:alice", Kind: "actor.human", Issuer: "local:owner"}
	store := &descriptors{endpoint: fabric.EndpointDescriptor{Ref: ref, Revision: "r1", Name: "ERP", Kind: "service.custom", Bindings: []fabric.BindingSummary{{ID: "owned-binding", Protocol: "custom"}}}, offer: fabric.OfferDescriptor{Ref: offer, Revision: "o1", Name: "invoice.get", BindingID: "owned-binding"}}
	adapter := &adapter{}
	res := &resolver{selection: Selection{BindingID: "owned-binding", EndpointRevision: "r1", Fingerprint: [32]byte{1}, Adapter: adapter}}
	adm := &admission{}
	d, e := New(Config{Audience: "local:domain", Descriptors: store, Bindings: res, Admission: adm})
	if e != nil {
		t.Fatal(e)
	}
	s, e := node.New(node.Config{Audience: "local:domain", Authenticator: authenticator{p}, Dispatcher: d})
	if e != nil {
		t.Fatal(e)
	}
	env := fabric.Envelope{ProtocolVersion: fabric.CurrentProtocolVersion, ID: "chosen-invocation", Operation: fabric.OperationInvoke, Principal: p, Source: p.Ref, Target: &ref, ExpectedRevision: "r1", Payload: json.RawMessage(`{"invoice":123}`), CreatedAt: time.Now().UTC(), Context: fabric.EnvelopeContext{Origin: p.Ref}}
	return s, d, env, store, res, adm, adapter
}
func execute(t *testing.T, s *node.Service, e fabric.Envelope) (node.Result, error) {
	t.Helper()
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return s.Execute(context.Background(), raw, "owned-peer")
}
func TestExactOfferDispatchLoadsOnlySelectedSchema(t *testing.T) {
	s, _, e, store, res, adm, a := setup(t)
	e.Target = &store.offer.Ref
	e.ExpectedRevision = "o1"
	result, err := execute(t, s, e)
	if err != nil {
		t.Fatal(err)
	}
	defer result.Stream.Close()
	if store.schemas != 1 || store.headers != 1 || res.calls != 1 || adm.calls != 1 || a.calls != 1 || a.request.Target != store.offer.Ref {
		t.Fatal("exact target or progressive disclosure violated")
	}
	for i := 0; i < 2; i++ {
		if _, err = result.Stream.Next(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if a.ctx.Err() == nil {
		t.Fatal("completed stream retained adapter lifetime")
	}
}
func TestStaleOrUnpublishedBindingNeverAdmits(t *testing.T) {
	for _, mode := range []string{"endpoint", "offer", "binding", "fingerprint", "published"} {
		t.Run(mode, func(t *testing.T) {
			s, _, e, store, res, adm, a := setup(t)
			switch mode {
			case "endpoint":
				store.endpoint.Revision = "r2"
			case "offer":
				e.Target = &store.offer.Ref
				e.ExpectedRevision = "old"
			case "binding":
				res.selection.BindingID = "other"
			case "fingerprint":
				res.selection.Fingerprint = [32]byte{}
			case "published":
				store.endpoint.Bindings = nil
			}
			r, err := execute(t, s, e)
			if r.Stream != nil {
				r.Stream.Close()
			}
			var structured *fabric.Error
			if !errors.As(err, &structured) || structured.Code != fabric.CodeStaleReference || adm.calls != 0 || a.calls != 0 {
				t.Fatalf("stale binding reached endpoint: %v", err)
			}
		})
	}
}
func TestAdmissionCannotReplayOrEscapeCallback(t *testing.T) {
	for _, mode := range []string{"double", "missing", "lost-context", "substitute", "discard-error"} {
		t.Run(mode, func(t *testing.T) {
			s, _, e, _, _, adm, a := setup(t)
			adm.mode = mode
			r, err := execute(t, s, e)
			if mode == "double" {
				if err != nil || a.calls != 1 {
					t.Fatal(err, a.calls)
				}
				r.Stream.Close()
			} else if mode == "substitute" || mode == "discard-error" {
				if err == nil || a.calls != 1 || a.stream.closed != 1 || a.ctx.Err() == nil {
					t.Fatal("substituted or leaked adapter stream", err)
				}
			} else if err == nil || a.calls != 0 {
				t.Fatal("invalid admission performed effects", err, a.calls)
			}
			if _, err = adm.delayed(adm.captured); err == nil {
				t.Fatal("escaped callback remained usable")
			}
			if a.calls > 1 {
				t.Fatal("callback replayed endpoint")
			}
		})
	}
}
func TestDirectAuthenticatedRequestStillRequiresNodeFinalization(t *testing.T) {
	_, d, e, _, _, adm, a := setup(t)
	raw, _ := json.Marshal(e)
	caller, err := fabric.NewAuthenticatedContext(e.Principal, "local:domain", raw)
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.Invoke(context.Background(), caller, fabric.InvokeRequest{InvocationID: e.ID, Target: *e.Target, ExpectedRevision: e.ExpectedRevision, Input: e.Payload})
	if err == nil || adm.calls != 0 || a.calls != 0 {
		t.Fatal("unfinalized request dispatched")
	}
}
func TestUnavailableEffectIsNotRetried(t *testing.T) {
	s, _, e, _, res, adm, a := setup(t)
	a.err = fabric.NewError(fabric.CodeTargetUnavailable, "unknown provider outcome")
	_, err := execute(t, s, e)
	if err == nil || a.calls != 1 || res.calls != 1 || adm.calls != 1 {
		t.Fatal("hidden replay or fallback", err, a.calls)
	}
}
func TestModifiedEnvelopePreservesOriginalAndFinalMetadata(t *testing.T) {
	s, d, e, _, _, adm, a := setup(t)
	manifest := extension.ExtensionManifest{ManifestVersion: "1.0", ID: "fixture.extension", Version: "1.0.0", MinProtocol: "1.0", MaxProtocol: "1.0", Interceptors: []extension.Registration{{ID: "fixture.extension.interceptor", Binding: "private", Placement: extension.PlacementSource, Match: extension.Match{Operation: fabric.OperationInvoke, Stage: "invoke.dispatch"}, Phases: []extension.Phase{extension.PhaseRequest}, TimeoutMillis: 1000}}}
	plan, err := extension.Compile([]extension.ExtensionManifest{manifest}, 10)
	if err != nil {
		t.Fatal(err)
	}
	handlers := extension.NewHandlerRegistry()
	handlers.Set("private", handler(func(context.Context, extension.InterceptRequest) (extension.Decision, error) {
		return extension.Decision{Action: extension.Modify, Patch: json.RawMessage(`[{"op":"replace","path":"/payload/invoice","value":456}]`)}, nil
	}))
	executor, _ := extension.NewExecutor(2)
	engine, err := extension.NewEngine(plan, handlers, executor, func(context.Context, fabric.ExecutionContext, fabric.Envelope, string, extension.Placement) (extension.MatchContext, error) {
		return extension.MatchContext{TargetKind: "service.custom"}, nil
	}, func(context.Context, fabric.ExecutionContext, fabric.Envelope) error { return nil }, nil, 8)
	if err != nil {
		t.Fatal(err)
	}
	s, err = node.New(node.Config{Audience: "local:domain", Authenticator: authenticator{e.Principal}, Dispatcher: d, Interceptors: engine})
	if err != nil {
		t.Fatal(err)
	}
	r, err := execute(t, s, e)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Stream.Close()
	var original, final fabric.Envelope
	if json.Unmarshal(adm.original, &original) != nil || json.Unmarshal(adm.final, &final) != nil {
		t.Fatal("missing original/final envelope")
	}
	if string(original.Payload) != `{"invoice":123}` || string(final.Payload) != `{"invoice":456}` || string(a.request.Input) != string(final.Payload) || original.ID != final.ID || original.Principal != final.Principal {
		t.Fatal("original authority or finalized input lost")
	}
}

func TestFinalizedInputPreservesJSONValues(t *testing.T) {
	for _, raw := range []string{`{ "text": "<html>&", "n": 9007199254740993 }`, "{\n  \"nested\": [ 1, 2 ]\n}"} {
		s, _, e, _, _, adm, a := setup(t)
		e.Payload = json.RawMessage(raw)
		exact, _ := json.Marshal(e)
		marshaledPayload, _ := json.Marshal(e.Payload)
		exact = bytes.Replace(exact, marshaledPayload, []byte(raw), 1)
		r, err := s.Execute(context.Background(), exact, "owned-peer")
		if err != nil {
			t.Fatal(err)
		}
		r.Stream.Close()
		var final fabric.Envelope
		if json.Unmarshal(adm.final, &final) != nil || string(final.Payload) != string(a.request.Input) {
			t.Fatal("frozen representations differ")
		}
		var original fabric.Envelope
		if json.Unmarshal(adm.original, &original) != nil || !bytes.Equal(adm.original, exact) || string(original.Payload) != raw {
			t.Fatal("original exact payload lost")
		}
		if bytes.Contains([]byte(raw), []byte("9007199254740993")) && !bytes.Contains(a.request.Input, []byte("9007199254740993")) {
			t.Fatal("large integer rounded")
		}
	}
}
func TestOriginalCancellationFencesDetachedAdmission(t *testing.T) {
	s, _, e, _, res, adm, a := setup(t)
	ctx, cancel := context.WithCancel(context.Background())
	res.before = cancel
	adm.mode = "detached"
	raw, _ := json.Marshal(e)
	_, err := s.Execute(ctx, raw, "owned-peer")
	if err == nil || a.calls != 0 {
		t.Fatal("canceled original performed endpoint effects", err)
	}
}

func TestRepeatedCloseReleasesUpstreamOnce(t *testing.T) {
	s, _, e, _, _, _, a := setup(t)
	r, err := execute(t, s, e)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err = r.Stream.Next(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 3; i++ {
		if err = r.Stream.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if a.stream.closed != 1 {
		t.Fatal("adapter closed repeatedly", a.stream.closed)
	}
}
