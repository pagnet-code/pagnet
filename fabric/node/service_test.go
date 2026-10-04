package node

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
)

// These fixtures prove operation boundaries, not real runtime/provider effects.
type fixtureAuth struct{ principal fabric.Principal }

func (a fixtureAuth) Authenticate(_ context.Context, r fabric.AuthenticationRequest) (fabric.ExecutionContext, error) {
	if r.PeerEvidence != "verified-local-peer" {
		return fabric.ExecutionContext{}, errors.New("private authentication diagnostic")
	}
	return fabric.NewAuthenticatedContext(a.principal, r.Audience, r.ExactEnvelope)
}

type fixtureSearch struct {
	calls  int
	result fabric.DiscoverResult
}

func (s *fixtureSearch) Search(context.Context, fabric.DiscoverRequest) (fabric.DiscoverResult, error) {
	s.calls++
	return s.result, nil
}

type fixtureStore struct {
	endpoint                fabric.EndpointDescriptor
	offer                   fabric.OfferDescriptor
	headers, pages, schemas int
}

func (s *fixtureStore) GetEndpoint(context.Context, fabric.EndpointRef, fabric.Revision) (fabric.EndpointDescriptor, error) {
	s.headers++
	return s.endpoint, nil
}
func (s *fixtureStore) GetOffer(context.Context, fabric.EndpointRef, fabric.Revision) (fabric.OfferDescriptor, error) {
	s.schemas++
	return s.offer, nil
}
func (s *fixtureStore) ListOffers(context.Context, fabric.EndpointRef, fabric.Revision, string, int) ([]fabric.OfferSummary, string, error) {
	s.pages++
	return []fabric.OfferSummary{{Ref: s.offer.Ref, Revision: s.offer.Revision, Name: s.offer.Name}}, "page-2", nil
}

type fixtureDispatcher struct {
	requests []fabric.InvokeRequest
	err      error
	ctx      context.Context
}

func (d *fixtureDispatcher) Invoke(ctx context.Context, _ fabric.ExecutionContext, r fabric.InvokeRequest) (fabric.InvocationStream, error) {
	d.requests = append(d.requests, r)
	d.ctx = ctx
	if d.err != nil {
		return nil, d.err
	}
	return &fixtureFrames{frames: []fabric.InvocationFrame{{InvocationID: r.InvocationID, Kind: fabric.FrameStart}, {InvocationID: r.InvocationID, Sequence: 1, Kind: fabric.FrameComplete}}}, nil
}

type fixtureFrames struct{ frames []fabric.InvocationFrame }

func (s *fixtureFrames) Next(context.Context) (fabric.InvocationFrame, error) {
	if len(s.frames) == 0 {
		return fabric.InvocationFrame{}, io.EOF
	}
	f := s.frames[0]
	s.frames = s.frames[1:]
	return f, nil
}
func (*fixtureFrames) Close() error { return nil }

func setup(t *testing.T) (*Service, fabric.Envelope, *fixtureSearch, *fixtureStore, *fixtureDispatcher) {
	t.Helper()
	ref, err := fabric.NewEndpointRef(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	offerRef, err := ref.WithOfferID(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	p := fabric.Principal{Ref: "local:alice", Issuer: "local:owner", Kind: "actor.human"}
	search := &fixtureSearch{result: fabric.DiscoverResult{Candidates: []fabric.Candidate{{Document: fabric.SearchDocument{Ref: ref, Revision: "r1", Name: "Maria", Kind: "actor.agent"}}}, IndexRevision: "g1"}}
	store := &fixtureStore{endpoint: fabric.EndpointDescriptor{Ref: ref, Revision: "r1", Name: "Maria", Kind: "actor.agent"}, offer: fabric.OfferDescriptor{Ref: offerRef, Revision: "o1", Name: "Invoice", InputSchema: json.RawMessage(`{"type":"object"}`)}}
	dispatch := &fixtureDispatcher{}
	s, err := New(Config{Audience: "local:domain", Authenticator: fixtureAuth{p}, Search: search, Descriptors: store, Dispatcher: dispatch})
	if err != nil {
		t.Fatal(err)
	}
	e := fabric.Envelope{ProtocolVersion: fabric.CurrentProtocolVersion, ID: "invocation-1", Principal: p, Source: p.Ref, CreatedAt: time.Now().UTC(), Context: fabric.EnvelopeContext{Origin: p.Ref}}
	return s, e, search, store, dispatch
}
func execute(t *testing.T, s *Service, e fabric.Envelope) (Result, error) {
	t.Helper()
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return s.Execute(context.Background(), b, "verified-local-peer")
}

func TestDiscoverAndDescribeNeverInvoke(t *testing.T) {
	s, e, search, store, dispatch := setup(t)
	e.Operation = fabric.OperationDiscover
	e.Payload = json.RawMessage(`{"query":"invoices","scope":{},"limit":10}`)
	for i := 0; i < 3; i++ {
		r, err := execute(t, s, e)
		if err != nil || r.Discover == nil {
			t.Fatalf("Discovery: %+v %v", r, err)
		}
	}
	if search.calls != 3 || len(dispatch.requests) != 0 || store.schemas != 0 {
		t.Fatal("Discovery executed an endpoint or loaded schemas")
	}
	e.Operation = fabric.OperationDescribe
	e.Payload, _ = json.Marshal(fabric.DescribeRequest{Selections: []fabric.DescribeSelection{{Ref: store.endpoint.Ref, ExpectedRevision: "r1", OffersLimit: 10}}})
	r, err := execute(t, s, e)
	if err != nil {
		t.Fatal(err)
	}
	if r.Describe.Descriptions[0].NextOffersCursor != "page-2" || store.schemas != 0 || len(dispatch.requests) != 0 {
		t.Fatal("Parent description loaded sibling schemas or invoked")
	}
	e.Payload, _ = json.Marshal(fabric.DescribeRequest{Selections: []fabric.DescribeSelection{{Ref: store.offer.Ref, ExpectedRevision: "o1"}}})
	if _, err = execute(t, s, e); err != nil {
		t.Fatal(err)
	}
	if store.schemas != 1 || len(dispatch.requests) != 0 {
		t.Fatal("Exact offer did not load only selected schema")
	}
}

func TestInvokeUsesExactRememberedTargetWithoutDiscovery(t *testing.T) {
	s, e, search, store, dispatch := setup(t)
	e.Operation = fabric.OperationInvoke
	e.Target = &store.endpoint.Ref
	e.ExpectedRevision = "r1"
	e.Payload = json.RawMessage(`{"message":"Do the chosen work","invocationId":"forged","target":"foreign"}`)
	r, err := execute(t, s, e)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Stream.Close()
	if search.calls != 0 || len(dispatch.requests) != 1 || dispatch.requests[0].Target != *e.Target || dispatch.requests[0].InvocationID != e.ID || dispatch.requests[0].ExpectedRevision != "r1" {
		t.Fatal("Target, protected identity or revision changed")
	}
	if string(dispatch.requests[0].Input) != string(e.Payload) {
		t.Fatal("Caller input was reinterpreted")
	}
	for i := 0; i < 2; i++ {
		if _, err = r.Stream.Next(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
}

func TestUnavailableInvocationDoesNotRetryOrFindFallback(t *testing.T) {
	s, e, search, store, dispatch := setup(t)
	e.Operation = fabric.OperationInvoke
	e.Target = &store.endpoint.Ref
	e.Payload = json.RawMessage(`{}`)
	dispatch.err = fabric.NewError(fabric.CodeTargetUnavailable, "Selected endpoint is unavailable")
	_, err := execute(t, s, e)
	var structured *fabric.Error
	if !errors.As(err, &structured) || structured.Code != fabric.CodeTargetUnavailable || search.calls != 0 || len(dispatch.requests) != 1 {
		t.Fatal("Unavailable target caused hidden retry or fallback")
	}
}

func TestForgedPrincipalAndWireCapabilityNeverDispatch(t *testing.T) {
	s, e, search, _, dispatch := setup(t)
	e.Operation = fabric.OperationDiscover
	e.Payload = json.RawMessage(`{"query":"x","scope":{},"limit":1}`)
	e.Principal.Ref = "foreign:mallory"
	e.Source = e.Principal.Ref
	if _, err := execute(t, s, e); err == nil {
		t.Fatal("Wire principal authenticated itself")
	}
	if search.calls != 0 || len(dispatch.requests) != 0 {
		t.Fatal("Forged identity reached component")
	}
	b, _ := json.Marshal(e)
	if _, err := s.Execute(context.Background(), b, map[string]bool{"verified": true}); err == nil {
		t.Fatal("Wire verification boolean replaced peer evidence")
	}
}

func TestInvocationDeadlineContextEndsWithStream(t *testing.T) {
	s, e, _, store, dispatch := setup(t)
	e.Operation = fabric.OperationInvoke
	e.Target = &store.endpoint.Ref
	e.Payload = json.RawMessage(`{}`)
	deadline := time.Now().Add(time.Minute)
	e.Context.Deadline = &deadline
	r, err := execute(t, s, e)
	if err != nil {
		t.Fatal(err)
	}
	if dispatch.ctx.Err() != nil {
		t.Fatal("Invocation context cancelled on operation return")
	}
	for i := 0; i < 2; i++ {
		if _, err = r.Stream.Next(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if !errors.Is(dispatch.ctx.Err(), context.Canceled) {
		t.Fatal("Terminal frame retained deadline resources")
	}
}

func TestStaleDescriptorCannotReturnDifferentRealization(t *testing.T) {
	s, e, _, store, _ := setup(t)
	e.Operation = fabric.OperationDescribe
	e.Payload, _ = json.Marshal(fabric.DescribeRequest{Selections: []fabric.DescribeSelection{{Ref: store.endpoint.Ref, ExpectedRevision: "r0"}}})
	r, err := execute(t, s, e)
	if err != nil {
		t.Fatal(err)
	}
	if r.Describe.Descriptions[0].Error == nil || store.pages != 0 {
		t.Fatal("Store revision mismatch returned descriptor")
	}
}
