package a2a

import (
	"bytes"
	"context"
	"encoding/json"
	sdk "github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2asrv"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/events/durable"
	"io"
	"iter"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type fixture struct {
	adapter   *Adapter
	endpoint  fabric.EndpointDescriptor
	caller    fabric.ExecutionContext
	store     *SQLiteStore
	storePath string
	server    *httptest.Server
	calls     atomic.Int32
	requests  [][]byte
	release   chan struct{}
}

func setup(t *testing.T, state sdk.TaskState, streaming bool) *fixture {
	return setupConfig(t, state, streaming, DefaultStoreConfig())
}
func setupConfig(t *testing.T, state sdk.TaskState, streaming bool, storeConfig StoreConfig) *fixture {
	t.Helper()
	f := &fixture{release: make(chan struct{})}
	t.Cleanup(func() { close(f.release) })
	exec := a2asrv.AgentExecutorFunc(func(ctx context.Context, c *a2asrv.ExecutorContext) iter.Seq2[sdk.Event, error] {
		return func(yield func(sdk.Event, error) bool) {
			task := sdk.NewSubmittedTask(c, c.Message)
			if !yield(task, nil) {
				return
			}
			if !yield(sdk.NewStatusUpdateEvent(task, sdk.TaskStateWorking, nil), nil) {
				return
			}
			first := sdk.NewArtifactEvent(task, sdk.NewDataPart(map[string]any{"large": uint64(9007199254740993)}))
			if !yield(first, nil) {
				return
			}
			update := sdk.NewArtifactUpdateEvent(task, first.Artifact.ID, sdk.NewTextPart("append"))
			update.LastChunk = true
			if !yield(update, nil) {
				return
			}
			if state == sdk.TaskStateWorking {
				select {
				case <-ctx.Done():
					return
				case <-f.release:
				}
				state = sdk.TaskStateCompleted
			}
			_ = yield(sdk.NewStatusUpdateEvent(task, state, nil), nil)
		}
	})
	official := a2asrv.NewJSONRPCHandler(a2asrv.NewHandler(exec))
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		raw, _ := io.ReadAll(r.Body)
		f.requests = append(f.requests, raw)
		r.Body = io.NopCloser(bytes.NewReader(raw))
		official.ServeHTTP(w, r)
	}))
	t.Cleanup(f.server.Close)
	var e error
	f.storePath = filepath.Join(t.TempDir(), "associations.sqlite")
	f.store, e = Bootstrap(context.Background(), f.storePath, testStoreScope(), storeConfig, testProtector(t))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = f.store.Close() })
	ref, _ := fabric.NewEndpointRef(make([]byte, 32))
	endpoint := sdk.NewAgentInterface(f.server.URL, sdk.TransportProtocolJSONRPC)
	card := &sdk.AgentCard{Name: "fixture", Version: "1", Capabilities: sdk.AgentCapabilities{Streaming: streaming}, SupportedInterfaces: []*sdk.AgentInterface{endpoint}}
	f.adapter, e = New(Config{Ref: ref, Revision: "r1", BindingID: "remote", BindingDigest: [32]byte{1}, Audience: "test.audience", Card: card, Interface: *endpoint, Cancellation: true, Associations: f.store, Credentials: func(context.Context, fabric.ExecutionContext, sdk.AgentInterface) (http.Header, error) {
		return http.Header{"Authorization": []string{"Bearer private-fixture"}}, nil
	}, DisclosureGate: func(context.Context, fabric.ExecutionContext, fabric.EndpointDescriptor, fabric.InvokeRequest) error {
		return nil
	}})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = f.adapter.Close() })
	f.endpoint = fabric.EndpointDescriptor{Ref: ref, Revision: "r1", Name: "remote", Kind: "service.a2a", Bindings: []fabric.BindingSummary{{ID: "remote", Protocol: "a2a", Version: "1.0", Streaming: streaming, Cancellation: true}}}
	f.caller, _ = fabric.NewAuthenticatedContext(fabric.Principal{Ref: "local:alice", Issuer: "local:owner", Kind: "actor.human"}, "test.audience", []byte("verified fixture"))
	return f
}
func (f *fixture) invoke(id, input string) (fabric.InvocationStream, error) {
	return f.adapter.Invoke(context.Background(), f.caller, f.endpoint, fabric.InvokeRequest{InvocationID: id, Target: f.endpoint.Ref, ExpectedRevision: f.endpoint.Revision, Input: json.RawMessage(input)})
}
func consume(t *testing.T, s fabric.InvocationStream) ([]byte, fabric.InvocationFrame) {
	t.Helper()
	defer s.Close()
	raw := []byte{}
	var end fabric.InvocationFrame
	seq := uint64(0)
	for {
		frame, e := s.Next(context.Background())
		if e == io.EOF {
			break
		}
		if e != nil {
			t.Fatal(e)
		}
		if frame.Sequence != seq {
			t.Fatal("order", frame)
		}
		seq++
		if frame.Kind == fabric.FrameChunk {
			raw = append(raw, frame.Data...)
		}
		end = frame
	}
	return raw, end
}
func TestOfficialSDKStreamExactEventsAndDurableAssociation(t *testing.T) {
	f := setup(t, sdk.TaskStateCompleted, true)
	s, e := f.invoke("first", `{"operation":"send","mode":"stream","parts":[{"data":{"large":9007199254740993}}]}`)
	if e != nil {
		t.Fatal(e)
	}
	raw, end := consume(t, s)
	if end.Kind != fabric.FrameComplete {
		t.Fatal(string(raw), end)
	}
	if !bytes.Contains(raw, []byte(`"large":9007199254740993`)) {
		t.Fatal("opaque output rounded", string(raw))
	}
	lines := bytes.Split(bytes.TrimSpace(raw), []byte{'\n'})
	if len(lines) != 5 {
		t.Fatal("events lost", len(lines), string(raw))
	}
	if !bytes.Contains(lines[2], []byte(`"artifactUpdate"`)) || !bytes.Contains(lines[3], []byte(`"append":true`)) || !bytes.Contains(lines[3], []byte(`"lastChunk":true`)) {
		t.Fatal("artifact semantics changed", string(raw))
	}
	if len(f.requests) != 1 || !bytes.Contains(f.requests[0], []byte(`"large":9007199254740993`)) {
		t.Fatal("opaque input rounded")
	}
	key := f.adapter.key(f.caller, "first")
	a, e := f.store.Lookup(context.Background(), key)
	if e != nil || a.TaskID == "" || a.ContextID == "" {
		t.Fatal(a, e)
	}
	if _, e = f.invoke("first", `{"operation":"send","mode":"stream","parts":[{"text":"again"}]}`); e == nil || f.calls.Load() != 1 {
		t.Fatal("automatic replay", e, f.calls.Load())
	}
	f.store.Close()
	f.store, e = Open(context.Background(), f.storePath, testStoreScope(), DefaultStoreConfig(), testProtector(t))
	if e != nil {
		t.Fatal(e)
	}
	f.adapter.config.Associations = f.store
	s, e = f.invoke("subscribe1", `{"operation":"subscribe","associationInvocation":"first"}`)
	if e != nil {
		t.Fatal(e)
	}
	_, end = consume(t, s)
	if end.Kind != fabric.FrameError || end.Error == nil || end.Error.Code != fabric.CodeUnsupported {
		t.Fatal("terminal subscription must be explicit unsupported", end)
	}
	s, e = f.invoke("get1", `{"operation":"get","associationInvocation":"first"}`)
	if e != nil {
		t.Fatal(e)
	}
	_, end = consume(t, s)
	if end.Kind != fabric.FrameComplete {
		t.Fatal(end)
	}
}
func TestTaskStatusesAreNotFabricatedCompletion(t *testing.T) {
	for _, state := range []sdk.TaskState{sdk.TaskStateAuthRequired, sdk.TaskStateInputRequired, sdk.TaskStateCanceled, sdk.TaskStateFailed} {
		t.Run(string(state), func(t *testing.T) {
			f := setup(t, state, true)
			s, e := f.invoke("stopped", `{"operation":"send","mode":"stream","parts":[{"text":"work"}]}`)
			if e != nil {
				t.Fatal(e)
			}
			raw, end := consume(t, s)
			if end.Kind != fabric.FrameError || !bytes.Contains(raw, []byte(state)) {
				t.Fatal("false completion", string(raw), end)
			}
		})
	}
}
func TestStreamingRefusedBeforeSDKUnaryFallback(t *testing.T) {
	f := setup(t, sdk.TaskStateCompleted, false)
	if _, e := f.invoke("unsupported", `{"operation":"send","mode":"stream","parts":[{"text":"work"}]}`); e == nil || f.calls.Load() != 0 {
		t.Fatal("SDK fallback invoked", e, f.calls.Load())
	}
}
func TestCredentialAndScopeRejectionBeforeHTTP(t *testing.T) {
	f := setup(t, sdk.TaskStateCompleted, true)
	req := fabric.InvokeRequest{InvocationID: "bad", Target: f.endpoint.Ref, ExpectedRevision: "old", Input: json.RawMessage(`{"operation":"send","mode":"stream","parts":[{"text":"work"}]}`)}
	if _, e := f.adapter.Invoke(context.Background(), f.caller, f.endpoint, req); e == nil {
		t.Fatal("stale binding accepted")
	}
	req.ExpectedRevision = "r1"
	if _, e := f.adapter.Invoke(context.Background(), fabric.ExecutionContext{}, f.endpoint, req); e == nil {
		t.Fatal("forged caller accepted")
	}
	f.adapter.config.Credentials = func(context.Context, fabric.ExecutionContext, sdk.AgentInterface) (http.Header, error) {
		return http.Header{"Idempotency-Key": []string{"unsafe"}}, nil
	}
	if _, e := f.adapter.Invoke(context.Background(), f.caller, f.endpoint, req); e == nil {
		t.Fatal("automatic transport replay header accepted")
	}
	if f.calls.Load() != 0 {
		t.Fatal("denied request disclosed")
	}
}
func TestSQLiteRestartAndCrossPrincipalIsolation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "owned.sqlite")
	s, e := Bootstrap(context.Background(), path, testStoreScope(), DefaultStoreConfig(), testProtector(t))
	if e != nil {
		t.Fatal(e)
	}
	ref, _ := fabric.NewEndpointRef(make([]byte, 32))
	key := AssociationKey{Principal: fabric.Principal{Ref: "local:alice", Issuer: "owner", Kind: "actor.human"}, Ref: ref, Revision: "r1", Binding: "private-hash", InvocationID: "first", Audience: "test.audience"}
	a := Association{Key: key, InputSHA: strings.Repeat("a", 64), Operation: "send", Mode: "stream"}
	if e = s.Admit(context.Background(), a); e != nil {
		t.Fatal(e)
	}
	if e = s.Associate(context.Background(), key, "remote-task", "remote-context"); e != nil {
		t.Fatal(e)
	}
	s.Close()
	s, e = Open(context.Background(), path, testStoreScope(), DefaultStoreConfig(), testProtector(t))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	found, e := s.Lookup(context.Background(), key)
	if e != nil || found.TaskID != "remote-task" {
		t.Fatal(found, e)
	}
	if e = s.Admit(context.Background(), a); e != ErrAttempted {
		t.Fatal("restart replay permitted", e)
	}
	wrong := key
	wrong.Principal.Ref = "local:bob"
	if _, e = s.Lookup(context.Background(), wrong); e == nil {
		t.Fatal("crossprincipal task lookup")
	}
	wrong = key
	wrong.Revision = "r2"
	if _, e = s.Lookup(context.Background(), wrong); e == nil {
		t.Fatal("stale revision lookup")
	}
	if e = s.Associate(context.Background(), key, "changed-task", "remote-context"); e == nil {
		t.Fatal("remote task association redirected")
	}
}
func TestCloseJoinsBlockedSDKNext(t *testing.T) {
	f := setup(t, sdk.TaskStateCompleted, true)
	entered := make(chan struct{})
	blocked := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		close(entered)
		<-r.Context().Done()
	}))
	defer blocked.Close()
	f.adapter.config.Interface.URL = blocked.URL
	f.adapter.card.SupportedInterfaces[0].URL = blocked.URL
	s, e := f.invoke("blocked", `{"operation":"send","mode":"stream","parts":[{"text":"work"}]}`)
	if e != nil {
		t.Fatal(e)
	}
	_, _ = s.Next(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _, _ = s.Next(context.Background()) }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("SDK request did not start")
	}
	closed := make(chan struct{})
	go func() { _ = s.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not cancel/join Next")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Next leaked")
	}
}

func TestOfficialSDKUnaryIsExactTaskSnapshot(t *testing.T) {
	f := setup(t, sdk.TaskStateCompleted, true)
	s, e := f.invoke("unary", `{"operation":"send","mode":"unary","parts":[{"text":"work"}]}`)
	if e != nil {
		t.Fatal(e)
	}
	raw, end := consume(t, s)
	if end.Kind != fabric.FrameComplete || bytes.Count(raw, []byte{'\n'}) != 1 || !bytes.Contains(raw, []byte(`"large":9007199254740993`)) {
		t.Fatal("unary result fabricated or rounded", string(raw), end)
	}
}
func TestOfficialSDKRestartSubscribeAndCancelOwnedTask(t *testing.T) {
	f := setup(t, sdk.TaskStateWorking, true)
	s, e := f.invoke("active", `{"operation":"send","mode":"stream","parts":[{"text":"work"}]}`)
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 3; i++ {
		if _, e = s.Next(context.Background()); e != nil {
			t.Fatal(e)
		}
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	f.store.Close()
	f.store, e = Open(context.Background(), f.storePath, testStoreScope(), DefaultStoreConfig(), testProtector(t))
	if e != nil {
		t.Fatal(e)
	}
	f.adapter.config.Associations = f.store
	before := f.calls.Load()
	bob, _ := fabric.NewAuthenticatedContext(fabric.Principal{Ref: "local:bob", Issuer: "local:owner", Kind: "actor.human"}, "test.audience", []byte("verified bob"))
	req := fabric.InvokeRequest{InvocationID: "foreign", Target: f.endpoint.Ref, ExpectedRevision: "r1", Input: json.RawMessage(`{"operation":"cancel","associationInvocation":"active"}`)}
	if _, e = f.adapter.Invoke(context.Background(), bob, f.endpoint, req); e == nil || f.calls.Load() != before {
		t.Fatal("foreign task cancel disclosed", e)
	}
	sub, e := f.invoke("resume", `{"operation":"subscribe","associationInvocation":"active"}`)
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 2; i++ {
		frame, e := sub.Next(context.Background())
		if e != nil || frame.Kind == fabric.FrameError {
			t.Fatal("owned subscription failed", frame, e)
		}
	}
	sub.Close()
	canceled, e := f.invoke("cancel", `{"operation":"cancel","associationInvocation":"active"}`)
	if e != nil {
		t.Fatal(e)
	}
	raw, end := consume(t, canceled)
	if end.Kind != fabric.FrameError || end.Error == nil || end.Error.Code != "a2a.STOPPED" || !bytes.Contains(raw, []byte(sdk.TaskStateCanceled)) {
		t.Fatal("cancellation falsely completed", string(raw), end)
	}
}

func TestSQLiteAdmissionHasOneWriter(t *testing.T) {
	s, e := Bootstrap(context.Background(), filepath.Join(t.TempDir(), "writers.sqlite"), testStoreScope(), DefaultStoreConfig(), testProtector(t))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	ref, _ := fabric.NewEndpointRef(make([]byte, 32))
	a := Association{Key: AssociationKey{Principal: fabric.Principal{Ref: "local:alice", Issuer: "owner", Kind: "actor.human"}, Ref: ref, Revision: "r1", Binding: "private", InvocationID: "exact", Audience: "test.audience"}, InputSHA: strings.Repeat("a", 64), Operation: "send", Mode: "stream"}
	answers := make(chan error, 16)
	for i := 0; i < 16; i++ {
		go func() { answers <- s.Admit(context.Background(), a) }()
	}
	accepted := 0
	for i := 0; i < 16; i++ {
		e := <-answers
		if e == nil {
			accepted++
		} else if e != ErrAttempted {
			t.Fatal(e)
		}
	}
	if accepted != 1 {
		t.Fatal("multiple initial effects admitted", accepted)
	}
}

func testStoreScope() StoreScope {
	ref, _ := fabric.NewEndpointRef(make([]byte, 32))
	return StoreScope{Domain: ref.Domain(), ID: "node-a2a", Audience: "test.audience"}
}
func testProtector(t *testing.T) DataProtector {
	t.Helper()
	p, e := durable.NewAESGCM(KeyReference{ID: "operator-test", Version: "1"}, bytes.Repeat([]byte{7}, 32))
	if e != nil {
		t.Fatal(e)
	}
	return p
}

func TestStructuredMessageIdentityIncludesFullPrincipal(t *testing.T) {
	first := fabric.Principal{Ref: "ab", Issuer: "owner", Kind: "actor.human"}
	second := fabric.Principal{Ref: "a", Issuer: "owner", Kind: "actor.human"}
	if messageIdentity("binding", first, "c") == messageIdentity("binding", second, "bc") {
		t.Fatal("concatenation identity collision")
	}
	sameRef := first
	sameRef.Issuer = "different-owner"
	if messageIdentity("binding", first, "c") == messageIdentity("binding", sameRef, "c") {
		t.Fatal("issuer omitted")
	}
	sameRef = first
	sameRef.Kind = "actor.service"
	if messageIdentity("binding", first, "c") == messageIdentity("binding", sameRef, "c") {
		t.Fatal("kind omitted")
	}
	if messageIdentity("binding", first, "c") == messageIdentity("other-binding", first, "c") {
		t.Fatal("binding omitted")
	}
	if messageIdentity("binding", first, "c") != messageIdentity("binding", first, "c") {
		t.Fatal("identity is nondeterministic")
	}
}
func TestSelectedProviderPrincipalChangeCannotReuseOwnedAssociation(t *testing.T) {
	f := setup(t, sdk.TaskStateCompleted, true)
	s, e := f.invoke("original", `{"operation":"send","mode":"stream","parts":[{"text":"work"}]}`)
	if e != nil {
		t.Fatal(e)
	}
	consume(t, s)
	config := f.adapter.config
	config.Card = f.adapter.card
	config.BindingDigest = [32]byte{}
	if invalid, e := New(config); e == nil {
		invalid.Close()
		t.Fatal("unbound provider principal accepted")
	}
	config.BindingDigest = [32]byte{2}
	config.Credentials = func(context.Context, fabric.ExecutionContext, sdk.AgentInterface) (http.Header, error) {
		return http.Header{"Authorization": []string{"Bearer explicitly-other-provider-account"}}, nil
	}
	replacement, e := New(config)
	if e != nil {
		t.Fatal(e)
	}
	defer replacement.Close()
	originalBinding := f.adapter.binding
	if len(f.requests) != 1 || !bytes.Contains(f.requests[0], []byte(messageIdentity(originalBinding, f.caller.PrincipalView(), "original"))) {
		t.Fatal("actual SDK request omitted structured message identity")
	}
	if replacement.binding == originalBinding {
		t.Fatal("provider principal digest omitted from binding")
	}
	before := f.calls.Load()
	req := fabric.InvokeRequest{InvocationID: "cancel-other-profile", Target: f.endpoint.Ref, ExpectedRevision: "r1", Input: json.RawMessage(`{"operation":"cancel","associationInvocation":"original"}`)}
	if _, e = replacement.Invoke(context.Background(), f.caller, f.endpoint, req); e == nil {
		t.Fatal("other provider account reused task")
	}
	req.InvocationID = "original"
	req.Input = json.RawMessage(`{"operation":"send","mode":"stream","parts":[{"text":"work"}]}`)
	if _, e = replacement.Invoke(context.Background(), f.caller, f.endpoint, req); e == nil {
		t.Fatal("changed profile replayed initial effect")
	}
	if f.calls.Load() != before {
		t.Fatal("profile mismatch reached HTTP")
	}
	// A credential rotation within the SAME declared principal profile preserves
	// the original binding and association; token bytes are not identity.
	config.BindingDigest = [32]byte{1}
	rotated, e := New(config)
	if e != nil {
		t.Fatal(e)
	}
	defer rotated.Close()
	if rotated.binding != originalBinding {
		t.Fatal("credential token incorrectly used as identity")
	}
	if _, e = f.store.Lookup(context.Background(), rotated.key(f.caller, "original")); e != nil {
		t.Fatal("same-principal token rotation lost association", e)
	}
}
