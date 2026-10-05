package continuations

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/extension"
	"github.com/pagnet-code/pagnet/fabric/extension/continuation"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

var background = context.Background()

type handlerFunc func(context.Context, extension.InterceptRequest) (extension.Decision, error)

func (f handlerFunc) Intercept(c context.Context, r extension.InterceptRequest) (extension.Decision, error) {
	return f(c, r)
}

type rig struct {
	t                            *testing.T
	store                        *continuation.Store
	dir                          string
	domain                       *registry.Store
	owner, human                 fabric.Principal
	caller, resumer              fabric.ExecutionContext
	original                     []byte
	ref                          fabric.EndpointRef
	revision                     fabric.Revision
	manifests                    []extension.ExtensionManifest
	recorder                     *Recorder
	engine                       *extension.Engine
	notifications                []PrivateNotification
	restores, targets, validates atomic.Int32
	signature                    []byte
	pub                          ed25519.PublicKey
	targetProof                  []byte
	config                       Config
}

func fixture(t *testing.T) *rig {
	t.Helper()
	r := &rig{t: t, owner: fabric.Principal{Ref: "spiffe://local/agent", Kind: "local.agent", Issuer: "issuer:local-agents"}, human: fabric.Principal{Ref: "spiffe://local/human", Kind: "local.human", Issuer: "issuer:local-humans"}}
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	r.pub = pub
	r.domain, e = registry.Bootstrap(background, filepath.Join(t.TempDir(), "domain"), r.owner)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { r.domain.Close(); r.store.Close() })
	var genesis registry.GenesisBody
	if e = json.Unmarshal(r.domain.Genesis().Body, &genesis); e != nil {
		t.Fatal(e)
	}
	r.ref, e = fabric.NewEndpointRef(genesis.PublicKey)
	if e != nil {
		t.Fatal(e)
	}
	ownerCtx, e := fabric.NewAuthenticatedContext(r.owner, r.domain.Namespace(), []byte("trusted operator mutation"))
	if e != nil {
		t.Fatal(e)
	}
	r.revision, e = r.domain.Register(background, ownerCtx, fabric.RegistryUpdate{Descriptor: fabric.EndpointDescriptor{Ref: r.ref, Kind: "service.local", Name: "Private target", Description: "An explicitly registered fixture target", Bindings: []fabric.BindingSummary{{ID: "private", Protocol: "local.fixture", Version: "1"}}}})
	if e != nil {
		t.Fatal(e)
	}
	env := fabric.Envelope{ProtocolVersion: "1.0", ID: "invocation:one", Operation: fabric.OperationInvoke, Principal: r.owner, Source: r.owner.Ref, Target: &r.ref, ExpectedRevision: r.revision, CreatedAt: time.Now().UTC(), Payload: json.RawMessage(`{"objective":"private"}`), Context: fabric.EnvelopeContext{Origin: r.owner.Ref}}
	r.original, e = json.Marshal(env)
	if e != nil {
		t.Fatal(e)
	}
	r.signature = ed25519.Sign(key, r.original)
	if !ed25519.Verify(pub, r.original, r.signature) {
		t.Fatal("source authentication fixture")
	}
	r.caller, e = fabric.NewAuthenticatedContext(r.owner, r.domain.Namespace(), r.original)
	if e != nil {
		t.Fatal(e)
	}
	r.resumer, e = fabric.NewAuthenticatedContext(r.human, r.domain.Namespace(), []byte("verified private claim request"))
	if e != nil {
		t.Fatal(e)
	}
	r.dir = filepath.Join(t.TempDir(), "continuations")
	r.store, e = continuation.Bootstrap(background, r.dir, continuation.Scope{Audience: r.domain.Namespace()}, continuation.DefaultOptions())
	if e != nil {
		t.Fatal(e)
	}
	r.manifests = []extension.ExtensionManifest{{ManifestVersion: "1.0", ID: "local.approval", Version: "1", MinProtocol: "1.0", MaxProtocol: "1.9", Interceptors: []extension.Registration{{ID: "local.approval.check", Match: extension.Match{Operation: fabric.OperationInvoke, Stage: "invoke.dispatch"}, Placement: extension.PlacementSource, NeedsPlaintext: true, Phases: []extension.Phase{extension.PhaseRequest, extension.PhaseResponse, extension.PhaseCompletion}, TimeoutMillis: 1000, Binding: "private.approval"}}}}
	r.targetProof = []byte(`{"targetReceipt":"genuine-committed-private-adapter"}`)
	r.config = Config{Store: r.store, Audience: r.domain.Namespace(), ConfiguredPlan: func(context.Context) (ConfiguredPlan, error) {
		plan, e := extension.Compile(r.manifests, 100)
		raw, _ := json.Marshal(r.manifests)
		return ConfiguredPlan{Plan: plan, Evidence: raw}, e
	}, SettlementTimeout: time.Second,
		SaveDeferredAdmission: func(_ context.Context, c fabric.ExecutionContext, snapshot continuation.Snapshot) ([]byte, error) {
			if c.PrincipalView() != r.owner || !bytes.Equal(snapshot.OriginalEnvelope, r.original) {
				return nil, errors.New("fixture original mismatch")
			}
			return []byte(`{"fixtureAdmission":"explicit trusted test root"}`), nil
		},
		ResumeAuthority: func(ctx context.Context, resumer, original fabric.ExecutionContext, claim *ResumeClaim, next func(context.Context, fabric.ExecutionContext) error) error {
			if resumer.PrincipalView() != r.human {
				return errors.New("wrong fixture resumer")
			}
			if _, _, e := claim.Consume(resumer); e != nil {
				return e
			}
			return next(ctx, original)
		},
		ResolvePrincipal: func(_ context.Context, ref string) (fabric.Principal, error) {
			if ref != r.human.Ref {
				return fabric.Principal{}, errors.New("not bound")
			}
			return r.human, nil
		},
		RestoreOriginal: func(_ context.Context, a HistoricalAdmission) (fabric.ExecutionContext, error) {
			r.restores.Add(1)
			if a.Principal != r.owner || a.Audience != r.domain.Namespace() || !bytes.Equal(a.OriginalBytes, r.original) || !ed25519.Verify(r.pub, a.OriginalBytes, r.signature) {
				return fabric.ExecutionContext{}, errors.New("original issuer/source proof not valid")
			}
			var body registry.GenesisBody
			if json.Unmarshal(r.domain.Genesis().Body, &body) != nil || body.Owner != a.Principal {
				return fabric.ExecutionContext{}, errors.New("historical owner binding changed")
			}
			return fabric.NewAuthenticatedForwardContext(a.Principal, a.Audience, a.OriginalBytes, a.Provenance)
		},
		Notify: func(_ context.Context, n PrivateNotification) error {
			r.notifications = append(r.notifications, n)
			return nil
		},
		VerifyEvidence: func(_ context.Context, _ fabric.ExecutionContext, e Evidence) (continuation.Outcome, error) {
			effect := fabric.EffectUnknown
			switch {
			case e.Kind == NoTarget:
				effect = fabric.EffectNotStarted
			case e.Kind == TargetUnary && bytes.Equal(e.Response, r.targetProof):
				effect = fabric.EffectCompleted
			case e.Kind == TargetTerminal && e.Frame != nil && e.Frame.Kind == fabric.FrameComplete && bytes.Equal(e.Frame.Data, r.targetProof):
				effect = fabric.EffectCompleted
			}
			return continuation.Outcome{Effect: effect, Data: []byte(`{"receipt":"private-adapter-verified"}`)}, nil
		}}
	r.recorder, e = New(r.config)
	if e != nil {
		t.Fatal(e)
	}
	r.engine = r.makeEngine(r.manifests, nil)
	return r
}
func (r *rig) makeEngine(manifests []extension.ExtensionManifest, custom handlerFunc) *extension.Engine {
	r.t.Helper()
	plan, e := extension.Compile(manifests, 100)
	if e != nil {
		r.t.Fatal(e)
	}
	bindings := extension.NewHandlerRegistry()
	handler := custom
	if handler == nil {
		handler = func(_ context.Context, request extension.InterceptRequest) (extension.Decision, error) {
			if request.Phase != extension.PhaseRequest {
				return extension.Decision{Action: extension.Continue}, nil
			}
			return extension.Decision{Action: extension.Defer, Deferral: &extension.Deferral{ExpiresAt: request.Envelope.CreatedAt.Add(time.Hour), ResumePrincipals: []string{r.human.Ref}, Durable: true}}, nil
		}
	}
	if e = bindings.Set("private.approval", handler); e != nil {
		r.t.Fatal(e)
	}
	executor, e := extension.NewExecutor(16)
	if e != nil {
		r.t.Fatal(e)
	}
	engine, e := extension.NewEngine(plan, bindings, executor, func(context.Context, fabric.ExecutionContext, fabric.Envelope, string, extension.Placement) (extension.MatchContext, error) {
		return extension.MatchContext{TargetKind: "service.local"}, nil
	}, func(ctx context.Context, c fabric.ExecutionContext, env fabric.Envelope) error {
		r.validates.Add(1)
		if c.PrincipalView() != r.owner {
			return errors.New("wrong original actor")
		}
		_, e := r.domain.Resolve(ctx, *env.Target, env.ExpectedRevision)
		return e
	}, r.recorder, 8)
	if e != nil {
		r.t.Fatal(e)
	}
	return engine
}
func (r *rig) deferWork() extension.Outcome {
	r.t.Helper()
	out, e := r.engine.ExecuteStage(background, r.caller, r.original, r.domain.Namespace(), "invoke.dispatch", extension.PlacementSource, r.downstream())
	if e != nil || out.DeferredID == "" || r.targets.Load() != 0 || r.validates.Load() != 0 || len(r.notifications) != 1 {
		r.t.Fatal("effects or disclosure before approval", out, e, r.targets.Load())
	}
	return out
}
func (r *rig) downstream() extension.Downstream {
	return func(context.Context, fabric.ExecutionContext, fabric.Envelope) (extension.Outcome, error) {
		r.targets.Add(1)
		return extension.Outcome{Response: append(json.RawMessage(nil), r.targetProof...)}, nil
	}
}
func claimID(label string) string { return hash([]byte(label)) }
func (r *rig) restart() {
	r.t.Helper()
	if e := r.store.Close(); e != nil {
		r.t.Fatal(e)
	}
	s, e := continuation.Open(background, r.dir, continuation.Scope{Audience: r.domain.Namespace()}, continuation.DefaultOptions())
	if e != nil {
		r.t.Fatal(e)
	}
	r.store = s
	r.config.Store = s
	r.recorder, e = New(r.config)
	if e != nil {
		r.t.Fatal(e)
	}
	r.engine = r.makeEngine(r.manifests, nil)
}
func TestActualRegistryDeferredRestartResumeNoDoubleClaim(t *testing.T) {
	r := fixture(t)
	out := r.deferWork()
	token := r.notifications[0].Capability.Token()
	r.restart()
	result, e := r.recorder.Resume(background, r.resumer, token, claimID("approval"), r.engine, r.downstream())
	if e != nil || !result.Claim.Fresh || r.targets.Load() != 1 || r.restores.Load() != 1 || r.validates.Load() != 1 {
		t.Fatal(result, e)
	}
	if result.Outcome.DeferredID != "" || !bytes.Equal(result.Outcome.Response, r.targetProof) {
		t.Fatal("wrong resumed response")
	}
	public, e := json.Marshal(result)
	if e != nil || bytes.Contains(public, []byte(token)) || bytes.Contains(public, r.original) {
		t.Fatal("private admission leaked", e)
	}
	retry, e := r.recorder.Resume(background, r.resumer, token, claimID("approval"), r.engine, r.downstream())
	if e != nil || retry.Claim.Fresh || retry.Claim.State != continuation.Complete || retry.Claim.Outcome.Effect != fabric.EffectCompleted || r.targets.Load() != 1 || r.restores.Load() != 1 {
		t.Fatal("duplicate executed", retry, e)
	}
	if _, e = r.recorder.Resume(background, r.resumer, token, claimID("other"), r.engine, r.downstream()); e == nil {
		t.Fatal("competing claim executed")
	}
	if out.DeferredID != result.Claim.Receipt.ID {
		t.Fatal("deferral identity changed")
	}
}
func TestWrongIssuerPlanStaleAndRevokedTargetHaveZeroEffects(t *testing.T) {
	for _, mode := range []string{"issuer", "plan", "target", "restorer", "binding"} {
		t.Run(mode, func(t *testing.T) {
			r := fixture(t)
			r.deferWork()
			token := r.notifications[0].Capability.Token()
			engine := r.engine
			resumer := r.resumer
			switch mode {
			case "issuer":
				p := r.human
				p.Issuer = "forged:issuer"
				resumer, _ = fabric.NewAuthenticatedContext(p, r.domain.Namespace(), []byte("forged assertion"))
			case "plan":
				changed := append([]extension.ExtensionManifest(nil), r.manifests...)
				changed[0].Version = "2"
				engine = r.makeEngine(changed, nil)
			case "target":
				operator, _ := fabric.NewAuthenticatedContext(r.owner, r.domain.Namespace(), []byte("trusted operator retirement"))
				if _, e := r.domain.Retire(background, operator, r.ref, r.revision); e != nil {
					t.Fatal(e)
				}
			case "binding":
				r.config.RestoreOriginal = func(context.Context, HistoricalAdmission) (fabric.ExecutionContext, error) {
					return fabric.NewAuthenticatedContext(r.owner, r.domain.Namespace(), []byte("different original proof"))
				}
				r.recorder, _ = New(r.config)
			case "restorer":
				r.config.RestoreOriginal = func(context.Context, HistoricalAdmission) (fabric.ExecutionContext, error) {
					return fabric.ExecutionContext{}, errors.New("issuer revoked")
				}
				r.recorder, _ = New(r.config)
			}
			_, e := r.recorder.Resume(background, resumer, token, claimID("approval"), engine, r.downstream())
			if e == nil || r.targets.Load() != 0 {
				t.Fatal("unauthorized effects", mode, e, r.targets.Load())
			}
			if mode == "issuer" && r.restores.Load() != 0 {
				t.Fatal("restored wrong issuer")
			}
		})
	}
}
func TestTargetCompletionPreservedBeforeResponseHookReject(t *testing.T) {
	r := fixture(t)
	r.engine = r.makeEngine(r.manifests, func(_ context.Context, request extension.InterceptRequest) (extension.Decision, error) {
		if request.Phase == extension.PhaseRequest {
			return extension.Decision{Action: extension.Defer, Deferral: &extension.Deferral{ExpiresAt: request.Envelope.CreatedAt.Add(time.Hour), ResumePrincipals: []string{r.human.Ref}, Durable: true}}, nil
		}
		return extension.Decision{Action: extension.Reject, Failure: fabric.NewError(fabric.CodeInterceptorRejected, "response withheld")}, nil
	})
	r.deferWork()
	token := r.notifications[0].Capability.Token()
	_, e := r.recorder.Resume(background, r.resumer, token, claimID("approval"), r.engine, r.downstream())
	if e == nil || r.targets.Load() != 1 {
		t.Fatal("response hook not rejected", e)
	}
	retry, e := r.recorder.Resume(background, r.resumer, token, claimID("approval"), r.engine, r.downstream())
	if e != nil || retry.Claim.Outcome == nil || retry.Claim.Outcome.Effect != fabric.EffectCompleted || retry.Claim.Fresh {
		t.Fatal("target completion overwritten by hook", retry, e)
	}
}
func TestArbitraryUnaryOutputDoesNotProveEffects(t *testing.T) {
	r := fixture(t)
	r.deferWork()
	token := r.notifications[0].Capability.Token()
	out, e := r.recorder.Resume(background, r.resumer, token, claimID("approval"), r.engine, func(context.Context, fabric.ExecutionContext, fabric.Envelope) (extension.Outcome, error) {
		return extension.Outcome{Response: json.RawMessage(`{"effect":"completed","trustMe":true}`)}, nil
	})
	if e != nil || !out.Claim.Fresh {
		t.Fatal(e)
	}
	retry, e := r.recorder.Resume(background, r.resumer, token, claimID("approval"), r.engine, r.downstream())
	if e != nil || retry.Claim.Outcome.Effect != fabric.EffectUnknown {
		t.Fatal("unverified output completed", retry, e)
	}
}

// The source adapter below has genuine pull-driven frames and a concurrent Close.
type frames struct {
	mu      sync.Mutex
	items   []fabric.InvocationFrame
	closed  chan struct{}
	once    sync.Once
	blocked chan struct{}
}

func (s *frames) Next(ctx context.Context) (fabric.InvocationFrame, error) {
	s.mu.Lock()
	if len(s.items) > 0 {
		f := s.items[0]
		s.items = s.items[1:]
		s.mu.Unlock()
		return f, nil
	}
	s.mu.Unlock()
	if s.blocked != nil {
		s.onceSignal()
		select {
		case <-s.closed:
			return fabric.InvocationFrame{}, context.Canceled
		case <-ctx.Done():
			return fabric.InvocationFrame{}, ctx.Err()
		}
	}
	return fabric.InvocationFrame{}, io.EOF
}
func (s *frames) onceSignal() {
	select {
	case s.blocked <- struct{}{}:
	default:
	}
}
func (s *frames) Close() error { s.once.Do(func() { close(s.closed) }); return nil }
func TestStreamingReceiptAndAbandonedConcurrentRead(t *testing.T) {
	for _, mode := range []string{"completed", "close", "timeout", "premature"} {
		t.Run(mode, func(t *testing.T) {
			r := fixture(t)
			r.deferWork()
			token := r.notifications[0].Capability.Token()
			source := &frames{closed: make(chan struct{}), items: []fabric.InvocationFrame{{InvocationID: "invocation:one", Sequence: 0, Kind: fabric.FrameStart}}}
			if mode == "completed" {
				source.items = append(source.items, fabric.InvocationFrame{InvocationID: "invocation:one", Sequence: 1, Kind: fabric.FrameComplete, Data: r.targetProof})
			}
			if mode == "close" || mode == "timeout" {
				source.blocked = make(chan struct{}, 1)
			}
			result, e := r.recorder.Resume(background, r.resumer, token, claimID("approval"), r.engine, func(context.Context, fabric.ExecutionContext, fabric.Envelope) (extension.Outcome, error) {
				r.targets.Add(1)
				return extension.Outcome{Stream: source}, nil
			})
			if e != nil || result.Outcome.Stream == nil {
				t.Fatal(e)
			}
			if _, e = result.Outcome.Stream.Next(background); e != nil {
				t.Fatal(e)
			}
			switch mode {
			case "completed":
				f, e := result.Outcome.Stream.Next(background)
				if e != nil || f.Kind != fabric.FrameComplete {
					t.Fatal(f, e)
				}
			case "premature":
				if _, e = result.Outcome.Stream.Next(background); e == nil {
					t.Fatal("premature EOF accepted")
				}
			case "timeout":
				c, cancel := context.WithTimeout(background, 20*time.Millisecond)
				defer cancel()
				if _, e = result.Outcome.Stream.Next(c); e == nil {
					t.Fatal("timeout accepted")
				}
			case "close":
				done := make(chan error, 1)
				go func() { _, e := result.Outcome.Stream.Next(background); done <- e }()
				select {
				case <-source.blocked:
				case <-time.After(time.Second):
					t.Fatal("source not reading")
				}
				if e = result.Outcome.Stream.Close(); e != nil {
					t.Fatal(e)
				}
				select {
				case e := <-done:
					if e == nil {
						t.Fatal("cancelled read succeeded")
					}
				case <-time.After(time.Second):
					t.Fatal("Close deadlocked Next")
				}
			}
			result.Outcome.Stream.Close()
			retry, e := r.recorder.Resume(background, r.resumer, token, claimID("approval"), r.engine, r.downstream())
			if e != nil || retry.Claim.Fresh || retry.Claim.Outcome == nil {
				t.Fatal(retry, e)
			}
			want := fabric.EffectUnknown
			if mode == "completed" {
				want = fabric.EffectCompleted
			}
			if retry.Claim.Outcome.Effect != want {
				t.Fatal("wrong genuine source state", retry.Claim.Outcome.Effect, want)
			}
		})
	}
}

func TestPrivateDeliveryLossDedupAndRotationMetadata(t *testing.T) {
	r := fixture(t)
	r.config.Notify = func(_ context.Context, n PrivateNotification) error {
		r.notifications = append(r.notifications, n)
		return errors.New("private delivery lost")
	}
	r.recorder, _ = New(r.config)
	r.engine = r.makeEngine(r.manifests, nil)
	first, e := r.engine.ExecuteStage(background, r.caller, r.original, r.domain.Namespace(), "invoke.dispatch", extension.PlacementSource, r.downstream())
	if e != nil || first.DeferredID == "" || first.DeferredNotificationError == nil || first.Stream != nil || len(r.notifications) != 1 || r.targets.Load() != 0 {
		t.Fatal("known commit lost to notification failure", first, e)
	}
	if first.DeferredID != r.notifications[0].ID {
		t.Fatal("committed ID discarded")
	}
	issued := r.notifications[0]
	retry, e := r.engine.ExecuteStage(background, r.caller, r.original, r.domain.Namespace(), "invoke.dispatch", extension.PlacementSource, r.downstream())
	if e != nil || retry.DeferredID != issued.ID || len(r.notifications) != 1 || r.targets.Load() != 0 {
		t.Fatal("ambiguous create reissued capability", retry, e)
	}
	rotated, e := r.recorder.RotatePending(background, r.resumer, issued.ID, 1)
	if e == nil || rotated.Revision != 2 || rotated.Delivered {
		t.Fatal("lost notification hid committed revision", rotated, e)
	}
	raw, _ := json.Marshal(rotated)
	if bytes.Contains(raw, []byte(r.notifications[1].Capability.Token())) {
		t.Fatal("metadata exposed rotated secret")
	}
	if _, e = r.recorder.Resume(background, r.resumer, issued.Capability.Token(), claimID("old"), r.engine, r.downstream()); e == nil {
		t.Fatal("old token survived rotation")
	}
	r.config.Notify = func(_ context.Context, n PrivateNotification) error {
		r.notifications = append(r.notifications, n)
		return nil
	}
	r.recorder, _ = New(r.config)
	rotated, e = r.recorder.RotatePending(background, r.resumer, issued.ID, rotated.Revision)
	if e != nil || !rotated.Delivered || rotated.Revision != 3 {
		t.Fatal(rotated, e)
	}
	if len(r.notifications[2].Recipients) != 1 || r.notifications[2].Recipients[0] != r.human {
		t.Fatal("rotated recipient changed")
	}
	if _, e = r.recorder.Resume(background, r.resumer, r.notifications[2].Capability.Token(), claimID("new"), r.engine, r.downstream()); e != nil {
		t.Fatal(e)
	}
}
func TestConcurrentClosePreservesAcceptedTargetCommit(t *testing.T) {
	r := fixture(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	verify := r.config.VerifyEvidence
	r.config.VerifyEvidence = func(ctx context.Context, c fabric.ExecutionContext, e Evidence) (continuation.Outcome, error) {
		if e.Kind == TargetTerminal {
			close(entered)
			<-release
		}
		return verify(ctx, c, e)
	}
	r.recorder, _ = New(r.config)
	r.engine = r.makeEngine(r.manifests, nil)
	r.deferWork()
	token := r.notifications[0].Capability.Token()
	source := &frames{closed: make(chan struct{}), items: []fabric.InvocationFrame{{InvocationID: "invocation:one", Sequence: 0, Kind: fabric.FrameStart}, {InvocationID: "invocation:one", Sequence: 1, Kind: fabric.FrameComplete, Data: r.targetProof}}}
	result, e := r.recorder.Resume(background, r.resumer, token, claimID("approval"), r.engine, func(context.Context, fabric.ExecutionContext, fabric.Envelope) (extension.Outcome, error) {
		return extension.Outcome{Stream: source}, nil
	})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = result.Outcome.Stream.Next(background); e != nil {
		t.Fatal(e)
	}
	readDone := make(chan error, 1)
	go func() { _, e := result.Outcome.Stream.Next(background); readDone <- e }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("genuine terminal not captured")
	}
	closed := make(chan error, 1)
	go func() { closed <- result.Outcome.Stream.Close() }()
	select {
	case <-source.closed:
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel producer")
	}
	close(release)
	select {
	case <-readDone:
	case <-time.After(time.Second):
		t.Fatal("Next deadlock")
	}
	select {
	case e := <-closed:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("Close deadlock")
	}
	retry, e := r.recorder.Resume(background, r.resumer, token, claimID("approval"), r.engine, r.downstream())
	if e != nil || retry.Claim.Outcome == nil || retry.Claim.Outcome.Effect != fabric.EffectCompleted {
		t.Fatal("Close erased original target terminal", retry, e)
	}
}

func TestApprovedResumeCacheRespondHasNoEndpointEffects(t *testing.T) {
	r := fixture(t)
	cache := r.manifests[0].Interceptors[0]
	cache.ID = "local.approval.cached"
	cache.After = []string{"local.approval.check"}
	r.manifests[0].Interceptors = append(r.manifests[0].Interceptors, cache)
	var e error
	r.recorder, e = New(r.config)
	if e != nil {
		t.Fatal(e)
	}
	r.engine = r.makeEngine(r.manifests, func(_ context.Context, request extension.InterceptRequest) (extension.Decision, error) {
		if request.Phase != extension.PhaseRequest {
			return extension.Decision{Action: extension.Continue}, nil
		}
		if request.InterceptorID == cache.ID {
			return extension.Decision{Action: extension.Respond, Response: json.RawMessage(`{"cached":true}`)}, nil
		}
		return extension.Decision{Action: extension.Defer, Deferral: &extension.Deferral{ExpiresAt: request.Envelope.CreatedAt.Add(time.Hour), ResumePrincipals: []string{r.human.Ref}, Durable: true}}, nil
	})
	r.deferWork()
	token := r.notifications[0].Capability.Token()
	result, e := r.recorder.Resume(background, r.resumer, token, claimID("approval"), r.engine, r.downstream())
	if e != nil || string(result.Outcome.Response) != `{"cached":true}` || r.targets.Load() != 0 || r.validates.Load() != 0 {
		t.Fatal("cache invoked target", result, e)
	}
	retry, e := r.recorder.Resume(background, r.resumer, token, claimID("approval"), r.engine, r.downstream())
	if e != nil || retry.Claim.Outcome == nil || retry.Claim.Outcome.Effect != fabric.EffectNotStarted {
		t.Fatal("cache pretended endpoint completion", retry, e)
	}
}
