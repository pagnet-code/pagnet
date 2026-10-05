//go:build linux || darwin

package fabricnode

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/adapters/mcp"
	"github.com/pagnet-code/pagnet/fabric/extension"
	"github.com/pagnet-code/pagnet/fabric/extension/continuation"
	extensionregistry "github.com/pagnet-code/pagnet/fabric/extension/registry"
	"github.com/pagnet-code/pagnet/fabric/localinstallation"
	"github.com/pagnet-code/pagnet/fabric/mcpbridge"
	"github.com/pagnet-code/pagnet/fabric/node"
	"github.com/pagnet-code/pagnet/fabric/node/continuations"
	"github.com/pagnet-code/pagnet/fabric/node/dispatch"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/fabricauth"
	"github.com/pagnet-code/pagnet/internal/fabricservices"
)

type continuationHandler func(context.Context, extension.InterceptRequest) (extension.Decision, error)

func (h continuationHandler) Intercept(ctx context.Context, r extension.InterceptRequest) (extension.Decision, error) {
	return h(ctx, r)
}

func TestActualKernelConfiguredDeferRestartResumeSameDispatchNoSecondEffect(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	private := t.TempDir()
	if err := os.Chmod(private, 0700); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(private, "fabric.sock")
	installed, err := localinstallation.Bootstrap(ctx, filepath.Join(private, "root"), localinstallation.Options{Settings: localinstallation.DefaultSettings(socket)})
	if err != nil {
		t.Fatal(err)
	}
	defer installed.Close()
	owner, err := installed.Operator(ctx)
	if err != nil {
		t.Fatal(err)
	}
	root := installed.Store.AuthorityIdentity()
	boundary, err := newLocalBoundary(ctx, installed.Store, owner, installed, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := fabricauth.New(fabricauth.Config{Root: root, RootOwner: root.Owner, Audience: root.Namespace, SocketPath: socket, CurrentRoot: installed.Store.CurrentAuthorityIdentity})
	if err != nil {
		t.Fatal(err)
	}
	boundary.sessions = auth
	session, closeSession := runtimeOwnerSession(t, ctx, &NativeRuntime{Authenticator: auth}, socket)
	defer closeSession()
	ref, _ := fabric.NewEndpointRef(root.PublicKey)
	rev, err := installed.Store.Register(ctx, owner, fabric.RegistryUpdate{Descriptor: fabric.EndpointDescriptor{Ref: ref, Kind: "service.mcp", Name: "Approved exact operation", Bindings: []fabric.BindingSummary{{ID: "mcp", Protocol: "mcp.tools", Version: "2026-07-28"}}}})
	if err != nil {
		t.Fatal(err)
	}
	scope := registry.DescriptorBatchScope{Endpoint: ref, ExpectedEndpointRevision: rev, BindingID: "mcp"}
	var effects atomic.Int32
	official := sdk.NewServer(&sdk.Implementation{Name: "approved-service", Version: "1"}, nil)
	official.AddTool(&sdk.Tool{Name: "echo", InputSchema: json.RawMessage(`{"type":"object","properties":{"input":{"type":"string"}},"required":["input"]}`)}, func(_ context.Context, r *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
		effects.Add(1)
		return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: string(r.Params.Arguments)}}}, nil
	})
	server := httptest.NewServer(sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return official }, &sdk.StreamableHTTPOptions{Stateless: true}))
	defer server.Close()
	profiles, err := fabricservices.NewProfileStore(ctx, installed.Store, installed.Operator, installed.Keys)
	if err != nil {
		t.Fatal(err)
	}
	account := [32]byte{91}
	_, err = profiles.Install(ctx, scope, fabricservices.Profile{Protocol: "mcp.tools", Version: "2026-07-28", CredentialSelector: "private approved account", BindingDigest: account, MCP: &fabricservices.MCPProfile{URL: server.URL, AllowHTTP: true, Limits: mcp.DefaultLimits}})
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := fabricservices.BootstrapInvocations(ctx, profiles, fabricservices.DefaultInvocationConfig(), boundary)
	if err != nil {
		t.Fatal(err)
	}
	connections, err := fabricservices.NewConnections(profiles, serviceRouterCredentials{account}, ledger, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer connections.Close()
	if err = connections.ConnectMCP(ctx, scope, true); err != nil {
		t.Fatal(err)
	}
	provider, err := NewServiceBindingProvider(connections)
	if err != nil {
		t.Fatal(err)
	}
	router, err := NewRouter(map[BindingProtocol]BindingProvider{{Protocol: "mcp.tools", Version: "2026-07-28"}: provider})
	if err != nil {
		t.Fatal(err)
	}
	offers, _, err := installed.Store.ListOffers(ctx, ref, rev, "", 2)
	if err != nil || len(offers) != 1 {
		t.Fatal(err, len(offers))
	}
	manifest := extension.ExtensionManifest{ManifestVersion: "1.0", ID: "local.approval", Version: "1", MinProtocol: "1.0", MaxProtocol: "1.0", Interceptors: []extension.Registration{{ID: "local.approval.check", Match: extension.Match{Operation: fabric.OperationInvoke, Stage: "invoke.dispatch"}, Placement: extension.PlacementSource, NeedsPlaintext: true, Phases: []extension.Phase{extension.PhaseRequest, extension.PhaseResponse, extension.PhaseCompletion}, TimeoutMillis: 1000, Binding: "private.approval"}}}
	extConfig := extensionregistry.DefaultConfig(installed.Store, installed.Keys, func(c context.Context, asserted fabric.ExecutionContext, _ registry.AuthorityIdentity) error {
		return installed.WithCurrentOperator(c, asserted, func(context.Context) error { return nil })
	})
	extensions, err := extensionregistry.Bootstrap(ctx, owner, extConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer extensions.Close()
	installedExtension, err := extensions.Install(ctx, owner, 1, extensionregistry.Installation{Manifest: manifest, Bindings: []extensionregistry.Binding{{ID: "private.approval", Protocol: "local.inline", Selector: "actual fixture approval handler", ProfileDigest: fmt.Sprintf("%x", sha256.Sum256([]byte("explicit-handler-v1")))}}})
	if err != nil {
		t.Fatal(err)
	}
	plans := func(context.Context) (continuations.ConfiguredPlan, error) {
		s, e := extensions.ConfiguredSnapshot()
		return continuations.ConfiguredPlan{Plan: s.Plan, Evidence: s.Evidence}, e
	}
	authority, err := NewLocalContinuationAuthority(boundary, plans, extensions.VerifyConfiguredPlanTx)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher, err := dispatch.New(dispatch.Config{Audience: root.Namespace, Descriptors: installed.Store, Bindings: router, Admission: boundary})
	if err != nil {
		t.Fatal(err)
	}
	service, err := node.New(node.Config{Audience: root.Namespace, Authenticator: auth, Descriptors: installed.Store, Dispatcher: dispatcher, ResumeDispatchVerifier: authority})
	if err != nil {
		t.Fatal(err)
	}
	storeDir := filepath.Join(private, "continuations")
	store, err := continuation.Bootstrap(ctx, storeDir, continuation.Scope{Audience: root.Namespace}, continuation.DefaultOptions(), installed.Keys)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { store.Close() }()
	var notification continuations.PrivateNotification
	config := continuations.Config{Store: store, Audience: root.Namespace, ConfiguredPlan: plans, SaveDeferredAdmission: authority.SaveDeferredAdmission, ResumeAuthority: authority.WithResume, RestoreOriginal: authority.RestoreOriginal, ResolvePrincipal: func(_ context.Context, ref string) (fabric.Principal, error) {
		if ref != root.Owner.Ref {
			return fabric.Principal{}, errors.New("not registered")
		}
		return root.Owner, nil
	}, Notify: func(_ context.Context, n continuations.PrivateNotification) error { notification = n; return nil }, VerifyEvidence: func(_ context.Context, _ fabric.ExecutionContext, e continuations.Evidence) (continuation.Outcome, error) {
		// This fixture does not pretend that arbitrary output is an endpoint receipt.
		// Unknown is truthful; the real SDK and signed service ledger prove effects.
		effect := fabric.EffectUnknown
		if e.Kind == continuations.NoTarget {
			effect = fabric.EffectNotStarted
		}
		return continuation.Outcome{Effect: effect, Data: []byte(`{}`)}, nil
	}, SettlementTimeout: time.Second}
	recorder, err := continuations.New(config)
	if err != nil {
		t.Fatal(err)
	}
	handlers := extension.NewHandlerRegistry()
	err = handlers.Set("private.approval", continuationHandler(func(_ context.Context, r extension.InterceptRequest) (extension.Decision, error) {
		if r.Phase != extension.PhaseRequest {
			return extension.Decision{Action: extension.Continue}, nil
		}
		return extension.Decision{Action: extension.Defer, Deferral: &extension.Deferral{Durable: true, ExpiresAt: time.Now().UTC().Add(time.Minute), ResumePrincipals: []string{root.Owner.Ref}}}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	executor, err := extension.NewExecutor(8)
	if err != nil {
		t.Fatal(err)
	}
	makeEngine := func(current *continuations.Recorder) *extension.Engine {
		plan, _ := plans(ctx)
		engine, err := extension.NewEngine(plan.Plan, handlers, executor, func(context.Context, fabric.ExecutionContext, fabric.Envelope, string, extension.Placement) (extension.MatchContext, error) {
			return extension.MatchContext{}, nil
		}, func(c context.Context, _ fabric.ExecutionContext, e fabric.Envelope) error {
			_, x := installed.Store.GetOffer(c, *e.Target, e.ExpectedRevision)
			return x
		}, current, 8)
		if err != nil {
			t.Fatal(err)
		}
		return engine
	}
	engine := makeEngine(recorder)
	deadline := time.Now().UTC().Add(time.Minute)
	original, proof, err := session.Build(ctx, mcpbridge.Call{Operation: fabric.OperationInvoke, Invoke: &fabric.InvokeRequest{Target: offers[0].Ref, ExpectedRevision: offers[0].Revision, Input: json.RawMessage(`{"input":"exact approved data"}`), Deadline: &deadline}})
	if err != nil {
		t.Fatal(err)
	}
	caller, err := auth.Authenticate(ctx, fabric.AuthenticationRequest{Audience: root.Namespace, ExactEnvelope: original, PeerEvidence: proof})
	if err != nil {
		t.Fatal(err)
	}
	downstream := func(c context.Context, o fabric.ExecutionContext, e fabric.Envelope) (extension.Outcome, error) {
		r, x := service.InvokeResumed(c, o, original, e)
		return extension.Outcome{Stream: r.Stream}, x
	}
	deferred, err := engine.ExecuteStage(ctx, caller, original, root.Namespace, "invoke.dispatch", extension.PlacementSource, downstream)
	if err != nil || deferred.DeferredID == "" || effects.Load() != 0 {
		t.Fatal("effect before actual approval", err, effects.Load())
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = continuation.Open(ctx, storeDir, continuation.Scope{Audience: root.Namespace}, continuation.DefaultOptions(), installed.Keys)
	if err != nil {
		t.Fatal(err)
	}
	config.Store = store
	recorder, err = continuations.New(config)
	if err != nil {
		t.Fatal(err)
	}
	resumerBytes, resumerProof, err := session.Build(ctx, mcpbridge.Call{Operation: fabric.OperationDiscover, Discover: &fabric.DiscoverRequest{Query: "private approval", Limit: 1}})
	if err != nil {
		t.Fatal(err)
	}
	resumer, err := auth.Authenticate(ctx, fabric.AuthenticationRequest{Audience: root.Namespace, ExactEnvelope: resumerBytes, PeerEvidence: resumerProof})
	if err != nil {
		t.Fatal(err)
	}
	claimID := sha256.Sum256([]byte("stable actual approval claim"))
	claim := fmt.Sprintf("%x", claimID)
	result, err := recorder.Resume(ctx, resumer, notification.Capability.Token(), claim, engine, downstream)
	if err != nil || result.Outcome.Stream == nil {
		t.Fatal("actual resumed node dispatch", err)
	}
	var complete bool
	for {
		f, x := result.Outcome.Stream.Next(ctx)
		if errors.Is(x, io.EOF) {
			break
		}
		if x != nil {
			t.Fatal(x)
		}
		complete = complete || f.Kind == fabric.FrameComplete
	}
	if err = result.Outcome.Stream.Close(); err != nil {
		t.Fatal(err)
	}
	if !complete || effects.Load() != 1 {
		t.Fatal("actual SDK effect/result", complete, effects.Load())
	}
	retry, err := recorder.Resume(ctx, resumer, notification.Capability.Token(), claim, engine, downstream)
	if err != nil || retry.Claim.Fresh || retry.Outcome.Stream != nil || effects.Load() != 1 {
		t.Fatal("claimed recovery reexecuted", err, effects.Load())
	}

	engine = makeEngine(recorder)
	deferAgain := func(ttl time.Duration) ([]byte, string) {
		limit := time.Now().UTC().Add(ttl)
		raw, peer, e := session.Build(ctx, mcpbridge.Call{Operation: fabric.OperationInvoke, Invoke: &fabric.InvokeRequest{Target: offers[0].Ref, ExpectedRevision: offers[0].Revision, Input: json.RawMessage(`{"input":"next independently approved data"}`), Deadline: &limit}})
		if e != nil {
			t.Fatal(e)
		}
		actual, e := auth.Authenticate(ctx, fabric.AuthenticationRequest{Audience: root.Namespace, ExactEnvelope: raw, PeerEvidence: peer})
		if e != nil {
			t.Fatal(e)
		}
		out, e := engine.ExecuteStage(ctx, actual, raw, root.Namespace, "invoke.dispatch", extension.PlacementSource, func(context.Context, fabric.ExecutionContext, fabric.Envelope) (extension.Outcome, error) {
			t.Fatal("new effects before approval")
			return extension.Outcome{}, nil
		})
		if e != nil || out.DeferredID == "" {
			t.Fatal(e)
		}
		return raw, notification.Capability.Token()
	}
	downstreamFor := func(raw []byte) extension.Downstream {
		return func(c context.Context, o fabric.ExecutionContext, e fabric.Envelope) (extension.Outcome, error) {
			r, x := service.InvokeResumed(c, o, raw, e)
			return extension.Outcome{Stream: r.Stream}, x
		}
	}
	stableClaim := func(name string) string { return fmt.Sprintf("%x", sha256.Sum256([]byte(name))) }
	expiredRaw, expiredToken := deferAgain(time.Second)
	var expiredEnvelope fabric.Envelope
	_ = fabric.DecodeJSON(expiredRaw, &expiredEnvelope)
	wait := time.NewTimer(time.Until(*expiredEnvelope.Context.Deadline))
	defer wait.Stop()
	select {
	case <-wait.C:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	expired, denied := recorder.Resume(ctx, resumer, expiredToken, stableClaim("expired-source"), engine, downstreamFor(expiredRaw))
	if denied == nil || expired.Outcome.Stream != nil || effects.Load() != 1 {
		t.Fatal("expired original paid deadline revived", denied, effects.Load())
	}
	staleRaw, staleToken := deferAgain(time.Minute)
	changed := extensionregistry.Installation{Manifest: manifest, Bindings: []extensionregistry.Binding{{ID: "private.approval", Protocol: "local.inline", Selector: "actual fixture approval handler", ProfileDigest: fmt.Sprintf("%x", sha256.Sum256([]byte("changed-profile-v2")))}}}
	if _, e := extensions.Update(ctx, owner, 2, installedExtension.Revision, changed); e != nil {
		t.Fatal(e)
	}
	stale, denied := recorder.Resume(ctx, resumer, staleToken, stableClaim("stale-private-binding"), engine, downstreamFor(staleRaw))
	if denied == nil || stale.Outcome.Stream != nil || effects.Load() != 1 {
		t.Fatal("changed configured binding authorized old pipeline", denied, effects.Load())
	}
	recorder, err = continuations.New(config)
	if err != nil {
		t.Fatal(err)
	}
	engine = makeEngine(recorder)
	activeRaw, activeToken := deferAgain(time.Minute)
	closedRaw, closedToken := deferAgain(time.Minute)
	active, err := recorder.Resume(ctx, resumer, activeToken, stableClaim("active-close"), engine, downstreamFor(activeRaw))
	if err != nil || active.Outcome.Stream == nil {
		t.Fatal("actual active resumed source", err, effects.Load())
	}

	for effects.Load() < 2 {
		f, e := active.Outcome.Stream.Next(ctx)
		if e != nil {
			t.Fatal(e)
		}
		if f.Kind == fabric.FrameComplete {
			t.Fatal("no pre-terminal active source", effects.Load())
		}
	}
	if err = session.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = active.Outcome.Stream.Next(ctx); err == nil {
		t.Fatal("closed resumer read cached source")
	}
	_ = active.Outcome.Stream.Close()
	closed, denied := recorder.Resume(ctx, resumer, closedToken, stableClaim("closed-resumer"), engine, downstreamFor(closedRaw))
	if denied == nil || closed.Outcome.Stream != nil || effects.Load() != 2 {
		t.Fatal("closed resumer dispatched", denied, effects.Load())
	}
	static, _ := fabric.NewAuthenticatedContext(caller.PrincipalView(), root.Namespace, original)
	var final fabric.Envelope
	_ = fabric.DecodeJSON(original, &final)
	if _, err = service.InvokeResumed(ctx, static, original, final); err == nil {
		t.Fatal("static historical context promoted")
	}
}
