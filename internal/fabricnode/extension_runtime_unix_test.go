//go:build linux || darwin

package fabricnode

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/adapters/mcp"
	"github.com/pagnet-code/pagnet/fabric/extension"
	extregistry "github.com/pagnet-code/pagnet/fabric/extension/registry"
	"github.com/pagnet-code/pagnet/fabric/localinstallation"
	"github.com/pagnet-code/pagnet/fabric/mcpbridge"
	"github.com/pagnet-code/pagnet/fabric/node"
	"github.com/pagnet-code/pagnet/fabric/node/continuations"
	"github.com/pagnet-code/pagnet/fabric/node/dispatch"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/fabricauth"
	"github.com/pagnet-code/pagnet/internal/fabricservices"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

type runtimeHTTPSecret struct{}

func (runtimeHTTPSecret) Authorization(_ context.Context, slot string) (string, error) {
	if slot != "operator.http.interceptor" {
		return "", errors.New("wrong private slot")
	}
	return "Bearer memory-only-interceptor-secret", nil
}
func TestActualKernelConfiguredHTTPRuntimeAllDecisionsPrivateResumeAndPlanFence(t *testing.T) {
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
	official.AddTool(&sdk.Tool{Name: "echo2", InputSchema: json.RawMessage(`{"type":"object","properties":{"input":{"type":"string"}},"required":["input"]}`)}, func(_ context.Context, r *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
		effects.Add(1)
		return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: "second:" + string(r.Params.Arguments)}}}, nil
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
	if err != nil || len(offers) != 2 {
		t.Fatal(err, len(offers))
	}
	if offers[0].Name == "echo2" {
		offers[0], offers[1] = offers[1], offers[0]
	}
	if offers[0].Name != "echo" || offers[1].Name != "echo2" {
		t.Fatal("actual named tool offers missing")
	}

	if err = InitializeExtensionInfrastructure(ctx, installed, DefaultExtensionSettings()); err != nil {
		t.Fatal(err)
	}
	var action atomic.Value
	action.Store(extension.Continue)
	var interceptorCalls atomic.Int32
	interceptor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer memory-only-interceptor-secret" {
			t.Error("private configured credential missing")
			w.WriteHeader(403)
			return
		}
		raw, e := io.ReadAll(io.LimitReader(r.Body, extension.MaxInterceptBytes+1))
		if e != nil || len(raw) > extension.MaxInterceptBytes {
			w.WriteHeader(400)
			return
		}
		if bytes.Contains(raw, []byte("memory-only-interceptor-secret")) {
			t.Error("credential entered envelope")
			w.WriteHeader(400)
			return
		}
		var request extension.InterceptRequest
		if fabric.DecodeJSON(raw, &request) != nil {
			w.WriteHeader(400)
			return
		}
		interceptorCalls.Add(1)
		d := extension.Decision{Action: extension.Continue}
		if request.Phase == extension.PhaseRequest {
			d.Action = action.Load().(extension.Action)
			switch d.Action {
			case extension.Modify:
				d.Patch = json.RawMessage(`[{"op":"replace","path":"/payload/input","value":"modified by configured interceptor"}]`)
			case extension.Reject:
				d.Failure = fabric.NewError(fabric.CodeInterceptorRejected, "Explicit fixture reject")
			case extension.Respond:
				d.Response = json.RawMessage(`{"cached":"actual interceptor response"}`)
			case extension.Redirect:
				if request.Envelope.Target != nil && *request.Envelope.Target == offers[1].Ref {
					d.Action = extension.Continue
				} else {
					d.Redirect = &extension.RedirectTarget{Ref: offers[1].Ref, ExpectedRevision: offers[1].Revision}
				}
			case extension.Defer:
				d.Deferral = &extension.Deferral{Durable: true, ExpiresAt: time.Now().UTC().Add(time.Minute), ResumePrincipals: []string{root.Owner.Ref}}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(d)
	}))
	defer interceptor.Close()
	runtime, err := NewExtensionRuntime(ctx, installed, boundary, ExtensionRuntimeConfig{Lifetime: ctx, Credentials: runtimeHTTPSecret{}, Bindings: router})
	if err != nil || runtime == nil {
		t.Fatal(err)
	}
	defer runtime.Close(ctx)
	var reference extregistry.Reference
	err = session.WithOwnerAdministration(ctx, []byte(`{"operation":"extension.add"}`), func(c context.Context, admin *fabricauth.OwnerAdministration) error {
		digest, e := runtime.PutProfile(c, admin, ExtensionProfile{Protocol: extensionHTTPProtocol, URL: interceptor.URL, CredentialSelector: "operator.http.interceptor", MaxConcurrency: 4})
		if e != nil {
			return e
		}
		manifest := extension.ExtensionManifest{ManifestVersion: "1.0", ID: "operator.http", Version: "1", MinProtocol: "1.0", MaxProtocol: "1.0", Interceptors: []extension.Registration{{ID: "operator.http.invoke", Match: extension.Match{Operation: fabric.OperationInvoke, Stage: "invoke.dispatch"}, Placement: extension.PlacementSource, NeedsPlaintext: true, Phases: []extension.Phase{extension.PhaseRequest, extension.PhaseResponse, extension.PhaseChunk, extension.PhaseCompletion}, TimeoutMillis: 1000, Binding: "operator.http.binding"}}}
		reference, e = runtime.Install(c, admin, 1, extregistry.Installation{Manifest: manifest, Bindings: []extregistry.Binding{{ID: "operator.http.binding", Protocol: extensionHTTPProtocol, Selector: "operator.http.interceptor", ProfileDigest: digest}}})
		return e
	})
	if err != nil {
		t.Fatal(err)
	}
	dispatcher, err := dispatch.New(dispatch.Config{Audience: root.Namespace, Descriptors: installed.Store, Bindings: router, Admission: boundary})
	if err != nil {
		t.Fatal(err)
	}
	service, err := node.New(node.Config{Audience: root.Namespace, Authenticator: auth, Descriptors: installed.Store, Dispatcher: dispatcher, Interceptors: runtime, ResumeDispatchVerifier: runtime.authority})
	if err != nil {
		t.Fatal(err)
	}
	invoke := func(a extension.Action) (node.Result, error) {
		action.Store(a)
		deadline := time.Now().UTC().Add(time.Minute)
		raw, proof, e := session.Build(ctx, mcpbridge.Call{Operation: fabric.OperationInvoke, Invoke: &fabric.InvokeRequest{Target: offers[0].Ref, ExpectedRevision: offers[0].Revision, Input: json.RawMessage(`{"input":"exact source data"}`), Deadline: &deadline}})
		if e != nil {
			return node.Result{}, e
		}
		return service.Execute(ctx, raw, proof)
	}
	drain := func(stream fabric.InvocationStream) []byte {
		if stream == nil {
			t.Fatal("missing actual stream")
		}
		defer stream.Close()
		var data []byte
		var completed bool
		for {
			frame, e := stream.Next(ctx)
			if errors.Is(e, io.EOF) {
				break
			}
			if e != nil {
				t.Fatal(e)
			}
			data = append(data, frame.Data...)
			completed = completed || frame.Kind == fabric.FrameComplete
		}
		if !completed {
			t.Fatal("missing genuine complete frame")
		}
		return data
	}
	result, err := invoke(extension.Continue)
	if err != nil {
		t.Fatal(err)
	}
	drain(result.Stream)
	if effects.Load() != 1 {
		t.Fatal("continue effect count", effects.Load())
	}
	result, err = invoke(extension.Modify)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(drain(result.Stream), []byte("modified by configured interceptor")) {
		t.Fatal("actual modified input not delivered")
	}
	if effects.Load() != 2 {
		t.Fatal("modify effect count", effects.Load())
	}
	if _, err = invoke(extension.Reject); err == nil || effects.Load() != 2 {
		t.Fatal("rejected invocation executed", err, effects.Load())
	}
	result, err = invoke(extension.Respond)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(drain(result.Stream), []byte("actual interceptor response")) || effects.Load() != 2 {
		t.Fatal("respond invoked endpoint")
	}
	result, err = invoke(extension.Redirect)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(drain(result.Stream), []byte("second:")) || effects.Load() != 3 {
		t.Fatal("redirect did not reenter actual selected dispatcher")
	}
	result, err = invoke(extension.Defer)
	if err != nil || result.DeferredID == "" || effects.Load() != 3 {
		t.Fatal("durable defer effect", err, effects.Load())
	}
	deferredID := result.DeferredID
	var resumed continuations.ResumeResult
	claimHash := sha256.Sum256([]byte("actual product admin resume claim"))
	claim := hex.EncodeToString(claimHash[:])
	err = session.WithOwnerAdministration(ctx, []byte(`{"operation":"continuation.resume"}`), func(c context.Context, admin *fabricauth.OwnerAdministration) error {
		var e error
		resumed, e = runtime.Resume(c, admin, deferredID, claim, service)
		if e != nil {
			return e
		}
		if resumed.Outcome.Stream == nil {
			return errors.New("no resumed stream")
		}
		_, e = resumed.Outcome.Stream.Next(c)
		return e
	})
	if err != nil {
		t.Fatal(err)
	}
	drain(resumed.Outcome.Stream)
	if effects.Load() != 4 {
		t.Fatal("private resumed effect count", effects.Load())
	}
	err = session.WithOwnerAdministration(ctx, []byte(`{"operation":"continuation.resume"}`), func(c context.Context, admin *fabricauth.OwnerAdministration) error {
		retry, e := runtime.Resume(c, admin, deferredID, claim, service)
		if e != nil {
			return e
		}
		if retry.Claim.Fresh || retry.Outcome.Stream != nil {
			return errors.New("duplicate resume reexecuted")
		}
		return nil
	})
	if err != nil || effects.Load() != 4 {
		t.Fatal("duplicate private claim", err, effects.Load())
	}
	err = session.WithOwnerAdministration(ctx, []byte(`{"operation":"extension.update"}`), func(c context.Context, admin *fabricauth.OwnerAdministration) error {
		selected, configured, e := runtime.Inspect(c, admin, reference.ID)
		if e != nil {
			return e
		}
		if selected.Revision != reference.Revision {
			return errors.New("inspection changed selected revision")
		}
		configured.Manifest.Version = "2"
		reference, e = runtime.Update(c, admin, 2, selected.Revision, configured)
		return e
	})
	if err != nil {
		t.Fatal(err)
	}
	action.Store(extension.Continue)
	result, err = invoke(extension.Continue)
	if err != nil {
		t.Fatal(err)
	}
	err = session.WithOwnerAdministration(ctx, []byte(`{"operation":"extension.remove"}`), func(c context.Context, admin *fabricauth.OwnerAdministration) error {
		return runtime.Remove(c, admin, 3, reference.Revision, reference.ID)
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = result.Stream.Next(ctx); err == nil {
		t.Fatal("changed configured plan disclosed old stream")
	}
	result.Stream.Close()
	if interceptorCalls.Load() < 6 {
		t.Fatal("remote protocol not used")
	}
	if err = runtime.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestActualKernelInstalledHTTPRuntimeDeferredRootRestartResume(t *testing.T) {
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
	defer func() { installed.Close() }()
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
	defer func() { closeSession() }()
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
	official.AddTool(&sdk.Tool{Name: "echo2", InputSchema: json.RawMessage(`{"type":"object","properties":{"input":{"type":"string"}},"required":["input"]}`)}, func(_ context.Context, r *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
		effects.Add(1)
		return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: "second:" + string(r.Params.Arguments)}}}, nil
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
	defer func() { connections.Close() }()
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
	if err != nil || len(offers) != 2 {
		t.Fatal(err, len(offers))
	}
	if offers[0].Name == "echo2" {
		offers[0], offers[1] = offers[1], offers[0]
	}
	if offers[0].Name != "echo" || offers[1].Name != "echo2" {
		t.Fatal("actual named tool offers missing")
	}

	if err = InitializeExtensionInfrastructure(ctx, installed, DefaultExtensionSettings()); err != nil {
		t.Fatal(err)
	}
	interceptor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request extension.InterceptRequest
		if json.NewDecoder(io.LimitReader(r.Body, extension.MaxInterceptBytes+1)).Decode(&request) != nil {
			w.WriteHeader(400)
			return
		}
		decision := extension.Decision{Action: extension.Continue}
		if request.Phase == extension.PhaseRequest {
			decision = extension.Decision{Action: extension.Defer, Deferral: &extension.Deferral{Durable: true, ExpiresAt: time.Now().UTC().Add(time.Minute), ResumePrincipals: []string{root.Owner.Ref}}}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(decision)
	}))
	defer interceptor.Close()
	runtime, err := NewExtensionRuntime(ctx, installed, boundary, ExtensionRuntimeConfig{Lifetime: ctx, Credentials: runtimeHTTPSecret{}, Bindings: router})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { runtime.Close(ctx) }()
	err = session.WithOwnerAdministration(ctx, []byte(`{"operation":"extension.add"}`), func(c context.Context, admin *fabricauth.OwnerAdministration) error {
		digest, e := runtime.PutProfile(c, admin, ExtensionProfile{Protocol: extensionHTTPProtocol, URL: interceptor.URL, CredentialSelector: "operator.http.interceptor", MaxConcurrency: 2})
		if e != nil {
			return e
		}
		manifest := extension.ExtensionManifest{ManifestVersion: "1.0", ID: "operator.approval", Version: "1", MinProtocol: "1.0", MaxProtocol: "1.0", Interceptors: []extension.Registration{{ID: "operator.approval.invoke", Match: extension.Match{Operation: fabric.OperationInvoke, Stage: "invoke.dispatch"}, Placement: extension.PlacementSource, NeedsPlaintext: true, Phases: []extension.Phase{extension.PhaseRequest, extension.PhaseResponse, extension.PhaseChunk, extension.PhaseCompletion}, TimeoutMillis: 1000, Binding: "operator.approval.binding"}}}
		_, e = runtime.Install(c, admin, 1, extregistry.Installation{Manifest: manifest, Bindings: []extregistry.Binding{{ID: "operator.approval.binding", Protocol: extensionHTTPProtocol, Selector: "operator.http.interceptor", ProfileDigest: digest}}})
		return e
	})
	if err != nil {
		t.Fatal(err)
	}
	makeService := func() *node.Service {
		dispatcher, e := dispatch.New(dispatch.Config{Audience: root.Namespace, Descriptors: installed.Store, Bindings: router, Admission: boundary})
		if e != nil {
			t.Fatal(e)
		}
		service, e := node.New(node.Config{Audience: root.Namespace, Authenticator: auth, Descriptors: installed.Store, Dispatcher: dispatcher, Interceptors: runtime, ResumeDispatchVerifier: runtime.authority})
		if e != nil {
			t.Fatal(e)
		}
		return service
	}
	service := makeService()
	deadline := time.Now().UTC().Add(time.Minute)
	exact, peer, err := session.Build(ctx, mcpbridge.Call{Operation: fabric.OperationInvoke, Invoke: &fabric.InvokeRequest{Target: offers[0].Ref, ExpectedRevision: offers[0].Revision, Input: json.RawMessage(`{"input":"original persisted deferred data"}`), Deadline: &deadline}})
	if err != nil {
		t.Fatal(err)
	}
	deferred, err := service.Execute(ctx, exact, peer)
	if err != nil || deferred.DeferredID == "" || effects.Load() != 0 {
		t.Fatal("effect before restart approval", err, effects.Load())
	}
	originalRoot := installed.Store.AuthorityIdentity()
	rootDirectory, err := installed.Store.CurrentAuthorityDirectory(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = runtime.Close(ctx); err != nil {
		t.Fatal(err)
	}
	connections.Close()
	closeSession()
	if err = installed.Close(); err != nil {
		t.Fatal(err)
	}
	installed, err = localinstallation.Load(ctx, rootDirectory, registry.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	if installed.Store.AuthorityIdentity().StoreID != originalRoot.StoreID {
		t.Fatal("restart fabricated root")
	}
	owner, err = installed.Operator(ctx)
	if err != nil {
		t.Fatal(err)
	}
	boundary, err = newLocalBoundary(ctx, installed.Store, owner, installed, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	auth, err = fabricauth.New(fabricauth.Config{Root: originalRoot, RootOwner: originalRoot.Owner, Audience: originalRoot.Namespace, SocketPath: socket, CurrentRoot: installed.Store.CurrentAuthorityIdentity})
	if err != nil {
		t.Fatal(err)
	}
	boundary.sessions = auth
	session, closeSession = runtimeOwnerSession(t, ctx, &NativeRuntime{Authenticator: auth}, socket)
	profiles, err = fabricservices.NewProfileStore(ctx, installed.Store, installed.Operator, installed.Keys)
	if err != nil {
		t.Fatal(err)
	}
	ledger, err = fabricservices.OpenInvocations(ctx, profiles, fabricservices.DefaultInvocationConfig(), boundary)
	if err != nil {
		t.Fatal(err)
	}
	connections, err = fabricservices.NewConnections(profiles, serviceRouterCredentials{account}, ledger, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err = connections.ConnectMCP(ctx, scope, false); err != nil {
		t.Fatal(err)
	}
	provider, err = NewServiceBindingProvider(connections)
	if err != nil {
		t.Fatal(err)
	}
	router, err = NewRouter(map[BindingProtocol]BindingProvider{{Protocol: "mcp.tools", Version: "2026-07-28"}: provider})
	if err != nil {
		t.Fatal(err)
	}
	runtime, err = NewExtensionRuntime(ctx, installed, boundary, ExtensionRuntimeConfig{Lifetime: ctx, Credentials: runtimeHTTPSecret{}, Bindings: router})
	if err != nil {
		t.Fatal(err)
	}
	service = makeService()
	hash := sha256.Sum256([]byte("retained exact installed private claim"))
	claim := hex.EncodeToString(hash[:])
	var resumed continuations.ResumeResult
	err = session.WithOwnerAdministration(ctx, []byte(`{"operation":"continuation.resume"}`), func(c context.Context, admin *fabricauth.OwnerAdministration) error {
		var e error
		resumed, e = runtime.Resume(c, admin, deferred.DeferredID, claim, service)
		return e
	})
	if err != nil || resumed.Outcome.Stream == nil {
		t.Fatal("protected configured restart resume", err)
	}
	var complete bool
	for {
		frame, e := resumed.Outcome.Stream.Next(ctx)
		if errors.Is(e, io.EOF) {
			break
		}
		if e != nil {
			t.Fatal(e)
		}
		complete = complete || frame.Kind == fabric.FrameComplete
	}
	resumed.Outcome.Stream.Close()
	if !complete || effects.Load() != 1 {
		t.Fatal("restarted original outcome", complete, effects.Load())
	}
	err = session.WithOwnerAdministration(ctx, []byte(`{"operation":"continuation.resume"}`), func(c context.Context, admin *fabricauth.OwnerAdministration) error {
		retry, e := runtime.Resume(c, admin, deferred.DeferredID, claim, service)
		if e != nil {
			return e
		}
		if retry.Claim.Fresh || retry.Outcome.Stream != nil {
			return errors.New("claimed source replayed")
		}
		return nil
	})
	if err != nil || effects.Load() != 1 {
		t.Fatal("restart duplicate claim", err, effects.Load())
	}
}
