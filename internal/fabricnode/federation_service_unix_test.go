//go:build linux || darwin

package fabricnode

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/adapters/mcp"
	"github.com/pagnet-code/pagnet/fabric/extension"
	extregistry "github.com/pagnet-code/pagnet/fabric/extension/registry"
	"github.com/pagnet-code/pagnet/fabric/federation"
	"github.com/pagnet-code/pagnet/fabric/mcpbridge"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/fabric/search"
	"github.com/pagnet-code/pagnet/internal/fabricauth"
	"github.com/pagnet-code/pagnet/internal/fabricfederation"
	"github.com/pagnet-code/pagnet/internal/fabricservices"
)

type remoteExtCredentials struct{}

func (remoteExtCredentials) Authorization(context.Context, string) (string, error) {
	return "Bearer explicitly-selected-test-provider", nil
}

func exerciseActualRemotePaidFinal(t *testing.T, a, b remoteInstalledPeer, auth *fabricauth.Authority, session *fabricauth.Session, sourceGate *fabricfederation.PeerGate, boundary *RemoteBoundary, exposures *FederationExposures, cfg, sourceCfg federation.Config, scenario string) {
	t.Helper()
	ctx := t.Context()
	ref, _ := fabric.NewEndpointRef(b.cert.Authority.PublicKey)
	rev, e := b.installation.Store.Register(ctx, b.owner, fabric.RegistryUpdate{Descriptor: fabric.EndpointDescriptor{Ref: ref, Kind: "service.mcp", Name: "Explicit federation source", Bindings: []fabric.BindingSummary{{ID: "mcp", Protocol: "mcp.tools", Version: "2026-07-28", Cancellation: true}}}})
	if e != nil {
		t.Fatal(e)
	}
	scope := registry.DescriptorBatchScope{Endpoint: ref, ExpectedEndpointRevision: rev, BindingID: "mcp"}
	var effects, transforms, sourceHooks, completions atomic.Int32
	provider := sdk.NewServer(&sdk.Implementation{Name: "original-remote-effect", Version: "1"}, nil)
	provider.AddTool(&sdk.Tool{Name: "compute", InputSchema: json.RawMessage(`{"type":"object"}`)}, func(context.Context, *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
		effects.Add(1)
		return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: "private raw original must never escape"}}}, nil
	})
	server := httptest.NewServer(sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return provider }, &sdk.StreamableHTTPOptions{Stateless: true}))
	defer server.Close()
	profiles, e := fabricservices.NewProfileStore(ctx, b.installation.Store, b.installation.Operator, b.installation.Keys)
	if e != nil {
		t.Fatal(e)
	}
	account := [32]byte{79}
	if _, e = profiles.Install(ctx, scope, fabricservices.Profile{Protocol: "mcp.tools", Version: "2026-07-28", CredentialSelector: "selected-federation-service", BindingDigest: account, MCP: &fabricservices.MCPProfile{URL: server.URL, AllowHTTP: true, Limits: mcp.DefaultLimits}}); e != nil {
		t.Fatal(e)
	}
	ledger, e := fabricservices.BootstrapInvocations(ctx, profiles, fabricservices.DefaultInvocationConfig(), boundary)
	if e != nil {
		t.Fatal(e)
	}
	connections, e := fabricservices.NewConnections(profiles, serviceRouterCredentials{account}, ledger, 2)
	if e != nil {
		t.Fatal(e)
	}
	defer connections.Close()
	if e = connections.ConnectMCP(ctx, scope, true); e != nil {
		t.Fatal(e)
	}
	providerBinding, e := NewServiceBindingProvider(connections)
	if e != nil {
		t.Fatal(e)
	}
	router, e := NewRouter(map[BindingProtocol]BindingProvider{{Protocol: "mcp.tools", Version: "2026-07-28"}: providerBinding})
	if e != nil {
		t.Fatal(e)
	}
	offers, _, e := b.installation.Store.ListOffers(ctx, ref, rev, "", 2)
	if e != nil || len(offers) != 1 {
		t.Fatal(e, len(offers))
	}
	offer := offers[0]
	if _, e = exposures.Put(ctx, 1, FederationExposureConfiguration{Exposures: []FederationExposure{{a.cert.Authority.Namespace, offer.Ref, offer.Revision, "mcp"}}}); e != nil {
		t.Fatal(e)
	}
	// Install real signed private extension configuration and actual HTTP provider.
	// The nondeterministic counter detects any replay of the original transformer.
	handler := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request extension.InterceptRequest
		raw, _ := io.ReadAll(io.LimitReader(r.Body, extension.MaxOutputResponseBytes+1))
		if fabric.DecodeJSON(raw, &request) != nil {
			t.Error("malformed interceptor request")
			w.WriteHeader(400)
			return
		}
		decision := extension.Decision{Action: extension.Continue}
		if request.InterceptorID == "test.pipeline.source" {
			sourceHooks.Add(1)
		}
		if request.Phase == extension.PhaseChunk {
			n := transforms.Add(1)
			if scenario == "transform_failure" {
				// Genuine remote transform ran, but its result was lost. The FULL
				// attempt marker must prohibit replay rather than rerunning this hook.
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			decision = extension.Decision{Action: extension.Modify, Patch: json.RawMessage(fmt.Sprintf(`[{"op":"replace","path":"/content","value":{"safe":%d}}]`, n))}
		}
		if request.Phase == extension.PhaseCompletion {
			completions.Add(1)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(decision)
	}))
	defer handler.Close()
	if e = InitializeExtensionInfrastructure(ctx, b.installation, DefaultExtensionSettings()); e != nil {
		t.Fatal(e)
	}
	infrastructure, e := openExtensionInfrastructure(ctx, b.installation)
	if e != nil {
		t.Fatal(e)
	}
	profile, e := infrastructure.Profiles.Put(ctx, ExtensionProfile{Protocol: extensionHTTPProtocol, URL: handler.URL, CredentialSelector: "test.provider", MaxConcurrency: 2, AllowHTTP: true})
	if e != nil {
		t.Fatal(e)
	}
	manifest := extension.ExtensionManifest{ManifestVersion: "1.0", ID: "test.pipeline", Version: "1", MinProtocol: "1.0", MaxProtocol: "1.0", Interceptors: []extension.Registration{
		{ID: "test.pipeline.destination", Match: extension.Match{Operation: fabric.OperationInvoke, Stage: "invoke.dispatch"}, Placement: extension.PlacementDestination, NeedsPlaintext: true, Phases: []extension.Phase{extension.PhaseRequest, extension.PhaseResponse, extension.PhaseChunk, extension.PhaseCompletion}, TimeoutMillis: 1000, Binding: "test.provider"},
		{ID: "test.pipeline.source", Match: extension.Match{Operation: fabric.OperationInvoke, Stage: "invoke.dispatch"}, Placement: extension.PlacementSource, Phases: []extension.Phase{extension.PhaseRequest}, TimeoutMillis: 1000, Binding: "test.provider"},
	}}
	if e = infrastructure.Registry.Reload(ctx, b.owner); e != nil {
		t.Fatal("reload configured snapshot", e)
	}
	snapshot, err := infrastructure.Registry.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if _, e = infrastructure.Registry.Install(ctx, b.owner, snapshot.Generation, extregistry.Installation{Manifest: manifest, Bindings: []extregistry.Binding{{ID: "test.provider", Protocol: extensionHTTPProtocol, Selector: "test.provider", ProfileDigest: profile}}}); e != nil {
		t.Fatal("install manifest", e)
	}
	infrastructure.Registry.Close()
	infrastructure.Continuations.Close()
	extensions, e := NewExtensionRuntime(ctx, b.installation, boundary.local, ExtensionRuntimeConfig{Lifetime: ctx, Credentials: remoteExtCredentials{}, Bindings: router, VerifyOriginalPhase: NewOriginalExtensionPhaseVerifier(nil, ledger), CurrentPhaseWitness: boundary.CurrentPhaseWitness, CurrentCaller: func(ctx context.Context, c fabric.ExecutionContext, next func(context.Context) error) error {
		if _, e := boundary.binding(c); e != nil {
			return e
		}
		return next(ctx)
	}})
	if e != nil {
		t.Fatal(e)
	}
	defer extensions.Close(ctx)
	n, e := ComposeRetained(ctx, b.installation.Store, func(context.Context, *registry.Store, *search.Backend) (Ports, error) {
		return Ports{Authenticator: boundary, Bindings: router, Admission: boundary, Interceptors: extensions, InvocationPlacement: extension.PlacementDestination}, nil
	})
	if e != nil {
		t.Fatal(e)
	}
	defer n.Close()
	limits := DefaultFinalOutputLimits
	if scenario == "capture_quota" {
		limits.MaxBytes = 4096
	}
	final, e := BootstrapFinalOutputs(ctx, boundary, ledger, b.installation.Keys, limits)
	if e != nil {
		t.Fatal(e)
	}
	admissions, e := federation.BootstrapAdmissionLedger(ctx, federation.AdmissionConfig{Store: b.installation.Store, Owner: b.installation.Operator, Protector: b.installation.Keys, Peers: boundary.peers, Policy: boundary.FederationAdmissionPolicy(), Limits: federation.AdmissionLimits{MaxInvocations: 8, MaxBytes: 4 << 20}, Verification: boundary.limits})
	if e != nil {
		t.Fatal(e)
	}
	runtime, e := NewFederationRuntime(FederationRuntimeConfig{Boundary: boundary, Node: n, Admissions: admissions, Outputs: final, Lifetime: ctx, MaxActive: 2})
	if e != nil {
		t.Fatal(e)
	}
	defer runtime.Close(ctx)
	original, evidence, e := session.Build(ctx, mcpbridge.Call{Operation: fabric.OperationInvoke, Invoke: &fabric.InvokeRequest{Target: offer.Ref, ExpectedRevision: offer.Revision, Input: json.RawMessage(`{"n":9007199254740993}`)}})
	if e != nil {
		t.Fatal(e)
	}
	caller, e := auth.Authenticate(ctx, fabric.AuthenticationRequest{ExactEnvelope: original, Audience: a.cert.Authority.Namespace, PeerEvidence: evidence})
	if e != nil {
		t.Fatal(e)
	}
	var env fabric.Envelope
	if fabric.DecodeJSON(original, &env) != nil {
		t.Fatal("source malformed")
	}
	old := env.Context
	env.Context.Hops++
	// A genuine source-root assertion may contain a foreign interceptor with
	// the same registration name. Signed transport ancestry is not proof that
	// this destination's hook ran; it must still transform and unwind once.
	env.Context.ExtensionChain = append(env.Context.ExtensionChain, "test.pipeline.destination")
	forwarded, _ := json.Marshal(env)
	provenance := func(c fabric.EnvelopeContext) fabric.Provenance {
		return fabric.Provenance{Origin: c.Origin, ParentID: c.ParentID, Ancestry: c.Ancestry, Hops: c.Hops, ExtensionChain: c.ExtensionChain, TriggerLineage: c.TriggerLineage}
	}
	now := time.Now().UTC()
	frame := fabric.ForwardFrame{SourceDomain: sourceCfg.Local.Authority.Namespace, SourceStoreID: sourceCfg.Local.Authority.StoreID, SourceKeyRevision: sourceCfg.Local.Authority.KeyRevision, DestinationDomain: cfg.Local.Authority.Namespace, DestinationStoreID: cfg.Local.Authority.StoreID, SourcePeerBindingDigest: sourceCfg.Local.BindingDigest, DestinationPeerBindingDigest: cfg.Local.BindingDigest, Principal: caller.PrincipalView(), Operation: env.Operation, Target: env.Target, ExpectedRevision: env.ExpectedRevision, InvocationID: env.ID, ReplayID: "paid-original-request", OriginalEnvelopeDigest: sha256.Sum256(original), ForwardedEnvelopeDigest: sha256.Sum256(forwarded), OriginalProvenance: provenance(old), ForwardedProvenance: provenance(env.Context), IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(30 * time.Second).Format(time.RFC3339Nano), BindingProfile: federation.Profile}
	gate, e := NewSourceForwardGate(sourceGate, auth, caller)
	if e != nil {
		t.Fatal(e)
	}
	proof, e := a.installation.Store.SignForwardExact(ctx, a.owner, caller, original, forwarded, frame, gate)
	if e != nil {
		t.Fatal(e)
	}
	bundle := actualEncryptedBundle(t, sourceCfg, cfg, federation.ForwardBundle{Proof: proof, Original: original, Forwarded: forwarded})
	delivery, cancel := context.WithCancel(ctx)
	started, e := runtime.Start(delivery, bundle)
	if scenario == "capture_quota" {
		cancel()
		runtime.wg.Wait()
		if effects.Load() != 1 {
			t.Fatal("quota test did not reach accepted original paid effect", effects.Load(), e)
		}
		if e == nil && started.Association == nil {
			t.Fatal("quota failure returned apparent success")
		}
		if _, err := runtime.Start(ctx, bundle); err == nil {
			t.Fatal("quota failure permitted original paid resend")
		}
		runtime.wg.Wait()
		if effects.Load() != 1 {
			t.Fatal("quota failure repeated accepted paid effect")
		}
		return
	}
	if e != nil || started.Association == nil {
		t.Fatal("actual paid start", e)
	}
	cancel() // only relay/view delivery ends
	runtime.wg.Wait()
	if scenario == "complete" && (effects.Load() != 1 || transforms.Load() != 1 || completions.Load() != 1 || sourceHooks.Load() != 0) {
		t.Fatal("pipeline effects/order", effects.Load(), transforms.Load(), completions.Load(), sourceHooks.Load())
	}
	var reference FinalOutputReference
	if fabric.DecodeJSON(started.Association.PrivateReference, &reference) != nil {
		t.Fatal("association malformed")
	}
	reference.Principal = caller.PrincipalView()
	reference.InvocationID = env.ID
	bundleRaw, _ := federation.EncodeForwardBundle(bundle)
	receiptDigest := sha256.Sum256(bundleRaw)
	payload := json.RawMessage(`{}`)
	controlNow := time.Now().UTC()
	control := fabric.ControlFrame{ProtocolVersion: "1", SourceDomain: sourceCfg.Local.Authority.Namespace, SourceStoreID: sourceCfg.Local.Authority.StoreID, SourceKeyRevision: sourceCfg.Local.Authority.KeyRevision, DestinationDomain: cfg.Local.Authority.Namespace, DestinationStoreID: cfg.Local.Authority.StoreID, SourcePeerBindingDigest: sourceCfg.Local.BindingDigest, DestinationPeerBindingDigest: cfg.Local.BindingDigest, Principal: caller.PrincipalView(), OriginalPrincipal: caller.PrincipalView(), InvocationID: env.ID, ReceiptDigest: receiptDigest, Action: "status", PayloadDigest: sha256.Sum256(payload), ReplayID: "fresh-final-read", IssuedAt: controlNow.Format(time.RFC3339Nano), ExpiresAt: controlNow.Add(30 * time.Second).Format(time.RFC3339Nano), BindingProfile: federation.Profile}
	var signed fabric.SignedControlProof
	e = session.WithAuthenticatedControl(ctx, control, payload, func(ctx context.Context, c fabric.ExecutionContext) error {
		g, e := NewSourceControlGate(sourceGate, auth, c, sourceCfg.Local, sourceCfg.Remote)
		if e != nil {
			return e
		}
		signed, e = a.installation.Store.SignControlExact(ctx, a.owner, c, payload, control, g)
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
	e = boundary.AuthenticateControl(ctx, cfg, federation.ControlRequest{Proof: signed, Payload: payload}, func(ctx context.Context, c fabric.ExecutionContext) error {
		for ordinal := uint64(0); ; ordinal++ {
			f, e := final.Frame(ctx, c, reference, ordinal)
			if e == io.EOF {
				break
			}
			if e != nil {
				if scenario == "transform_failure" {
					var failure *fabric.Error
					if !errors.As(e, &failure) || failure.Code != "federation.FINALIZATION_UNKNOWN" || failure.Effect != fabric.EffectUnknown {
						t.Fatal("failed transform was not honest incomplete finalization", e)
					}
					return nil
				}
				return e
			}
			if bytes.Contains(f.Data, []byte("private raw")) {
				t.Fatal("raw source bypassed output pipeline")
			}
			if f.Kind == fabric.FrameChunk && !bytes.Equal(f.Data, []byte(`{"safe":1}`)) {
				t.Fatal("nondeterministic transformer replayed", string(f.Data))
			}
		}
		return nil
	})
	if e != nil {
		t.Fatal("fresh final output", e)
	}
	if effects.Load() != 1 || transforms.Load() != 1 {
		t.Fatal("history reran effects")
	}
	if scenario == "transform_failure" {
		// An unresolved attempted hook remains unknown after retained reopen.
		reopened, err := OpenFinalOutputs(ctx, boundary, ledger, b.installation.Keys)
		if err != nil {
			t.Fatal(err)
		}
		e = boundary.AuthenticateControl(ctx, cfg, federation.ControlRequest{Proof: signed, Payload: payload}, func(ctx context.Context, c fabric.ExecutionContext) error {
			_, err := reopened.Frame(ctx, c, reference, 1)
			var failure *fabric.Error
			if !errors.As(err, &failure) || failure.Code != "federation.FINALIZATION_UNKNOWN" {
				t.Fatal("reopen reran or fabricated ambiguous transform", err)
			}
			return nil
		})
		if e != nil {
			t.Fatal(e)
		}
		if _, err := runtime.Start(ctx, bundle); err == nil {
			t.Fatal("ambiguous transform permitted paid resend")
		}
		runtime.wg.Wait()
		if effects.Load() != 1 || transforms.Load() != 1 {
			t.Fatal("ambiguous transform repeated")
		}
		return
	}
	// Reopening retained encrypted state does not reconstruct the source stream
	// or rerun nondeterministic output hooks. The exact final projection survives.
	reopened, err := OpenFinalOutputs(ctx, boundary, ledger, b.installation.Keys)
	if err != nil {
		t.Fatal("reopen final projection", err)
	}
	e = boundary.AuthenticateControl(ctx, cfg, federation.ControlRequest{Proof: signed, Payload: payload}, func(ctx context.Context, c fabric.ExecutionContext) error {
		for ordinal := uint64(0); ; ordinal++ {
			want, err := final.Frame(ctx, c, reference, ordinal)
			got, other := reopened.Frame(ctx, c, reference, ordinal)
			if err == io.EOF && other == io.EOF {
				break
			}
			if err != nil || other != nil {
				t.Fatal("retained frame after reopen", err, other)
			}
			a, _ := json.Marshal(want)
			b, _ := json.Marshal(got)
			if !bytes.Equal(a, b) {
				t.Fatal("retained final frame changed")
			}
		}
		altered := reference
		altered.Commitment[0] ^= 1
		if _, err := reopened.Frame(ctx, c, altered, 0); err == nil {
			t.Fatal("forged final association accepted")
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	if _, err := runtime.Start(ctx, bundle); err == nil {
		t.Fatal("original execution was dispatched twice")
	}
	runtime.wg.Wait()
	if effects.Load() != 1 || transforms.Load() != 1 || completions.Load() != 1 {
		t.Fatal("retained request repeated original pipeline")
	}
	// A currently authenticated signed control is not an exposure grant. Removing
	// the explicitly published target fences disclosure, including cached output.
	if _, err := exposures.Put(ctx, 2, FederationExposureConfiguration{}); err != nil {
		t.Fatal("remove exposure", err)
	}
	e = boundary.AuthenticateControl(ctx, cfg, federation.ControlRequest{Proof: signed, Payload: payload}, func(ctx context.Context, c fabric.ExecutionContext) error {
		_, err := reopened.Frame(ctx, c, reference, 0)
		if err == nil {
			t.Fatal("retired exposure disclosed retained final output")
		}
		return nil
	})
	if e != nil {
		t.Fatal("fresh control authentication", e)
	}
}
