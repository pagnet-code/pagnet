//go:build linux || darwin

package fabricnode

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/extension"
	extregistry "github.com/pagnet-code/pagnet/fabric/extension/registry"
	"github.com/pagnet-code/pagnet/fabric/federation"
	"github.com/pagnet-code/pagnet/fabric/identity"
	"github.com/pagnet-code/pagnet/fabric/mcpbridge"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/fabric/search"
	"github.com/pagnet-code/pagnet/internal/fabricauth"
	"github.com/pagnet-code/pagnet/internal/fabricfederation"
	"github.com/pagnet-code/pagnet/internal/fabricnative"
	"github.com/pagnet-code/pagnet/internal/localpeer"
	"github.com/pagnet-code/pagnet/internal/nativeauthority"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
)

func exerciseActualRemoteNativeFinal(t *testing.T, a, b remoteInstalledPeer, auth *fabricauth.Authority, session *fabricauth.Session, sourceGate *fabricfederation.PeerGate, boundary *RemoteBoundary, exposures *FederationExposures, cfg, sourceCfg federation.Config) {
	t.Helper()
	ctx := t.Context()
	dir, err := os.MkdirTemp("", "pgn-federated-native-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	// Worker private state must not sit below the runtime binary's read grant.
	// The actual sandbox intentionally denies that overlap.
	workerDir, err := os.MkdirTemp("", "pgn-federated-worker-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(workerDir)
	binary, fake := filepath.Join(dir, "pagnet"), filepath.Join(dir, "native")
	sourceDir, _ := filepath.Abs("../..")
	for _, build := range []struct{ path, pkg string }{{binary, "./cmd/pagnet"}, {fake, "./cmd/pagnet-fake-runtime"}} {
		command := exec.CommandContext(ctx, "go", "build", "-o", build.path, build.pkg)
		command.Dir = sourceDir
		if out, err := command.CombinedOutput(); err != nil {
			t.Fatal("build genuine worker", err, string(out))
		}
	}
	authorityDir, err := b.installation.Store.CurrentAuthorityDirectory(ctx)
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := NewNativeRuntime(ctx, b.installation.Store, NativeRuntimeConfig{Owner: b.owner, Fence: boundary, Protector: b.installation.Keys, Admission: boundary, Policy: boundary, StartupPolicy: boundary, Credentials: func(context.Context, []string) ([]string, error) { return nil, nil }, Binary: binary, AuthorityDirectory: authorityDir, SocketPath: b.socket, ControllerBootID: "remote-native-A", MaxWorkers: 2, MaxStartupMetadataBytes: 1 << 20, StartupTimeout: 10 * time.Second, CleanupCaller: b.installation.Operator})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()

	ref, _ := fabric.NewEndpointRef(b.cert.Authority.PublicKey)
	revision, err := b.installation.Store.Register(ctx, b.owner, fabric.RegistryUpdate{Descriptor: fabric.EndpointDescriptor{Ref: ref, Kind: "agent.local", Name: "Explicit original remote runtime", Bindings: []fabric.BindingSummary{{ID: "native", Protocol: "local.native", Version: "1"}}}})
	if err != nil {
		t.Fatal(err)
	}
	workspace := filepath.Join(dir, "workspace")
	if err = os.Mkdir(workspace, 0700); err != nil {
		t.Fatal(err)
	}
	spec := sessionworker.NativeSpec{Kind: "local", Runtime: domain.RuntimeFakePersistent, Binary: fake, MCPExecutable: binary, Workspace: workspace, LocalAuthorityDirectory: authorityDir, LocalFabricSocket: b.socket, Env: []string{"HOME=" + workspace, "PATH=/usr/bin:/bin"}}
	raw, err := hex.DecodeString(sessionworker.LocalNativeProfileFingerprint(spec))
	if err != nil {
		t.Fatal(err)
	}
	physical := identity.WorkerBinding{WorkerID: "remote-worker", StateDirectoryID: "remote-state", OwnershipGeneration: "remote-original-A", ActualRuntime: string(spec.Runtime)}
	copy(physical.ProfileDigest[:], raw)
	scope := registry.DescriptorBatchScope{Endpoint: ref, ExpectedEndpointRevision: revision, BindingID: "native"}
	if _, err = runtime.Profiles.Put(ctx, scope, fabricnative.Profile{Native: spec, Worker: physical, Directory: workerDir}); err != nil {
		t.Fatal(err)
	}
	if _, _, err = runtime.Profiles.ProvisionInitialControl(ctx, runtime.Authority, scope); err != nil {
		t.Fatal(err)
	}
	// Join-test teardown owns only the genuine independently spawned worker.
	// Capture its kernel PID from authenticated IPC once Resolve succeeds.
	defer func() {
		clean, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		control, binding, err := runtime.Authority.RetainedNativeControl(clean, b.owner, identity.Scope{Endpoint: ref, DescriptorRevision: revision, BindingID: "native"})
		_ = control
		if err != nil {
			return
		}
		original, err := nativeauthority.NewLocalScope(runtime.Authority.Identity(), binding)
		if err != nil {
			return
		}
		h, err := runtime.Resolver.Refresh(clean, b.owner, original)
		if err != nil {
			return
		}
		defer clear(h.ControlKey)
		process, err := h.Client.OwnerProcess()
		if err == nil {
			child, _ := os.FindProcess(process.PID)
			_ = child.Signal(os.Interrupt)
			for clean.Err() == nil {
				if live, err := localpeer.ReadProcess(process.PID); err != nil || live.Start != process.Start {
					return
				}
				time.Sleep(10 * time.Millisecond)
			}
			t.Error("generated native worker did not exit")
		}
	}()
	if _, err = exposures.Put(ctx, 1, FederationExposureConfiguration{Exposures: []FederationExposure{{a.cert.Authority.Namespace, ref, revision, "native"}}}); err != nil {
		t.Fatal(err)
	}
	var nativeChunks, nativeCompletions atomic.Int32
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		var phase extension.InterceptRequest
		if json.NewDecoder(request.Body).Decode(&phase) != nil {
			w.WriteHeader(400)
			return
		}
		if phase.Phase == extension.PhaseChunk {
			nativeChunks.Add(1)
		}
		if phase.Phase == extension.PhaseCompletion {
			nativeCompletions.Add(1)
		}
		json.NewEncoder(w).Encode(extension.Decision{Action: extension.Continue})
	}))
	defer hook.Close()
	if err = InitializeExtensionInfrastructure(ctx, b.installation, DefaultExtensionSettings()); err != nil {
		t.Fatal(err)
	}
	infrastructure, err := openExtensionInfrastructure(ctx, b.installation)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := infrastructure.Profiles.Put(ctx, ExtensionProfile{Protocol: extensionHTTPProtocol, URL: hook.URL, CredentialSelector: "credentials.none", MaxConcurrency: 2, AllowHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	configured, err := infrastructure.Registry.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	manifest := extension.ExtensionManifest{ManifestVersion: "1.0", ID: "test.native.pipeline", Version: "1", MinProtocol: "1.0", MaxProtocol: "1.0", Interceptors: []extension.Registration{{ID: "test.native.pipeline.destination", Match: extension.Match{Operation: fabric.OperationInvoke, Stage: "invoke.dispatch"}, Placement: extension.PlacementDestination, NeedsPlaintext: true, Phases: []extension.Phase{extension.PhaseRequest, extension.PhaseResponse, extension.PhaseChunk, extension.PhaseCompletion}, TimeoutMillis: 1000, Binding: "native.http"}}}
	if _, err = infrastructure.Registry.Install(ctx, b.owner, configured.Generation, extregistry.Installation{Manifest: manifest, Bindings: []extregistry.Binding{{ID: "native.http", Protocol: extensionHTTPProtocol, Selector: "credentials.none", ProfileDigest: profile}}}); err != nil {
		t.Fatal(err)
	}
	infrastructure.Registry.Close()
	infrastructure.Continuations.Close()
	extensions, err := NewExtensionRuntime(ctx, b.installation, boundary.local, ExtensionRuntimeConfig{Lifetime: ctx, Bindings: runtime.router, VerifyOriginalPhase: NewOriginalExtensionPhaseVerifier(runtime.Adapter, nil), CurrentPhaseWitness: boundary.CurrentPhaseWitness, CurrentCaller: func(current context.Context, caller fabric.ExecutionContext, next func(context.Context) error) error {
		if _, err := boundary.binding(caller); err != nil {
			return err
		}
		return next(current)
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer extensions.Close(ctx)
	n, err := ComposeRetained(ctx, b.installation.Store, func(context.Context, *registry.Store, *search.Backend) (Ports, error) {
		return Ports{Authenticator: boundary, Bindings: runtime.router, Admission: boundary, Interceptors: extensions, InvocationPlacement: extension.PlacementDestination}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	outputs, err := BootstrapNativeFinalOutputs(ctx, boundary, runtime.Adapter, b.installation.Keys, DefaultFinalOutputLimits)
	if err != nil {
		t.Fatal(err)
	}
	admissions, err := federation.BootstrapAdmissionLedger(ctx, federation.AdmissionConfig{Store: b.installation.Store, Owner: b.installation.Operator, Protector: b.installation.Keys, Peers: boundary.peers, Policy: boundary.FederationAdmissionPolicy(), Limits: federation.AdmissionLimits{MaxInvocations: 4, MaxBytes: 4 << 20}, Verification: boundary.limits})
	if err != nil {
		t.Fatal(err)
	}
	remote, err := NewFederationRuntime(FederationRuntimeConfig{Boundary: boundary, Node: n, Admissions: admissions, Outputs: outputs, Lifetime: ctx, MaxActive: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close(ctx)
	original, evidence, err := session.Build(ctx, mcpbridge.Call{Operation: fabric.OperationInvoke, Invoke: &fabric.InvokeRequest{Target: ref, ExpectedRevision: revision, Input: json.RawMessage(`{"input":"let original remote once"}`)}})
	if err != nil {
		t.Fatal(err)
	}
	caller, err := auth.Authenticate(ctx, fabric.AuthenticationRequest{ExactEnvelope: original, Audience: a.cert.Authority.Namespace, PeerEvidence: evidence})
	if err != nil {
		t.Fatal(err)
	}
	var env fabric.Envelope
	if fabric.DecodeJSON(original, &env) != nil {
		t.Fatal("source request")
	}
	previous := env.Context
	env.Context.Hops++
	forwarded, _ := json.Marshal(env)
	provenance := func(c fabric.EnvelopeContext) fabric.Provenance {
		return fabric.Provenance{Origin: c.Origin, ParentID: c.ParentID, Ancestry: c.Ancestry, Hops: c.Hops, ExtensionChain: c.ExtensionChain, TriggerLineage: c.TriggerLineage}
	}
	now := time.Now().UTC()
	frame := fabric.ForwardFrame{SourceDomain: sourceCfg.Local.Authority.Namespace, SourceStoreID: sourceCfg.Local.Authority.StoreID, SourceKeyRevision: sourceCfg.Local.Authority.KeyRevision, DestinationDomain: cfg.Local.Authority.Namespace, DestinationStoreID: cfg.Local.Authority.StoreID, SourcePeerBindingDigest: sourceCfg.Local.BindingDigest, DestinationPeerBindingDigest: cfg.Local.BindingDigest, Principal: caller.PrincipalView(), Operation: env.Operation, Target: env.Target, ExpectedRevision: env.ExpectedRevision, InvocationID: env.ID, ReplayID: "genuine-native-request", OriginalEnvelopeDigest: sha256.Sum256(original), ForwardedEnvelopeDigest: sha256.Sum256(forwarded), OriginalProvenance: provenance(previous), ForwardedProvenance: provenance(env.Context), IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(30 * time.Second).Format(time.RFC3339Nano), BindingProfile: federation.Profile}
	gate, err := NewSourceForwardGate(sourceGate, auth, caller)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := a.installation.Store.SignForwardExact(ctx, a.owner, caller, original, forwarded, frame, gate)
	if err != nil {
		t.Fatal(err)
	}
	bundle := actualEncryptedBundle(t, sourceCfg, cfg, federation.ForwardBundle{Proof: proof, Original: original, Forwarded: forwarded})
	delivery, cancel := context.WithCancel(ctx)
	start, err := remote.Start(delivery, bundle)
	if err != nil || start.Association == nil {
		t.Fatal("native original admitted", err)
	}
	cancel()
	remote.wg.Wait()
	var reference FinalOutputReference
	if fabric.DecodeJSON(start.Association.PrivateReference, &reference) != nil {
		t.Fatal("reference")
	}
	reference.Principal = caller.PrincipalView()
	reference.InvocationID = env.ID
	bundleRaw, _ := federation.EncodeForwardBundle(bundle)
	payload := json.RawMessage(`{}`)
	now = time.Now().UTC()
	control := fabric.ControlFrame{ProtocolVersion: "1", SourceDomain: sourceCfg.Local.Authority.Namespace, SourceStoreID: sourceCfg.Local.Authority.StoreID, SourceKeyRevision: sourceCfg.Local.Authority.KeyRevision, DestinationDomain: cfg.Local.Authority.Namespace, DestinationStoreID: cfg.Local.Authority.StoreID, SourcePeerBindingDigest: sourceCfg.Local.BindingDigest, DestinationPeerBindingDigest: cfg.Local.BindingDigest, Principal: caller.PrincipalView(), OriginalPrincipal: caller.PrincipalView(), InvocationID: env.ID, ReceiptDigest: sha256.Sum256(bundleRaw), Action: "status", PayloadDigest: sha256.Sum256(payload), ReplayID: "native-final-read", IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(30 * time.Second).Format(time.RFC3339Nano), BindingProfile: federation.Profile}
	var signed fabric.SignedControlProof
	err = session.WithAuthenticatedControl(ctx, control, payload, func(c context.Context, p fabric.ExecutionContext) error {
		g, err := NewSourceControlGate(sourceGate, auth, p, sourceCfg.Local, sourceCfg.Remote)
		if err != nil {
			return err
		}
		signed, err = a.installation.Store.SignControlExact(c, a.owner, p, payload, control, g)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenNativeFinalOutputs(ctx, boundary, runtime.Adapter, b.installation.Keys)
	if err != nil {
		t.Fatal("reopen native final projection", err)
	}
	var output bytes.Buffer
	err = boundary.AuthenticateControl(ctx, cfg, federation.ControlRequest{Proof: signed, Payload: payload}, func(c context.Context, p fabric.ExecutionContext) error {
		for ordinal := uint64(0); ; ordinal++ {
			frame, err := outputs.Frame(c, p, reference, ordinal)
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return err
			}
			retained, err := reopened.Frame(c, p, reference, ordinal)
			want, _ := json.Marshal(frame)
			got, _ := json.Marshal(retained)
			if err != nil || !bytes.Equal(want, got) {
				t.Fatal("reopened native final frame differs", err)
			}
			if frame.InvocationID != env.ID || frame.Sequence != ordinal {
				t.Fatal("source identity relabeled")
			}
			if frame.Kind == fabric.FrameError {
				t.Fatal(frame.Error)
			}
			if frame.Kind == fabric.FrameChunk {
				output.Write(frame.Data)
			}
		}
	})
	if err != nil {
		t.Fatal("genuine native final output", err)
	}
	if nativeChunks.Load() < 1 || nativeCompletions.Load() != 1 {
		t.Fatal("actual accepted native pipeline skipped HTTP phase", nativeChunks.Load(), nativeCompletions.Load())
	}
	if output.String() != "[fake-persist local-native] handled let original remote once: let original remote once" {
		t.Fatal("original native content differs", output.String())
	}
	if _, err = remote.Start(ctx, bundle); err == nil {
		t.Fatal("original native invocation resent")
	}
	remote.wg.Wait()
	// The final stream may release delivery but not replace/stop the accepted
	// runtime. The retained journal proves the original physical source directly.
	claim, err := runtime.Checkpoints.LookupLaunch(ctx, mustNativeOwnership(t, runtime, b.owner, scope))
	if err != nil || !claim.Exists {
		t.Fatal(err)
	}
	client, err := runtime.Resolver.Refresh(ctx, b.owner, claim.Ownership)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Client.Call(ctx, sessionworker.LocalRequest{Type: "snapshot"})
	clear(client.ControlKey)
	if err != nil || response.Snapshot == nil || response.Snapshot.PID <= 1 || response.Snapshot.NativeSessionID == "" {
		t.Fatal("lost original runtime", err)
	}

}
func mustNativeOwnership(t *testing.T, r *NativeRuntime, owner fabric.ExecutionContext, scope registry.DescriptorBatchScope) nativeauthority.Scope {
	t.Helper()
	_, b, err := r.Authority.RetainedNativeControl(t.Context(), owner, identity.Scope{Endpoint: scope.Endpoint, DescriptorRevision: scope.ExpectedEndpointRevision, BindingID: scope.BindingID})
	if err != nil {
		t.Fatal(err)
	}
	s, err := nativeauthority.NewLocalScope(r.Authority.Identity(), b)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
