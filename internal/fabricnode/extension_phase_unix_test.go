//go:build linux || darwin

package fabricnode

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/extension"
	extregistry "github.com/pagnet-code/pagnet/fabric/extension/registry"
	"github.com/pagnet-code/pagnet/fabric/mcpbridge"
	"github.com/pagnet-code/pagnet/fabric/node/dispatch"
	"github.com/pagnet-code/pagnet/internal/fabricauth"
)

type phaseFixtureBindings struct{}

func (phaseFixtureBindings) Select(context.Context, fabric.ExecutionContext, fabric.EndpointDescriptor, *fabric.OfferDescriptor) (dispatch.Selection, error) {
	return dispatch.Selection{BindingID: "phase.fixture"}, nil
}

type phaseFixtureFrames struct {
	id      string
	ordinal uint64
}

func (s *phaseFixtureFrames) Next(context.Context) (fabric.InvocationFrame, error) {
	if s.ordinal >= 3 {
		return fabric.InvocationFrame{}, io.EOF
	}
	kind := []fabric.FrameKind{fabric.FrameStart, fabric.FrameChunk, fabric.FrameComplete}[s.ordinal]
	frame := fabric.InvocationFrame{InvocationID: s.id, Sequence: s.ordinal, Kind: kind}
	s.ordinal++
	return frame, nil
}
func (*phaseFixtureFrames) Close() error { return nil }

// No endpoint effect is simulated here: actual SDK/installed source execution
// is covered by the paired Runtime fixtures. This proves HTTP phase authority
// using a genuine kernel session and a blocked real HTTP hook.
func TestExtensionHTTPPhaseRechecksRealSessionAfterSlowHook(t *testing.T) {
	for _, mode := range []string{"session_close", "plan_remove"} {
		t.Run(mode, func(t *testing.T) { extensionHTTPPhaseRevocation(t, mode) })
	}
}

func extensionHTTPPhaseRevocation(t *testing.T, mode string) {
	r, i := extensionLifecycleRuntime(t)
	r.config.Bindings = phaseFixtureBindings{}
	root := i.Store.AuthorityIdentity()
	socket := filepath.Join(filepath.Dir(i.Configuration().Settings.SocketPath), "phase.sock")
	auth, err := fabricauth.New(fabricauth.Config{Root: root, RootOwner: root.Owner, Audience: root.Namespace, SocketPath: socket, CurrentRoot: i.Store.CurrentAuthorityIdentity})
	if err != nil {
		t.Fatal(err)
	}
	r.boundary.sessions = auth
	session, closeSession := runtimeOwnerSession(t, t.Context(), &NativeRuntime{Authenticator: auth}, socket)
	defer closeSession()
	owner, err := i.Operator(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	ref, err := fabric.NewEndpointRef(root.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	revision, err := i.Store.Register(t.Context(), owner, fabric.RegistryUpdate{Descriptor: fabric.EndpointDescriptor{Ref: ref, Kind: "test.phase", Name: "Phase source", Bindings: []fabric.BindingSummary{{ID: "phase.fixture", Protocol: "test.fixture", Version: "1"}}}})
	if err != nil {
		t.Fatal(err)
	}
	entered, finish := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var call extension.InterceptRequest
		if json.NewDecoder(req.Body).Decode(&call) != nil {
			w.WriteHeader(400)
			return
		}
		calls.Add(1)
		if call.Phase == extension.PhaseChunk {
			close(entered)
			<-finish
		}
		json.NewEncoder(w).Encode(extension.Decision{Action: extension.Continue})
	}))
	defer server.Close()
	var installation extregistry.Reference
	err = session.WithOwnerAdministration(t.Context(), []byte(`{"operation":"phase.install"}`), func(ctx context.Context, admin *fabricauth.OwnerAdministration) error {
		digest, e := r.PutProfile(ctx, admin, ExtensionProfile{Protocol: extensionHTTPProtocol, URL: server.URL, CredentialSelector: "credentials.none", MaxConcurrency: 1})
		if e != nil {
			return e
		}
		installation, e = r.Install(ctx, admin, 1, extregistry.Installation{Manifest: extension.ExtensionManifest{ManifestVersion: "1.0", ID: "test.phase", Version: "1", MinProtocol: "1.0", MaxProtocol: "1.0", Interceptors: []extension.Registration{{ID: "test.phase.hook", Match: extension.Match{Operation: fabric.OperationInvoke, Stage: "invoke.dispatch"}, Placement: extension.PlacementSource, Phases: []extension.Phase{extension.PhaseRequest, extension.PhaseResponse, extension.PhaseChunk, extension.PhaseCompletion}, TimeoutMillis: 5000, Binding: "phase.http"}}}, Bindings: []extregistry.Binding{{ID: "phase.http", Protocol: extensionHTTPProtocol, Selector: "credentials.none", ProfileDigest: digest}}})
		return e
	})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().UTC().Add(20 * time.Second)
	raw, proof, err := session.Build(t.Context(), mcpbridge.Call{Operation: fabric.OperationInvoke, Invoke: &fabric.InvokeRequest{Target: ref, ExpectedRevision: revision, Input: json.RawMessage(`{}`), Deadline: &deadline}})
	if err != nil {
		t.Fatal(err)
	}
	caller, err := auth.Authenticate(t.Context(), fabric.AuthenticationRequest{ExactEnvelope: raw, Audience: root.Namespace, PeerEvidence: proof})
	if err != nil {
		t.Fatal(err)
	}
	result, err := r.ExecuteStage(t.Context(), caller, raw, root.Namespace, "invoke.dispatch", extension.PlacementSource, func(_ context.Context, _ fabric.ExecutionContext, envelope fabric.Envelope) (extension.Outcome, error) {
		return extension.Outcome{Stream: &phaseFixtureFrames{id: envelope.ID}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer result.Stream.Close()
	if _, err = result.Stream.Next(t.Context()); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, e := result.Stream.Next(t.Context()); done <- e }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("chunk phase never reached real HTTP")
	}
	if mode == "session_close" {
		session.Close()
	} else {
		err = session.WithOwnerAdministration(t.Context(), []byte(`{"operation":"phase.remove"}`), func(ctx context.Context, admin *fabricauth.OwnerAdministration) error {
			return r.Remove(ctx, admin, 2, installation.Revision, "test.phase")
		})
		if err != nil {
			close(finish)
			t.Fatal(err)
		}
	}
	close(finish)
	select {
	case err = <-done:
		if err == nil {
			t.Fatal("late HTTP accepted after genuine session revocation")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("revoked HTTP phase did not join")
	}
	if calls.Load() != 3 {
		t.Fatal("revoked actor caused another hook", calls.Load())
	}
}
