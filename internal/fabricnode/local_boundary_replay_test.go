//go:build linux || darwin

package fabricnode

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/localinstallation"
	"github.com/pagnet-code/pagnet/fabric/mcpbridge"
	"github.com/pagnet-code/pagnet/fabric/node"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/fabricauth"
	"github.com/pagnet-code/pagnet/internal/fabricservices"
)

type replayPolicyDispatcher struct {
	invoke func(context.Context, fabric.ExecutionContext, fabric.InvokeRequest) (fabric.InvocationStream, error)
}

func (d replayPolicyDispatcher) Invoke(ctx context.Context, c fabric.ExecutionContext, r fabric.InvokeRequest) (fabric.InvocationStream, error) {
	return d.invoke(ctx, c, r)
}

type noEffectReplayPolicyStream struct{}

func (noEffectReplayPolicyStream) Next(context.Context) (fabric.InvocationFrame, error) {
	return fabric.InvocationFrame{}, io.EOF
}
func (noEffectReplayPolicyStream) Close() error { return nil }

func TestActualReplayPolicyOuterRequestRebuildExactHistoryAndCloseRevocation(t *testing.T) {
	ctx := context.Background()
	private := t.TempDir()
	if e := os.Chmod(private, 0700); e != nil {
		t.Fatal(e)
	}
	socket := filepath.Join(private, "fabric.sock")
	installation, e := localinstallation.Bootstrap(ctx, filepath.Join(private, "root"), localinstallation.Options{Settings: localinstallation.DefaultSettings(socket)})
	if e != nil {
		t.Fatal(e)
	}
	defer installation.Close()
	owner, e := installation.Operator(ctx)
	if e != nil {
		t.Fatal(e)
	}
	root := installation.Store.AuthorityIdentity()
	boundary, e := newLocalBoundary(ctx, installation.Store, owner, installation, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	auth, e := fabricauth.New(fabricauth.Config{Root: root, RootOwner: root.Owner, Audience: root.Namespace, SocketPath: socket, CurrentRoot: installation.Store.CurrentAuthorityIdentity})
	if e != nil {
		t.Fatal(e)
	}
	boundary.sessions = auth
	session, closeSession := runtimeOwnerSession(t, ctx, &NativeRuntime{Authenticator: auth}, socket)
	defer closeSession()
	ref, _ := fabric.NewEndpointRef(root.PublicKey)
	rev, e := installation.Store.Register(ctx, owner, fabric.RegistryUpdate{Descriptor: fabric.EndpointDescriptor{Ref: ref, Kind: "service.mcp", Name: "Selected replay policy target", Bindings: []fabric.BindingSummary{{ID: "mcp", Protocol: "mcp.tools", Version: "1", Idempotency: true}}}})
	if e != nil {
		t.Fatal(e)
	}
	scope := registry.DescriptorBatchScope{Endpoint: ref, ExpectedEndpointRevision: rev, BindingID: "mcp"}
	fingerprint := sha256.Sum256([]byte("actual operator-selected test profile"))
	checks := 0
	service, e := node.New(node.Config{Audience: root.Namespace, Authenticator: auth, Descriptors: installation.Store, Dispatcher: replayPolicyDispatcher{invoke: func(current context.Context, caller fabric.ExecutionContext, r fabric.InvokeRequest) (fabric.InvocationStream, error) {
		actual, original, final, ok := node.FinalizedRequestFromContext(current)
		if !ok || actual.PrincipalView() != caller.PrincipalView() {
			t.Fatal("actual node capability absent")
		}
		facts := fabricservices.InvocationFacts{Principal: caller.PrincipalView(), InvocationID: r.InvocationID, Target: r.Target, Revision: r.ExpectedRevision, Scope: scope, Fingerprint: fingerprint, OriginalSHA: sha256.Sum256(original), FinalizedSHA: sha256.Sum256(final), InputSHA: sha256.Sum256(r.Input)}
		old := facts
		old.InvocationID = "original-execution"
		old.OriginalSHA = sha256.Sum256([]byte("different exact original"))
		old.FinalizedSHA = sha256.Sum256([]byte("different original dispatch"))
		check := func(stamped context.Context, c, o fabricservices.InvocationFacts) error {
			return installation.Store.WithNativeAuthority(stamped, owner, registry.AuthorityScope{Endpoint: ref, ExpectedRevision: rev, BindingID: "mcp"}, func(tx *registry.AuthorityTx) error {
				return boundary.AuthorizeHistoryTx(stamped, tx, caller, c, o, "alias_verify")
			})
		}
		if check(current, facts, old) == nil {
			t.Fatal("outer unstamped request authorized alias")
		}
		if boundary.WithReplayRequest(ctx, caller, facts, func(context.Context) error { t.Fatal("wire facts minted node capability"); return nil }) == nil {
			t.Fatal("missing opaque node capability accepted")
		}
		err := boundary.WithReplayRequest(current, caller, facts, func(stamped context.Context) error {
			if e := check(stamped, facts, old); e != nil {
				return e
			}
			checks++
			for _, mutate := range []func(*fabricservices.InvocationFacts){func(f *fabricservices.InvocationFacts) { f.Principal.Issuer = "foreign" }, func(f *fabricservices.InvocationFacts) { f.Target, _ = fabric.NewEndpointRef(root.PublicKey) }, func(f *fabricservices.InvocationFacts) { f.Revision = "changed" }, func(f *fabricservices.InvocationFacts) { f.Scope.BindingID = "changed" }, func(f *fabricservices.InvocationFacts) { f.Fingerprint[0] ^= 1 }, func(f *fabricservices.InvocationFacts) { f.InputSHA[0] ^= 1 }} {
				wrong := old
				mutate(&wrong)
				if check(stamped, facts, wrong) == nil {
					t.Fatal("changed original execution promoted to alias")
				}
			}
			changed := facts
			changed.FinalizedSHA[0] ^= 1
			if check(stamped, changed, old) == nil {
				t.Fatal("changed current request accepted")
			}
			static, _ := fabric.NewAuthenticatedContext(caller.PrincipalView(), root.Namespace, original)
			if boundary.WithReplayRequest(current, static, facts, func(context.Context) error { t.Fatal("historical static principal promoted"); return nil }) == nil {
				t.Fatal("static caller gained replay permission")
			}
			if e := session.Close(); e != nil {
				t.Fatal(e)
			}
			if check(stamped, facts, old) == nil {
				t.Fatal("Session.Close before destination TX did not revoke alias")
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		return noEffectReplayPolicyStream{}, nil
	}}})
	if e != nil {
		t.Fatal(e)
	}
	deadline := time.Now().UTC().Add(time.Minute)
	raw, proof, e := session.Build(ctx, mcpbridge.Call{Operation: fabric.OperationInvoke, Invoke: &fabric.InvokeRequest{Target: ref, ExpectedRevision: rev, Input: json.RawMessage(`{"input":"exact"}`), IdempotencyKey: "same-private-key", Deadline: &deadline}})
	if e != nil {
		t.Fatal(e)
	}
	result, e := service.Execute(ctx, raw, proof)
	if e != nil {
		t.Fatal("actual private replay policy failed", e)
	}
	if checks != 1 {
		t.Fatal("replay policy callback not exactly once", checks)
	}
	_ = result.Stream.Close()
}
