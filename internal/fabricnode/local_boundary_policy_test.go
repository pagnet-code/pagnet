//go:build linux || darwin

package fabricnode

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/localinstallation"
	"github.com/pagnet-code/pagnet/fabric/mcpbridge"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/fabricauth"
	"github.com/pagnet-code/pagnet/internal/fabricservices"
)

func TestLocalBoundaryCallbackErrorRepeatEscapeAndUnsealedDeny(t *testing.T) {
	ctx := context.Background()
	expected := errors.New("original destination failure")
	calls := 0
	err := guardedBoundary(ctx, func(c context.Context, n func(context.Context) error) error { _ = n(c); return nil }, func(context.Context) error { calls++; return expected })
	if !errors.Is(err, expected) || calls != 1 {
		t.Fatal("swallowed destination failure", err, calls)
	}
	calls = 0
	err = guardedBoundary(ctx, func(c context.Context, n func(context.Context) error) error { _ = n(c); _ = n(c); return nil }, func(context.Context) error { calls++; return nil })
	if err == nil || calls != 1 {
		t.Fatal("repeated callback admitted", err, calls)
	}
	var escaped func(context.Context) error
	err = guardedBoundary(ctx, func(c context.Context, n func(context.Context) error) error { escaped = n; return n(c) }, func(context.Context) error { calls++; return nil })
	if err != nil || escaped(ctx) == nil {
		t.Fatal("escaped callback remained usable")
	}
}

func TestLocalServicePrivateStampExactFactsCloseAndHistoricalA2AAssociation(t *testing.T) {
	ctx := context.Background()
	private := t.TempDir()
	if e := os.Chmod(private, 0700); e != nil {
		t.Fatal(e)
	}
	socket := filepath.Join(private, "fabric.sock")
	installed, e := localinstallation.Bootstrap(ctx, filepath.Join(private, "domain"), localinstallation.Options{Settings: localinstallation.DefaultSettings(socket)})
	if e != nil {
		t.Fatal(e)
	}
	defer installed.Close()
	owner, e := installed.Operator(ctx)
	if e != nil {
		t.Fatal(e)
	}
	boundary, e := newLocalBoundary(ctx, installed.Store, owner, installed, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	if boundary.callerCurrent(ctx, owner, func(context.Context) error { t.Fatal("unsealed caller escaped"); return nil }) == nil {
		t.Fatal("unsealed authority accepted caller")
	}
	root := installed.Store.AuthorityIdentity()
	authority, e := fabricauth.New(fabricauth.Config{Root: root, RootOwner: root.Owner, Audience: root.Namespace, SocketPath: socket, CurrentRoot: installed.Store.CurrentAuthorityIdentity})
	if e != nil {
		t.Fatal(e)
	}
	boundary.sessions = authority
	session, closeSession := runtimeOwnerSession(t, ctx, &NativeRuntime{Authenticator: authority}, socket)
	defer closeSession()
	raw, proof, e := session.Build(ctx, mcpbridge.Call{Operation: fabric.OperationDiscover, Discover: &fabric.DiscoverRequest{Query: "local", Limit: 10}})
	if e != nil {
		t.Fatal(e)
	}
	caller, e := authority.Authenticate(ctx, fabric.AuthenticationRequest{ExactEnvelope: raw, Audience: root.Namespace, PeerEvidence: proof})
	if e != nil {
		t.Fatal(e)
	}
	ref, _ := fabric.NewEndpointRef(root.PublicKey)
	rev, e := installed.Store.Register(ctx, owner, fabric.RegistryUpdate{Descriptor: fabric.EndpointDescriptor{Ref: ref, Kind: "service.a2a", Name: "Actual local policy target", Bindings: []fabric.BindingSummary{{ID: "service", Protocol: "a2a.jsonrpc", Version: "1"}}}})
	if e != nil {
		t.Fatal(e)
	}
	scope := registry.DescriptorBatchScope{Endpoint: ref, ExpectedEndpointRevision: rev, BindingID: "service"}
	hash := sha256.Sum256(raw)
	stamp := &dispatchStamp{boundary: boundary, association: authority, authenticatedCaller: caller, caller: root.Owner, originalSHA: hash, finalizedSHA: hash, inputSHA: hash, invocationID: "current", target: ref, revision: rev, scope: scope, fingerprint: hash}
	current := context.WithValue(ctx, dispatchStampKey{}, stamp)
	facts := fabricservices.InvocationFacts{Principal: root.Owner, InvocationID: "current", Target: ref, Revision: rev, Scope: scope, Fingerprint: hash, OriginalSHA: hash, FinalizedSHA: hash, InputSHA: hash}
	check := func(c context.Context, f fabricservices.InvocationFacts, action string) error {
		return installed.Store.WithNativeAuthority(c, owner, registry.AuthorityScope{Endpoint: ref, ExpectedRevision: rev, BindingID: "service"}, func(tx *registry.AuthorityTx) error { return boundary.AuthorizeTx(c, tx, caller, f, action) })
	}
	if e = check(current, facts, "reserve"); e != nil {
		t.Fatal("exact private current stamp denied", e)
	}
	if check(ctx, facts, "reserve") == nil {
		t.Fatal("wire-like facts created stamp")
	}
	for _, mutate := range []func(*fabricservices.InvocationFacts){func(f *fabricservices.InvocationFacts) { f.InvocationID = "other" }, func(f *fabricservices.InvocationFacts) { f.InputSHA[0] ^= 1 }, func(f *fabricservices.InvocationFacts) { f.FinalizedSHA[0] ^= 1 }, func(f *fabricservices.InvocationFacts) { f.OriginalSHA[0] ^= 1 }, func(f *fabricservices.InvocationFacts) { f.Fingerprint[0] ^= 1 }, func(f *fabricservices.InvocationFacts) { f.Revision = "other" }, func(f *fabricservices.InvocationFacts) { f.Principal.Issuer = "other" }, func(f *fabricservices.InvocationFacts) { f.Scope.BindingID = "other" }} {
		wrong := facts
		mutate(&wrong)
		if check(current, wrong, "reserve") == nil {
			t.Fatal("changed invocation facts admitted")
		}
	}
	original := facts
	original.InvocationID = "original-send"
	original.OriginalSHA[0] ^= 1
	original.FinalizedSHA[0] ^= 1
	original.InputSHA[0] ^= 1
	if check(current, original, "association_read") == nil {
		t.Fatal("unselected historical task authorized")
	}
	stamp.associationInvocation = "original-send"
	if e = check(current, original, "association_read"); e != nil {
		t.Fatal("exact selected historical association denied", e)
	}
	if check(current, original, "reserve") == nil {
		t.Fatal("history lookup authorized fresh invocation")
	}
	other := original
	other.Principal.Ref = "other"
	if check(current, other, "association_read") == nil {
		t.Fatal("foreign subject history disclosed")
	}
	if _, e = json.Marshal(caller); e == nil {
		t.Fatal("opaque association serialized")
	}
	if e = session.Close(); e != nil {
		t.Fatal(e)
	}
	if check(current, facts, "pull") == nil {
		t.Fatal("closed current association read source")
	}
}
