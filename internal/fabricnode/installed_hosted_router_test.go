//go:build linux || darwin

// The step-6b hosted-native invoke router over a genuine installation: the
// provider's fail-closed deferred holders and its single-hosted-actor
// resolution (exact target + the actor's own principal only), and the
// adapter's retained-prompt grammar gate (an undeliverable prompt is refused
// as invalid input BEFORE any seal or journal write; a deliverable prompt
// passes the gate and fails later at the genuine daemon probe).

package fabricnode

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/localinstallation"
	"github.com/pagnet-code/pagnet/fabric/node"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/fabricagent"
	"github.com/pagnet-code/pagnet/internal/fabricauth"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
)

// hostedRouterFixture is the step-6b router over a real, empty trust
// boundary: a genuine local installation with the installed hosted endpoint
// registered (and the operator-selected profile installed under a real
// kernel owner session), the fused node, and a real daemon over the node's
// daemon-side components (no host connection, no launched worker).
type hostedRouterFixture struct {
	t        *testing.T
	n        *InstalledNode
	h        *InstalledHosted
	deferred *hostedDeferred
	provider *hostedNativeProvider

	root     registry.AuthorityIdentity
	owner    fabric.ExecutionContext
	ref      fabric.EndpointRef
	revision fabric.Revision
	profile  fabricagent.HostedProfile
	actor    fabric.Principal
}

func newHostedRouterFixture(t *testing.T) *hostedRouterFixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 120*time.Second)
	t.Cleanup(cancel)

	parent := t.TempDir()
	socketDir := filepath.Join(parent, "run")
	if err := os.Mkdir(socketDir, 0o700); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(parent, "authority")
	socket := filepath.Join(socketDir, "node.sock")
	bootstrap, err := localinstallation.Bootstrap(ctx, dir, localinstallation.Options{Settings: localinstallation.DefaultSettings(socket)})
	if err != nil {
		t.Fatal(err)
	}
	owner, err := bootstrap.Operator(ctx)
	if err != nil {
		t.Fatal(err)
	}
	root := bootstrap.Store.AuthorityIdentity()
	ref, err := fabric.NewEndpointRef(root.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := fabric.EndpointDescriptor{
		Ref: ref, Kind: "actor.agent", Name: "Hosted", Description: "Step 6b hosted router target",
		Bindings: []fabric.BindingSummary{{ID: "original", Protocol: HostedNativeBindingProtocol, Version: "1"}},
	}
	revision, err := bootstrap.Store.Register(ctx, owner, fabric.RegistryUpdate{Descriptor: descriptor})
	if err != nil {
		t.Fatal(err)
	}
	if err := bootstrap.Close(); err != nil {
		t.Fatal(err)
	}

	// The operator-selected original worker association: the cloud identity
	// the operator pinned (no launched worker exists in this fixture; the
	// explicit probe pins the fields the adapter must present).
	profile := fabricagent.HostedProfile{
		DefinitionID:    domain.NewID().String(),
		PrincipalID:     domain.NewID().String(),
		NetworkID:       domain.NewID().String(),
		OwnershipID:     domain.NewID().String(),
		NativeProfile:   [32]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20},
		WorkerDirectory: t.TempDir(),
		Scope: sessionworker.Scope{
			ServerURL:  "https://app.pagnet.dev",
			TenantID:   domain.NewID().String(),
			AccountID:  domain.NewID().String(),
			HostID:     domain.NewID().String(),
			InstanceID: domain.NewID().String(),
			Generation: "1",
		},
	}
	if err := profile.Validate(); err != nil {
		t.Fatalf("fixture profile is invalid: %v", err)
	}
	probe := func(_ context.Context, p fabricagent.HostedProfile) error {
		if p.NetworkID != profile.NetworkID || p.OwnershipID != profile.OwnershipID || p.Scope != profile.Scope || p.NativeProfile != profile.NativeProfile || p.WorkerDirectory != profile.WorkerDirectory {
			return errors.New("fixture probe: profile does not match the original worker")
		}
		return nil
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	n, err := OpenInstalled(ctx, InstalledConfig{Directory: dir, Binary: binary, Hosted: &InstalledHostedConfig{Probe: probe}})
	if err != nil {
		t.Fatalf("OpenInstalled: %v", err)
	}
	t.Cleanup(func() { _ = n.Close() })
	h := n.Hosted
	if h == nil {
		t.Fatal("the hosted product was not composed")
	}

	// The real daemon over the node's daemon-side components (the fused
	// composition), wired into the product and the provider's deferred
	// holder exactly as cmd/pagnet wires it post-daemon.
	d := newFusedDaemon(t, h, &gateCell{})
	h.SetDaemon(d)
	deferred := newHostedDeferred()
	deferred.setDaemon(d)
	provider := newHostedNativeProvider(n, deferred)
	provider.setProduct(h)

	// Install the operator-selected profile under a genuine kernel owner
	// session (the same binding the production admin act runs under): the
	// fixture's own socket in the 0700 directory, bound like the node's.
	owner, err = n.Installation.Operator(ctx)
	if err != nil {
		t.Fatal(err)
	}
	scope := registry.DescriptorBatchScope{Endpoint: ref, ExpectedEndpointRevision: revision, BindingID: "original"}
	adminSocket := filepath.Join(socketDir, "owner.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: adminSocket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	if err := os.Chmod(adminSocket, 0o600); err != nil {
		t.Fatal(err)
	}
	peer, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: adminSocket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { peer.Close() })
	accepted, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { accepted.Close() })
	auth, err := fabricauth.New(fabricauth.Config{
		Root: root, RootOwner: root.Owner, Audience: root.Namespace,
		SocketPath: adminSocket, CurrentRoot: n.Installation.Store.CurrentAuthorityIdentity,
	})
	if err != nil {
		t.Fatal(err)
	}
	session, err := auth.BindOwner(ctx, accepted)
	if err != nil {
		t.Fatalf("bind the fixture owner session: %v", err)
	}
	t.Cleanup(func() { session.Close() })
	if err := session.WithOwnerAdministration(ctx, []byte(`{"operation":"fixture.profile.install"}`), func(ctx context.Context, access *fabricauth.OwnerAdministration) error {
		_, e := h.Profiles.Install(ctx, access, scope, profile)
		return e
	}); err != nil {
		t.Fatalf("install the operator-selected profile: %v", err)
	}

	f := &hostedRouterFixture{
		t: t, n: n, h: h, deferred: deferred, provider: provider,
		root: root, owner: owner, ref: ref, revision: revision, profile: profile,
		actor: fabric.Principal{Ref: ref.String(), Kind: descriptor.Kind, Issuer: root.Namespace},
	}
	return f
}

func (f *hostedRouterFixture) descriptor() fabric.EndpointDescriptor {
	f.t.Helper()
	descriptor, err := f.n.Installation.Store.GetEndpoint(f.t.Context(), f.ref, f.revision)
	if err != nil {
		f.t.Fatal(err)
	}
	return descriptor
}

func (f *hostedRouterFixture) binding() fabric.BindingSummary {
	return fabric.BindingSummary{ID: "original", Protocol: HostedNativeBindingProtocol, Version: "1"}
}

func (f *hostedRouterFixture) actorContext() fabric.ExecutionContext {
	f.t.Helper()
	descriptorBytes, err := json.Marshal(f.descriptor())
	if err != nil {
		f.t.Fatal(err)
	}
	caller, err := fabric.NewAuthenticatedContext(f.actor, f.root.Namespace, descriptorBytes)
	if err != nil {
		f.t.Fatal(err)
	}
	return caller
}

func (f *hostedRouterFixture) ownerContext() fabric.ExecutionContext {
	f.t.Helper()
	caller, err := fabric.NewAuthenticatedContext(f.owner.PrincipalView(), f.root.Namespace, []byte("fixture owner evidence"))
	if err != nil {
		f.t.Fatal(err)
	}
	return caller
}

// journalCounts returns the retained hosted-invocation journal markers and
// original-dispatch claims in the installation (the grammar gate must leave
// both at zero).
func (f *hostedRouterFixture) journalCounts(t *testing.T) (int, int) {
	t.Helper()
	ctx := t.Context()
	owner, err := f.n.Installation.Operator(ctx)
	if err != nil {
		t.Fatal(err)
	}
	list := func(prefix string, skipNested bool) int {
		t.Helper()
		n := 0
		cursor := ""
		for {
			page, err := f.n.Installation.Store.ListGlobalAuthorityRecords(ctx, owner, registry.AuthorityNativeCheckpoint, prefix, cursor, 32)
			if err != nil {
				t.Fatalf("list %s records: %v", prefix, err)
			}
			for _, r := range page.Records {
				if skipNested && (strings.Contains(r.Key.ID, "/chunk/") || r.Key.ID == "hosted/invocation/capacity") {
					continue
				}
				n++
			}
			if page.NextCursor == "" {
				return n
			}
			cursor = page.NextCursor
		}
	}
	return list("hosted/invocation/", true), list("original-dispatch/", false)
}

func hostedRouterErrorCode(t *testing.T, err error) fabric.ErrorCode {
	t.Helper()
	if err == nil {
		t.Fatal("expected a refusal, got nil")
	}
	var fe *fabric.Error
	if !errors.As(err, &fe) {
		t.Fatalf("refusal %v is not a structured fabric error", err)
	}
	return fe.Code
}

// TestHostedRouterProviderFailClosed proves the provider's deferred holders:
// an unwired resolution is an honest refusal (never a fabricated adapter or
// fingerprint), in both the missing-product and the missing-daemon states,
// and a fully wired provider still refuses offers.
func TestHostedRouterProviderFailClosed(t *testing.T) {
	f := newHostedRouterFixture(t)
	ctx := t.Context()
	target := f.descriptor()
	binding := f.binding()

	// (a) No product (setProduct never called): the router itself is not
	// wired yet.
	unwired := newHostedNativeProvider(f.n, newHostedDeferred())
	if _, _, err := unwired.ResolveBinding(ctx, f.actorContext(), target, binding, nil); err == nil {
		t.Fatal("unwired provider resolved an adapter")
	} else if code := hostedRouterErrorCode(t, err); code != fabric.CodeTargetUnavailable || !strings.Contains(err.Error(), "router") {
		t.Fatalf("unwired provider refusal = %s / %q, want the honest router refusal", code, err)
	}

	// (b) Product wired, daemon not wired: the daemon holder refuses.
	productOnly := newHostedNativeProvider(f.n, newHostedDeferred())
	productOnly.setProduct(f.h)
	if _, _, err := productOnly.ResolveBinding(ctx, f.actorContext(), target, binding, nil); err == nil {
		t.Fatal("daemon-less provider resolved an adapter")
	} else if code := hostedRouterErrorCode(t, err); code != fabric.CodeTargetUnavailable || !strings.Contains(err.Error(), "daemon") {
		t.Fatalf("daemon-less provider refusal = %s / %q, want the honest daemon refusal", code, err)
	}

	// (c) Fully wired: offers are refused (the installed endpoint only).
	if _, _, err := f.provider.ResolveBinding(ctx, f.actorContext(), target, binding, &fabric.OfferDescriptor{}); err == nil {
		t.Fatal("wired provider resolved an offer")
	} else if code := hostedRouterErrorCode(t, err); code != fabric.CodeStaleReference {
		t.Fatalf("offer refusal = %s / %q, want the stale-reference refusal", code, err)
	}

	// (d) Unauthenticated routing is refused.
	if _, _, err := f.provider.ResolveBinding(ctx, fabric.ExecutionContext{}, target, binding, nil); err == nil {
		t.Fatal("unauthenticated resolution allowed")
	} else if code := hostedRouterErrorCode(t, err); code != fabric.CodeUnauthenticated {
		t.Fatalf("unauthenticated refusal = %s, want the unauthenticated code", code)
	}
}

// TestHostedRouterProviderResolution proves the single-hosted-actor
// selection: the exact installed endpoint under the actor's own principal
// resolves the adapter with the installed profile's native fingerprint, while
// a wrong target (a hosted binding without an installed profile), a wrong
// binding ID, or a wrong caller (the owner) is an honest refusal.
func TestHostedRouterProviderResolution(t *testing.T) {
	f := newHostedRouterFixture(t)
	ctx := t.Context()
	target := f.descriptor()
	binding := f.binding()

	// Correct target + caller: the adapter and the pinned fingerprint.
	adapter, fingerprint, err := f.provider.ResolveBinding(ctx, f.actorContext(), target, binding, nil)
	if err != nil {
		t.Fatalf("correct target + caller refused: %v", err)
	}
	if adapter == nil || fingerprint != f.profile.NativeProfile {
		t.Fatalf("resolution = adapter %v / fingerprint %x, want the adapter and the installed native profile", adapter, fingerprint)
	}

	// Wrong caller (the installation owner is not the hosted actor).
	if _, _, err := f.provider.ResolveBinding(ctx, f.ownerContext(), target, binding, nil); err == nil {
		t.Fatal("the owner resolved the hosted adapter")
	} else if code := hostedRouterErrorCode(t, err); code != fabric.CodeUnauthenticated {
		t.Fatalf("owner refusal = %s, want the unauthenticated code", code)
	}

	// Wrong target: a second hosted binding WITHOUT an installed profile.
	// It is not an installed hosted binding, so the selection stays on the
	// installed endpoint and this target differs from it.
	ref2, err := fabric.NewEndpointRef(f.root.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	descriptor2 := fabric.EndpointDescriptor{
		Ref: ref2, Kind: "actor.agent", Name: "Uninstalled", Description: "Hosted binding without an installed profile",
		Bindings: []fabric.BindingSummary{{ID: "original", Protocol: HostedNativeBindingProtocol, Version: "1"}},
	}
	rev2, err := f.n.Installation.Store.Register(ctx, f.owner, fabric.RegistryUpdate{Descriptor: descriptor2})
	if err != nil {
		t.Fatal(err)
	}
	descriptor2.Revision = rev2
	if _, _, err := f.provider.ResolveBinding(ctx, f.actorContext(), descriptor2, binding, nil); err == nil {
		t.Fatal("the uninstalled hosted endpoint resolved an adapter")
	} else if code := hostedRouterErrorCode(t, err); code != fabric.CodeStaleReference {
		t.Fatalf("wrong-target refusal = %s, want the stale-reference code", code)
	}

	// Wrong binding ID on the installed target.
	if _, _, err := f.provider.ResolveBinding(ctx, f.actorContext(), target, fabric.BindingSummary{ID: "other", Protocol: HostedNativeBindingProtocol, Version: "1"}, nil); err == nil {
		t.Fatal("a foreign binding ID resolved the adapter")
	} else if code := hostedRouterErrorCode(t, err); code != fabric.CodeStaleReference {
		t.Fatalf("wrong-binding refusal = %s, want the stale-reference code", code)
	}
}

// hostedRouterAuthenticator accepts exactly the installed hosted actor's
// envelopes (the test-side stand-in for the node's genuine hosted session
// admission; the principal is the decoded envelope principal, nothing else).
type hostedRouterAuthenticator struct{ actor fabric.Principal }

func (a hostedRouterAuthenticator) Authenticate(_ context.Context, r fabric.AuthenticationRequest) (fabric.ExecutionContext, error) {
	var e fabric.Envelope
	if fabric.DecodeJSON(r.ExactEnvelope, &e) != nil || e.Principal != a.actor {
		return fabric.ExecutionContext{}, fabric.NewError(fabric.CodeUnauthenticated, "fixture caller denied")
	}
	return fabric.NewAuthenticatedContext(a.actor, r.Audience, r.ExactEnvelope)
}

// hostedRouterDirectDispatcher drives the exact registered descriptor through
// the real provider (no offer selection, no search).
type hostedRouterDirectDispatcher struct {
	router     *Router
	descriptor fabric.EndpointDescriptor
}

func (d hostedRouterDirectDispatcher) Invoke(ctx context.Context, c fabric.ExecutionContext, r fabric.InvokeRequest) (fabric.InvocationStream, error) {
	selected, e := d.router.Select(ctx, c, d.descriptor, nil)
	if e != nil {
		return nil, e
	}
	return selected.Adapter.Invoke(ctx, c, d.descriptor, r)
}

// TestHostedRouterAdapterPromptGrammarBeforeJournal proves the adapter's
// retained-prompt gate: an undeliverable prompt (unknown field, empty input,
// non-string input, or more than 128 KiB) is refused as invalid input BEFORE
// any seal or journal write, and a deliverable prompt passes the gate and
// fails LATER (the genuine daemon probe, no worker in this fixture) — the
// journal is empty in both cases.
func TestHostedRouterAdapterPromptGrammarBeforeJournal(t *testing.T) {
	f := newHostedRouterFixture(t)
	ctx := t.Context()

	router, err := NewRouter(map[BindingProtocol]BindingProvider{{Protocol: HostedNativeBindingProtocol, Version: "1"}: f.provider})
	if err != nil {
		t.Fatal(err)
	}
	n, err := node.New(node.Config{
		Audience:      f.root.Namespace,
		Authenticator: hostedRouterAuthenticator{actor: f.actor},
		Dispatcher:    hostedRouterDirectDispatcher{router: router, descriptor: f.descriptor()},
	})
	if err != nil {
		t.Fatal(err)
	}

	run := func(payload string) (fabric.ErrorCode, bool) {
		t.Helper()
		env := fabric.Envelope{
			ProtocolVersion:  fabric.CurrentProtocolVersion,
			ID:               domain.NewID().String(),
			Operation:        fabric.OperationInvoke,
			Principal:        f.actor,
			Source:           f.actor.Ref,
			Target:           &f.ref,
			ExpectedRevision: f.revision,
			CreatedAt:        time.Now().UTC(),
			Payload:          json.RawMessage(payload),
			Context:          fabric.EnvelopeContext{Origin: f.actor.Ref},
		}
		raw, err := json.Marshal(env)
		if err != nil {
			t.Fatal(err)
		}
		_, err = n.Execute(ctx, raw, nil)
		if err == nil {
			t.Fatal("the invoke completed; it must be refused (no worker is connected)")
		}
		var fe *fabric.Error
		if !errors.As(err, &fe) {
			t.Fatalf("invoke failure %v is not a structured fabric error", err)
		}
		return fe.Code, strings.Contains(err.Error(), "prompt")
	}

	// Undeliverable prompts: refused as invalid input, never journaled.
	oversized := `{"input":"` + strings.Repeat("x", 128<<10+1) + `"}`
	for name, payload := range map[string]string{
		"unknown field": `{"input":"exact prompt","extra":1}`,
		"empty input":   `{"input":""}`,
		"non-string":    `{"input":7}`,
		"oversized":     oversized,
		"not an object": `"just a string"`,
	} {
		code, mentionsPrompt := run(payload)
		if code != fabric.CodeInvalidInput {
			t.Fatalf("%s: code = %s, want the invalid-input refusal", name, code)
		}
		if !mentionsPrompt {
			t.Fatalf("%s: refusal %q must be the retained-prompt gate", name, payload)
		}
		if markers, claims := f.journalCounts(t); markers != 0 || claims != 0 {
			t.Fatalf("%s: the journal retained %d markers / %d claims; an undeliverable prompt must never be sealed or journaled", name, markers, claims)
		}
	}

	// A deliverable prompt passes the grammar gate: the failure is a LATER,
	// non-grammar one (the genuine daemon probe finds no worker), and the
	// journal is still empty (nothing is sealed before the probe).
	code, _ := run(`{"input":"exact retained hosted prompt"}`)
	if code == fabric.CodeInvalidInput {
		t.Fatal("a deliverable prompt was refused by the grammar gate")
	}
	if code != fabric.CodeTargetUnavailable {
		t.Fatalf("deliverable prompt failed with %s, want the daemon-component failure after the grammar gate", code)
	}
	if markers, claims := f.journalCounts(t); markers != 0 || claims != 0 {
		t.Fatalf("the deliverable prompt journaled %d markers / %d claims before its probe failure", markers, claims)
	}
}
