//go:build linux || darwin

package fabricnode

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/localinstallation"
	"github.com/pagnet-code/pagnet/internal/daemon"
	"github.com/pagnet-code/pagnet/internal/fabricadmin"
)

// gateCell is a mutex-protected cell for the advertisement gate (the gate is
// written by the test goroutine and read by the daemon's connect path, so the
// handoff is synchronized; nil = fail-closed, never advertised).
type gateCell struct {
	mu   sync.Mutex
	gate func(context.Context) bool
}

func (c *gateCell) set(g func(context.Context) bool) {
	c.mu.Lock()
	c.gate = g
	c.mu.Unlock()
}
func (c *gateCell) call(ctx context.Context) bool {
	c.mu.Lock()
	g := c.gate
	c.mu.Unlock()
	return g != nil && g(ctx)
}
func (c *gateCell) has() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.gate != nil
}

// newFusedDaemon builds a real daemon over the fused node's daemon-side
// components with the exact advertisement gate cmd/pagnet's fused serve uses
// (fail-closed until the runtime bindings are wired post-daemon, then the
// genuine bindings.Ready on the connect context).
func newFusedDaemon(t *testing.T, h *InstalledHosted, cell *gateCell) *daemon.Daemon {
	t.Helper()
	stateDir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	d, err := daemon.New(daemon.Config{
		HostID:    domain.NewID().String(),
		StateDir:  stateDir,
		NoScan:    true,
		HostedOwnerGuard:      h.OwnerGuard,
		HostedInvocationGuard: h.InvocationGuard,
		HostedFabricSideports: h.Sideports,
		HostedAdvertise:       cell.call,
	}, nil)
	if err != nil {
		t.Fatalf("daemon.New: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	d.ServerURL = "https://app.pagnet.dev"
	return d
}

// TestInstalledHostedFusedWiring proves the fused composition at the
// composition boundary (a genuine installation, a real daemon over its
// daemon-side components, no cloud, no launched worker): OpenInstalled composes
// the installed hosted product, the daemon is built over its daemon-side
// components, the runtime bindings / publisher / daemon / probe are wired
// post-daemon, and the advertisement gate transitions from fail-closed (never
// advertised) to the genuine bindings.Ready. A fresh installation has no
// retained original workers, so the owner-guard readiness is vacuously
// satisfied and the capability is advertised once wired.
func TestInstalledHostedFusedWiring(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	_, n := newHostedProductInstallation(t, ctx)
	defer func() { _ = n.Close() }()
	h := n.Hosted
	if h == nil {
		t.Fatal("the hosted product was not composed")
	}

	cell := &gateCell{}
	d := newFusedDaemon(t, h, cell)

	// Pre-wiring: the gate is fail-closed and the product is not wired.
	if cell.has() {
		t.Fatal("the advertisement gate must be nil before the daemon wiring")
	}
	if h.Wired() {
		t.Fatal("the product reports wired before the daemon wiring")
	}
	if got := d.HostedAdvertise(ctx); got {
		t.Fatal("the advertisement gate must not pass before the daemon wiring")
	}

	// Post-daemon wiring (mirrors cmd/pagnet's fused serve).
	bindings, err := NewHostedRuntimeBindings(ctx, n.Installation.Store, h.Profiles, d, h.OwnerGuard)
	if err != nil {
		t.Fatalf("NewHostedRuntimeBindings: %v", err)
	}
	cell.set(func(ctx context.Context) bool { return bindings.Ready(ctx) == nil })
	owner, err := n.Installation.Operator(ctx)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := NewHostedCatalogPublisher(ctx, bindings, owner)
	if err != nil {
		t.Fatalf("NewHostedCatalogPublisher: %v", err)
	}
	h.SetBindings(bindings)
	h.SetPublisher(publisher)
	h.SetDaemon(d)
	h.SetProbe(d.ProbeHostedProfile)

	// Post-wiring: the product is wired and the gate is the genuine readiness.
	if !h.Wired() {
		t.Fatal("the product is not wired after the daemon wiring")
	}
	if !cell.has() {
		t.Fatal("the advertisement gate was not wired")
	}
	if got := d.HostedAdvertise(ctx); !got {
		t.Fatal("the gate must advertise once wired with a (vacuously) ready owner guard")
	}
}

// TestInstalledHostedAdminListRevoke proves the hosted binding list/revoke
// acts run under the genuine owner session over the real private admin socket:
// the list is truthful (it shows the exact registered binding and never
// fabricates one), revoke retires the endpoint (NEW calls denied, the retained
// journal untouched), and the list then reflects the retired state.
func TestInstalledHostedAdminListRevoke(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	parent := t.TempDir()
	socketDir := filepath.Join(parent, "run")
	if err := os.Mkdir(socketDir, 0o700); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(parent, "authority")
	socket := filepath.Join(socketDir, "node.sock")
	installed, err := localinstallation.Bootstrap(ctx, dir, localinstallation.Options{Settings: localinstallation.DefaultSettings(socket)})
	if err != nil {
		t.Fatal(err)
	}
	owner, err := installed.Operator(ctx)
	if err != nil {
		t.Fatal(err)
	}
	root := installed.Store.AuthorityIdentity()
	ref, err := fabric.NewEndpointRef(root.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := fabric.EndpointDescriptor{
		Ref: ref, Kind: "actor.agent", Name: "Bound", Description: "A hosted binding without an installed profile",
		Bindings: []fabric.BindingSummary{{ID: "original", Protocol: HostedNativeBindingProtocol, Version: "1"}},
	}
	if _, err = installed.Store.Register(ctx, owner, fabric.RegistryUpdate{Descriptor: descriptor}); err != nil {
		t.Fatal(err)
	}
	if err = installed.Close(); err != nil {
		t.Fatal(err)
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	n, err := OpenInstalled(ctx, InstalledConfig{Directory: dir, Binary: binary, Hosted: &InstalledHostedConfig{}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = n.Close() }()

	admin, err := fabricadmin.Dial(ctx, socket)
	if err != nil {
		t.Fatalf("dial the real private admin socket: %v", err)
	}
	defer func() { _ = admin.Close() }()

	type hostedBindingView struct {
		Endpoint  string `json:"endpoint"`
		Retired   bool   `json:"retired"`
		Binding   string `json:"binding"`
		Instance  string `json:"instance,omitempty"`
		NetworkID string `json:"networkId,omitempty"`
	}
	listBindings := func() []hostedBindingView {
		t.Helper()
		response, err := admin.Call(ctx, fabricadmin.Request{Version: 1, ID: "hosted.binding.list", Operation: "hosted.binding.list", Input: []byte(`{}`)})
		if err != nil {
			t.Fatalf("hosted.binding.list transport: %v", err)
		}
		if response.Error != nil {
			t.Fatalf("hosted.binding.list: %v", response.Error)
		}
		var views []hostedBindingView
		if err := json.Unmarshal(response.Result, &views); err != nil {
			t.Fatalf("decode hosted binding list: %v (%s)", err, response.Result)
		}
		return views
	}

	// Truthful list: the one registered binding, no fabricated instance/network.
	views := listBindings()
	if len(views) != 1 || views[0].Endpoint != ref.String() || views[0].Binding != "original" || views[0].Retired {
		t.Fatalf("unexpected truthful list: %+v", views)
	}
	if views[0].Instance != "" || views[0].NetworkID != "" {
		t.Fatalf("a binding without an installed profile must not fabricate an instance/network: %+v", views[0])
	}

	// Revoke retires the endpoint.
	revokeResponse, err := admin.Call(ctx, fabricadmin.Request{
		Version: 1, ID: "hosted.binding.revoke", Operation: "hosted.binding.revoke",
		Input: mustJSON(t, map[string]string{"endpoint": ref.String()}),
	})
	if err != nil {
		t.Fatalf("hosted.binding.revoke transport: %v", err)
	}
	if revokeResponse.Error != nil {
		t.Fatalf("hosted.binding.revoke: %v", revokeResponse.Error)
	}

	// The endpoint is genuinely retired in the store (the journal is untouched;
	// only the endpoint's active head changes).
	owner, err = n.Installation.Operator(ctx)
	if err != nil {
		t.Fatal(err)
	}
	page, err := n.Installation.Store.ListEndpointHeads(ctx, owner, "", 100)
	if err != nil {
		t.Fatal(err)
	}
	retired := false
	for _, head := range page.Heads {
		if head.Ref == ref {
			retired = head.Retired
		}
	}
	if !retired {
		t.Fatal("revoke must retire the endpoint in the registry")
	}

	// The truthful list then reflects the change: the revoked binding is no
	// longer an active hosted binding, so the active list is empty. (A retired
	// descriptor has no public read path, so the list is truthful for active
	// bindings; the retained journal preserves the history.)
	views = listBindings()
	if len(views) != 0 {
		t.Fatalf("the list must reflect the revoked binding as no longer active: %+v", views)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
