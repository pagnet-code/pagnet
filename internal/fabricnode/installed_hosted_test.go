//go:build linux || darwin

package fabricnode

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/fabric/localinstallation"
	"github.com/pagnet-code/pagnet/internal/fabricauth"
	"github.com/pagnet-code/pagnet/internal/fabrichost"
)

// newHostedProductInstallation bootstraps a fresh local installation (no
// retained workers) and opens the node with an explicit hosted config, so the
// installed hosted product is composed over a real, empty trust boundary.
func newHostedProductInstallation(t *testing.T, ctx context.Context) (dir string, n *InstalledNode) {
	t.Helper()
	parent := t.TempDir()
	socketDir := filepath.Join(parent, "run")
	if err := os.Mkdir(socketDir, 0o700); err != nil {
		t.Fatal(err)
	}
	dir = filepath.Join(parent, "authority")
	socket := filepath.Join(socketDir, "node.sock")
	installed, err := localinstallation.Bootstrap(ctx, dir, localinstallation.Options{Settings: localinstallation.DefaultSettings(socket)})
	if err != nil {
		t.Fatal(err)
	}
	if err := installed.Close(); err != nil {
		t.Fatal(err)
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	n, err = OpenInstalled(ctx, InstalledConfig{Directory: dir, Binary: binary, Hosted: &InstalledHostedConfig{}})
	if err != nil {
		t.Fatal(err)
	}
	return dir, n
}

// TestInstalledHostedDeferredHoldersFailClosed proves the installed hosted
// product's deferred references are fail-closed until the daemon exists and
// cmd/pagnet completes the wiring: before wiring, Wired is false and the
// hosted-socket validator / facts / resolver all refuse with an honest error
// (never a silent no-op, never a fabricated principal).
func TestInstalledHostedDeferredHoldersFailClosed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, n := newHostedProductInstallation(t, ctx)
	defer func() { _ = n.Close() }()
	h := n.Hosted
	if h == nil {
		t.Fatal("the hosted product was not composed")
	}
	if h.Wired() {
		t.Fatal("the product reports wired before the daemon wiring")
	}
	if _, err := h.HostedValidator()(ctx, fabricauth.HostedPeer{}); err == nil {
		t.Fatal("the unwired hosted validator must refuse, not fabricate a principal")
	}
	if _, err := h.HostedFacts()(ctx, fabricauth.HostedPeer{}); err == nil {
		t.Fatal("the unwired hosted facts must refuse")
	}
	if _, err := h.ResolveHosted()(ctx, fabrichost.HostedSelector{}); err == nil {
		t.Fatal("the unwired hosted resolver must refuse")
	}
}
