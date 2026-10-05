//go:build linux || darwin

package fabricnode

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/fabric/localinstallation"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

func TestExtensionInfrastructureExplicitInterruptedSetupAndRetainedRestart(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	private := t.TempDir()
	if e := os.Chmod(private, 0700); e != nil {
		t.Fatal(e)
	}
	dir := filepath.Join(private, "root")
	i, e := localinstallation.Bootstrap(ctx, dir, localinstallation.Options{Settings: localinstallation.DefaultSettings(filepath.Join(private, "fabric.sock"))})
	if e != nil {
		t.Fatal(e)
	}
	defer func() { i.Close() }()
	if state, e := openExtensionInfrastructure(ctx, i); e != nil || state != nil {
		t.Fatal("missing-all should disable without setup", e)
	}
	if _, e = os.Lstat(filepath.Join(dir, "continuations")); !os.IsNotExist(e) {
		t.Fatal("startup created store")
	}
	s := DefaultExtensionSettings()
	owner, e := i.Operator(ctx)
	if e != nil {
		t.Fatal(e)
	}
	root := i.Store.AuthorityIdentity()
	// A genuine signed preparing phase models a crash before SQLite setup.
	value, e := sealExtensionSetup(i, extensionConfiguration{1, "preparing", root, i.Keys.Reference(), filepath.Join(dir, "continuations"), s})
	if e != nil {
		t.Fatal(e)
	}
	e = i.Store.WithNativeAuthority(ctx, owner, registry.AuthorityScope{MaxOperations: 1}, func(tx *registry.AuthorityTx) error {
		_, x := tx.CAS(extensionConfigurationKey, 0, value, false)
		return x
	})
	if e != nil {
		t.Fatal(e)
	}
	if e = initializeExtensionProfiles(ctx, i, s.MaxProfiles); e != nil {
		t.Fatal(e)
	}
	if _, e = openExtensionInfrastructure(ctx, i); e == nil {
		t.Fatal("startup repaired interrupted setup")
	}
	changed := s
	changed.MaxProfiles++
	if e = InitializeExtensionInfrastructure(ctx, i, changed); e == nil {
		t.Fatal("changed preparing setup replaced original pin")
	}
	if e = InitializeExtensionInfrastructure(ctx, i, s); e != nil {
		t.Fatal("explicit retry failed", e)
	}
	r, e := extensionSetupRecord(ctx, i, extensionConfigurationKey)
	if e != nil || r.Revision != 2 {
		t.Fatal("missing signed ready pin", e)
	}
	if e = InitializeExtensionInfrastructure(ctx, i, s); e != nil {
		t.Fatal("exact setup retry", e)
	}
	r2, _ := extensionSetupRecord(ctx, i, extensionConfigurationKey)
	if r2.Sequence != r.Sequence {
		t.Fatal("exact retry mutated setup")
	}
	state, e := openExtensionInfrastructure(ctx, i)
	if e != nil || state == nil {
		t.Fatal("ready startup", e)
	}
	if e = state.Continuations.Close(); e != nil {
		t.Fatal(e)
	}
	state.Registry.Close()
	if e = i.Close(); e != nil {
		t.Fatal(e)
	}
	i, e = localinstallation.Load(ctx, dir, registry.DefaultOptions())
	if e != nil {
		t.Fatal(e)
	}
	state, e = openExtensionInfrastructure(ctx, i)
	if e != nil || state == nil {
		t.Fatal("same-key retained startup", e)
	}
	if i.Store.AuthorityIdentity().StoreID != root.StoreID {
		t.Fatal("startup replaced root")
	}
	state.Continuations.Close()
	state.Registry.Close()
	if e = os.Remove(filepath.Join(dir, "continuations", "continuations.sqlite")); e != nil {
		t.Fatal(e)
	}
	if _, e = openExtensionInfrastructure(ctx, i); e == nil {
		t.Fatal("ready missing SQLite silently repaired")
	}
	if e = InitializeExtensionInfrastructure(ctx, i, s); e == nil {
		t.Fatal("ready missing SQLite regenerated on explicit retry")
	}
}

func TestExtensionInfrastructurePartialPurposeDeniesStartup(t *testing.T) {
	ctx := t.Context()
	private := t.TempDir()
	if e := os.Chmod(private, 0700); e != nil {
		t.Fatal(e)
	}
	i, e := localinstallation.Bootstrap(ctx, filepath.Join(private, "root"), localinstallation.Options{Settings: localinstallation.DefaultSettings(filepath.Join(private, "fabric.sock"))})
	if e != nil {
		t.Fatal(e)
	}
	defer i.Close()
	if e = initializeExtensionProfiles(ctx, i, 2); e != nil {
		t.Fatal(e)
	}
	if _, e = openExtensionInfrastructure(ctx, i); e == nil {
		t.Fatal("partial profiles treated as disabled")
	}
	if e = InitializeExtensionInfrastructure(ctx, i, DefaultExtensionSettings()); e == nil {
		t.Fatal("orphan purpose silently attested by fresh setup")
	}
}
