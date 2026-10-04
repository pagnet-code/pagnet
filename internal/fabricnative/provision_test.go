package fabricnative

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/identity"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
)

func TestExplicitInitialProvisionPreservesPartialRowsAndNeverLaunches(t *testing.T) {
	c, original, rootDir := checkpointFixture(t, registry.DefaultOptions())
	profiles, err := NewProfileStore(t.Context(), c.store, c.owner, c.protector)
	if err != nil {
		t.Fatal(err)
	}
	private := t.TempDir()
	workspace := filepath.Join(private, "workspace")
	native := sessionworker.NativeSpec{Kind: "local", Runtime: domain.RuntimeFakePersistent, Binary: filepath.Join(private, "bin", "native"), MCPExecutable: filepath.Join(private, "bin", "pagnet"), Workspace: workspace, LocalAuthorityDirectory: rootDir, LocalFabricSocket: filepath.Join(private, "fabric.sock"), Env: []string{"PATH=/usr/bin:/bin", "HOME=" + workspace}}
	worker := original.OriginalBinding.Worker
	worker.ActualRuntime = string(native.Runtime)
	digest, _ := hex.DecodeString(sessionworker.LocalNativeProfileFingerprint(native))
	copy(worker.ProfileDigest[:], digest)
	profile := Profile{Native: native, Worker: worker, Directory: filepath.Join(private, "workers", "new")}
	ref, err := fabric.NewEndpointRef(c.root.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	revision, err := c.store.Register(t.Context(), c.owner, fabric.RegistryUpdate{Descriptor: fabric.EndpointDescriptor{Ref: ref, Name: "Maria", Description: "Sales and customer support", Kind: "actor.agent", Bindings: []fabric.BindingSummary{{ID: "native", Protocol: "local.native", Version: "1"}}}})
	if err != nil {
		t.Fatal(err)
	}
	scope := registry.DescriptorBatchScope{Endpoint: ref, ExpectedEndpointRevision: revision, BindingID: "native"}
	if _, err = profiles.Put(t.Context(), scope, profile); err != nil {
		t.Fatal(err)
	}
	selected := identity.Scope{Endpoint: ref, DescriptorRevision: revision, BindingID: "native"}
	initial, err := c.authority.AcquireController(t.Context(), c.owner, selected, 0, "original-provision", "original-controller")
	if err != nil {
		t.Fatal(err)
	}
	controller, binding, err := profiles.ProvisionInitialControl(t.Context(), c.authority, scope)
	if err != nil || controller.Proof.Revision != initial.Proof.Revision || binding.Worker != worker {
		t.Fatal("partial provisioning replaced original facts", err)
	}
	again, bound, err := profiles.ProvisionInitialControl(t.Context(), c.authority, scope)
	if err != nil || again.Proof.Revision != controller.Proof.Revision || bound.Proof.Revision != binding.Proof.Revision {
		t.Fatal("retry reminted physical slot", err)
	}
	if _, _, err = c.authority.CurrentNativeState(t.Context(), c.owner, selected); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(profile.Directory); !os.IsNotExist(err) {
		t.Fatal("provision created a worker or bootstrap", err)
	}
}
