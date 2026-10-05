package fabricnode

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/events/durable"
	"github.com/pagnet-code/pagnet/fabric/identity"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/fabricnative"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
)

func TestNativeBindingUsesActualEncryptedProfileWithoutLaunching(t *testing.T) {
	ctx := t.Context()
	dir := filepath.Join(t.TempDir(), "registry")
	principal := fabric.Principal{Ref: "local:operator", Kind: "actor.human", Issuer: "local:os"}
	store, err := registry.Bootstrap(ctx, dir, principal)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	caller, err := fabric.NewAuthenticatedContext(principal, store.Namespace(), []byte("operator setup"))
	if err != nil {
		t.Fatal(err)
	}
	ref, err := fabric.NewEndpointRef(store.AuthorityIdentity().PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	binding := fabric.BindingSummary{ID: "native", Protocol: "local.native", Version: "1"}
	revision, err := store.Register(ctx, caller, fabric.RegistryUpdate{Descriptor: fabric.EndpointDescriptor{Ref: ref, Kind: "actor.agent", Name: "Maria", Description: "Sales", Bindings: []fabric.BindingSummary{binding}}})
	if err != nil {
		t.Fatal(err)
	}
	key := sha256.Sum256([]byte("operator private storage key"))
	protector, err := durable.NewAESGCM(durable.KeyReference{ID: "private-profile", Version: "1"}, key[:])
	if err != nil {
		t.Fatal(err)
	}
	profiles, err := fabricnative.NewProfileStore(ctx, store, caller, protector)
	if err != nil {
		t.Fatal(err)
	}
	private := t.TempDir()
	workspace := filepath.Join(private, "workspace")
	native := sessionworker.NativeSpec{Kind: "local", Runtime: domain.RuntimeFakePersistent, Binary: filepath.Join(private, "native"), MCPExecutable: filepath.Join(private, "pagnet"), Workspace: workspace, LocalAuthorityDirectory: dir, LocalFabricSocket: filepath.Join(private, "fabric.sock"), Env: []string{"PATH=/usr/bin:/bin", "HOME=" + workspace}}
	digest, err := hex.DecodeString(sessionworker.LocalNativeProfileFingerprint(native))
	if err != nil {
		t.Fatal(err)
	}
	worker := identity.WorkerBinding{WorkerID: "declared-slot", StateDirectoryID: "declared-state", OwnershipGeneration: "declared-generation", ActualRuntime: string(native.Runtime)}
	copy(worker.ProfileDigest[:], digest)
	profile := fabricnative.Profile{Native: native, Worker: worker, Directory: filepath.Join(private, "worker")}
	scope := registry.DescriptorBatchScope{Endpoint: ref, ExpectedEndpointRevision: revision, BindingID: binding.ID}
	if _, err = profiles.Put(ctx, scope, profile); err != nil {
		t.Fatal(err)
	}
	descriptor, err := store.GetEndpoint(ctx, ref, revision)
	if err != nil {
		t.Fatal(err)
	}
	// Selection must not call the adapter. An unconfigured adapter is deliberately
	// supplied: invocation would fail, while private profile selection is valid.
	adapter := &fabricnative.Adapter{}
	provider := &NativeBindingProvider{Profiles: profiles, Adapter: adapter}
	selected, fingerprint, err := provider.ResolveBinding(ctx, caller, descriptor, binding, nil)
	if err != nil || selected != adapter || fingerprint == ([32]byte{}) {
		t.Fatal("actual profile selection", err)
	}
	_, repeated, err := provider.ResolveBinding(ctx, caller, descriptor, binding, nil)
	if err != nil || repeated != fingerprint {
		t.Fatal("selection changed retained identity", err)
	}
	if _, err = os.Stat(profile.Directory); !os.IsNotExist(err) {
		t.Fatal("selection launched or provisioned worker", err)
	}
	if _, _, err = provider.ResolveBinding(ctx, fabric.ExecutionContext{}, descriptor, binding, nil); err == nil {
		t.Fatal("unauthenticated profile access")
	}
	stale := descriptor
	stale.Revision = "stale"
	if _, _, err = provider.ResolveBinding(ctx, caller, stale, binding, nil); err == nil {
		t.Fatal("stale profile selected")
	}
	other, _ := fabric.NewEndpointRef(store.AuthorityIdentity().PublicKey)
	otherOffer, _ := other.WithOfferID(store.AuthorityIdentity().PublicKey)
	if _, _, err = provider.ResolveBinding(ctx, caller, descriptor, binding, &fabric.OfferDescriptor{Ref: otherOffer, BindingID: binding.ID}); err == nil {
		t.Fatal("foreign offer selected")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "registry.sqlite"))
	if err != nil || bytes.Contains(raw, []byte(workspace)) {
		t.Fatal("private profile exposed in storage", err)
	}
}
