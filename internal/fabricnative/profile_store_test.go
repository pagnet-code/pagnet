package fabricnative

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/events/durable"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
)

func TestPrivateNativeProfileActualRegistryRestartRenewalAndCAS(t *testing.T) {
	c, original, directory := checkpointFixture(t, registry.DefaultOptions())
	key, err := durable.NewAESGCM(durable.KeyReference{ID: "explicit-private-profile", Version: "1"}, bytes.Repeat([]byte{31}, 32))
	if err != nil {
		t.Fatal(err)
	}
	profiles, err := NewProfileStore(t.Context(), c.store, c.owner, key)
	if err != nil {
		t.Fatal(err)
	}
	private := t.TempDir()
	workspace := filepath.Join(private, "workspace")
	native := sessionworker.NativeSpec{Kind: "local", Runtime: domain.RuntimeFakePersistent, Binary: filepath.Join(private, "bin", "native"), MCPExecutable: filepath.Join(private, "bin", "pagnet"), Workspace: workspace, LocalAuthorityDirectory: directory, LocalFabricSocket: filepath.Join(private, "fabric.sock"), Env: []string{"PATH=/usr/bin:/bin", "HOME=" + workspace, "CUSTOM_PROFILE=private-profile-marker"}, CredentialEnvKeys: []string{"CUSTOM_SECRET"}}
	worker := original.OriginalBinding.Worker
	worker.ActualRuntime = string(native.Runtime)
	digest, _ := hex.DecodeString(sessionworker.LocalNativeProfileFingerprint(native))
	copy(worker.ProfileDigest[:], digest)
	profile := Profile{Native: native, Worker: worker, Directory: filepath.Join(private, "workers", "original")}
	scope := registry.DescriptorBatchScope{Endpoint: original.OriginalBinding.Scope.Endpoint, ExpectedEndpointRevision: original.OriginalBinding.Scope.DescriptorRevision, BindingID: "native"}
	if generation, e := profiles.Put(t.Context(), scope, profile); e != nil || generation != 1 {
		t.Fatal("private profile commit", generation, e)
	}
	if generation, e := profiles.Put(t.Context(), scope, profile); e != nil || generation != 1 {
		t.Fatal("exact installation retry lost retained profile", generation, e)
	}
	page, err := c.store.ReadBindingProjection(t.Context(), c.owner, scope, "", 1)
	if err != nil || bytes.Contains(page.PrivateConfig, []byte("private-profile-marker")) || len(page.Rows) != 0 {
		t.Fatal("private config was not encrypted or published offers", err)
	}
	unsafe := profile
	unsafe.Native.Env = append(append([]string(nil), native.Env...), "CUSTOM_SECRET=must-never-persist")
	scope.ExpectedProjectionRevision = 1
	if _, e := profiles.Put(t.Context(), scope, unsafe); e == nil {
		t.Fatal("provider credential persisted")
	}
	endpoint, err := c.store.GetEndpoint(t.Context(), scope.Endpoint, scope.ExpectedEndpointRevision)
	if err != nil {
		t.Fatal(err)
	}
	endpoint.Name = "Renamed Maria"
	previous := endpoint.Revision
	endpoint.Revision = ""
	updated, err := c.store.Update(t.Context(), c.owner, fabric.RegistryUpdate{Descriptor: endpoint, ExpectedRevision: previous})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, e := profiles.Get(t.Context(), scope); e == nil {
		t.Fatal("stale descriptor authorized profile access")
	}
	scope.ExpectedEndpointRevision = updated
	if err = c.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := registry.Open(t.Context(), directory)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	profiles, err = NewProfileStore(t.Context(), reopened, c.owner, key)
	if err != nil {
		t.Fatal(err)
	}
	loaded, generation, err := profiles.Get(t.Context(), scope)
	if err != nil || generation != 1 || !equalNativeValue(loaded, profile) || !reflect.DeepEqual(loaded.Native.Env, profile.Native.Env) {
		t.Fatal("restart/rename changed original private profile", generation, err)
	}
	wrong, _ := durable.NewAESGCM(durable.KeyReference{ID: "explicit-private-profile", Version: "1"}, bytes.Repeat([]byte{32}, 32))
	untrusted, _ := NewProfileStore(t.Context(), reopened, c.owner, wrong)
	if _, _, e := untrusted.Get(t.Context(), scope); e == nil {
		t.Fatal("wrong key accepted")
	}
	for _, name := range []string{"registry.sqlite", "registry.sqlite-journal"} {
		raw, readErr := os.ReadFile(filepath.Join(directory, name))
		if readErr != nil && !(name == "registry.sqlite-journal" && os.IsNotExist(readErr)) {
			t.Fatal(readErr)
		}
		if bytes.Contains(raw, []byte("must-never-persist")) {
			t.Fatal("secret appeared on disk")
		}
	}
}
