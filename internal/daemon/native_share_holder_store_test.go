//go:build linux || darwin

package daemon

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	hostcrypto "github.com/pagnet-code/pagnet/internal/crypto"
	"github.com/pagnet-code/pagnet/transport"
)

func nativeShareStoreFixture(t *testing.T) (*NativeShareHolderStore, *hostcrypto.HostIdentity, transport.NativeShareBindingPreparePayload, transport.HostSessionPayload) {
	t.Helper()
	request, session, worker := nativeShareValidationFixture()
	request.Binding.ExpiresAt = time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
	stateDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(stateDir, 0700); err != nil {
		t.Fatal(err)
	}
	registry, err := OpenNativeWorkerRegistry(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = registry.Close() })
	if _, err := registry.Reserve(worker.Scope, worker.Spec, "original", ""); err != nil {
		t.Fatal(err)
	}
	identity, err := hostcrypto.NewHostIdentity()
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewNativeShareHolderStore(registry, identity)
	if err != nil {
		t.Fatal(err)
	}
	return store, identity, request, session
}

func nativeShareStorePath(store *NativeShareHolderStore, request transport.NativeShareBindingPreparePayload) string {
	return filepath.Join(store.registry.root, "closed-share-bindings", string(request.Binding.BindingID))
}

func TestNativeShareHolderStoreRestartRetryAndIsolation(t *testing.T) {
	store, identity, request, session := nativeShareStoreFixture(t)
	endpoint := "https://example.test"
	prepared, err := store.Prepare(request, endpoint, session)
	if err != nil {
		t.Fatal(err)
	}
	if err := prepared.Verify(request, prepared.Subject, identity.Ed25519Verifier()); err != nil {
		t.Fatal(err)
	}
	original, _ := json.Marshal(prepared)
	registryRoot := store.registry.root
	if err := store.registry.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenNativeWorkerRegistry(filepath.Dir(registryRoot))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	restarted, err := NewNativeShareHolderStore(reopened, identity)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := restarted.Prepare(request, endpoint, session)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := json.Marshal(retry)
	if !bytes.Equal(original, again) {
		t.Fatal("restart retry changed holder or signed evidence")
	}
	// Two immutable native workers on the same host receive distinct holders.
	_, _, worker := nativeShareValidationFixture()
	second := request
	second.CommandID = "20000000-0000-4000-8000-000000000001"
	second.Binding.BindingID = "20000000-0000-4000-8000-000000000002"
	second.Binding.InstanceID = "20000000-0000-4000-8000-000000000003"
	second.Binding.ContextID = "20000000-0000-4000-8000-000000000004"
	worker.Scope.InstanceID = string(second.Binding.InstanceID)
	if _, err := reopened.Reserve(worker.Scope, worker.Spec, "original", ""); err != nil {
		t.Fatal(err)
	}
	other, err := restarted.Prepare(second, endpoint, session)
	if err != nil {
		t.Fatal(err)
	}
	if other.HolderID == prepared.HolderID || other.HolderX25519 == prepared.HolderX25519 || other.BindingDigest == prepared.BindingDigest {
		t.Fatal("two instances shared a holder")
	}
	if other.Verify(request, prepared.Subject, identity.Ed25519Verifier()) == nil {
		t.Fatal("cross-instance receipt replay accepted")
	}
	for _, req := range []transport.NativeShareBindingPreparePayload{request, second} {
		info, err := os.Stat(filepath.Join(nativeShareStorePath(restarted, req), "holder.json"))
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("holder file is not private", err)
		}
	}
}

func TestNativeShareHolderStoreConflictsAndExpiry(t *testing.T) {
	store, _, request, session := nativeShareStoreFixture(t)
	endpoint := "https://example.test"
	prepared, err := store.Prepare(request, endpoint, session)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name   string
		mutate func(*transport.NativeShareBindingPreparePayload, *transport.HostSessionPayload)
	}{
		{"command", func(p *transport.NativeShareBindingPreparePayload, _ *transport.HostSessionPayload) {
			p.CommandID = "20000000-0000-4000-8000-000000000001"
		}},
		{"principal", func(p *transport.NativeShareBindingPreparePayload, _ *transport.HostSessionPayload) {
			p.Binding.PrincipalID = "20000000-0000-4000-8000-000000000001"
		}},
		{"context", func(p *transport.NativeShareBindingPreparePayload, _ *transport.HostSessionPayload) {
			p.Binding.ContextID = "20000000-0000-4000-8000-000000000001"
		}},
		{"nativeGeneration", func(p *transport.NativeShareBindingPreparePayload, _ *transport.HostSessionPayload) {
			p.Binding.NativeGeneration = "changed-generation"
		}},
		{"network", func(p *transport.NativeShareBindingPreparePayload, _ *transport.HostSessionPayload) {
			p.Binding.NetworkID = "20000000-0000-4000-8000-000000000001"
		}},
		{"grant", func(p *transport.NativeShareBindingPreparePayload, _ *transport.HostSessionPayload) {
			p.Binding.GrantGeneration++
		}},
		{"admission", func(_ *transport.NativeShareBindingPreparePayload, s *transport.HostSessionPayload) {
			s.NativeAdmissionID = "20000000-0000-4000-8000-000000000001"
		}},
		{"runner", func(_ *transport.NativeShareBindingPreparePayload, s *transport.HostSessionPayload) {
			s.RunnerID = "20000000-0000-4000-8000-000000000001"
		}},
		{"runnerEpoch", func(_ *transport.NativeShareBindingPreparePayload, s *transport.HostSessionPayload) {
			s.RunnerEpoch = s.RunnerEpoch.Add(time.Nanosecond)
		}},
		{"boot", func(_ *transport.NativeShareBindingPreparePayload, s *transport.HostSessionPayload) {
			s.BootID = "another-boot"
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			changed, changedSession := request, session
			tt.mutate(&changed, &changedSession)
			evidence, err := store.Prepare(changed, endpoint, changedSession)
			if err == nil || evidence.HolderID != "" {
				t.Fatal("returned evidence for conflicting immutable identity")
			}
		})
	}
	// A binding ID cannot move to a second independently valid worker.
	_, _, worker := nativeShareValidationFixture()
	moved := request
	moved.Binding.InstanceID = "20000000-0000-4000-8000-000000000002"
	worker.Scope.InstanceID = string(moved.Binding.InstanceID)
	if _, err := store.registry.Reserve(worker.Scope, worker.Spec, "original", ""); err != nil {
		t.Fatal(err)
	}
	if evidence, err := store.Prepare(moved, endpoint, session); err == nil || evidence.HolderID != "" {
		t.Fatal("binding ID moved to another worker")
	}
	// Also reject a valid but replaced local profile rather than trusting input.
	worker.Scope.InstanceID = string(request.Binding.InstanceID)
	worker.Spec.Workspace = "/changed-profile"
	worker.ProfileFingerprint = "not-the-derived-fingerprint"
	raw, err := json.Marshal(worker)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.registry.db.Exec(`UPDATE native_workers SET payload=? WHERE instance_id=?`, raw, worker.Scope.InstanceID); err != nil {
		t.Fatal(err)
	}
	if evidence, err := store.Prepare(request, endpoint, session); err == nil || evidence.HolderID != "" {
		t.Fatal("accepted corrupt registry profile")
	}
	// Restore authority and ensure expiry fences even an exact cached retry.
	_, _, originalWorker := nativeShareValidationFixture()
	originalWorker.Dir = store.registry.Dir(originalWorker.Scope)
	originalWorker.ProfileFingerprint = prepared.Subject.ProfileFingerprint
	originalWorker.Profile = "original"
	raw, _ = json.Marshal(originalWorker)
	if _, err := store.registry.db.Exec(`UPDATE native_workers SET payload=? WHERE instance_id=?`, raw, originalWorker.Scope.InstanceID); err != nil {
		t.Fatal(err)
	}
	expiry, _ := time.Parse(time.RFC3339Nano, request.Binding.ExpiresAt)
	store.now = func() time.Time { return expiry }
	if evidence, err := store.Prepare(request, endpoint, session); err == nil || evidence.HolderID != "" {
		t.Fatal("returned expired evidence")
	}
}

func TestNativeShareHolderStoreUnsafeOrPartialState(t *testing.T) {
	for _, name := range []string{"pending", "partial", "unknownField", "wrongKey", "targetSymlink", "targetPermissions", "targetHardlink", "parentSymlink", "parentPermissions", "rootPermissions", "lockSymlink"} {
		t.Run(name, func(t *testing.T) {
			store, _, request, session := nativeShareStoreFixture(t)
			if _, err := store.Prepare(request, "https://example.test", session); err != nil {
				t.Fatal(err)
			}
			directory := nativeShareStorePath(store, request)
			target := filepath.Join(directory, "holder.json")
			bindingDir := directory
			switch name {
			case "pending":
				if err := os.Remove(target); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(directory, "holder.pending"), []byte("partial"), 0600); err != nil {
					t.Fatal(err)
				}
			case "partial":
				if err := os.WriteFile(target, []byte(`{"version":`), 0600); err != nil {
					t.Fatal(err)
				}
			case "unknownField":
				if err := os.WriteFile(target, []byte(`{"version":1,"unexpected":true}`), 0600); err != nil {
					t.Fatal(err)
				}
			case "wrongKey":
				raw, err := os.ReadFile(target)
				if err != nil {
					t.Fatal(err)
				}
				var record nativeShareHolderRecord
				if err := json.Unmarshal(raw, &record); err != nil {
					t.Fatal(err)
				}
				clear(raw)
				record.PrivateKey[0] ^= 8
				raw, err = json.Marshal(record)
				clear(record.PrivateKey)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(target, raw, 0600); err != nil {
					t.Fatal(err)
				}
				clear(raw)
			case "targetSymlink":
				if err := os.Rename(target, target+".saved"); err != nil {
					t.Fatal(err)
				}
				// Keep no unexpected sibling: target must itself be rejected as a symlink.
				saved := filepath.Join(t.TempDir(), "saved")
				if err := os.Rename(target+".saved", saved); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(saved, target); err != nil {
					t.Fatal(err)
				}
			case "targetPermissions":
				if err := os.Chmod(target, 0640); err != nil {
					t.Fatal(err)
				}
			case "targetHardlink":
				if err := os.Link(target, filepath.Join(t.TempDir(), "linked")); err != nil {
					t.Fatal(err)
				}
			case "parentSymlink":
				saved := directory + ".saved"
				if err := os.Rename(directory, saved); err != nil {
					t.Fatal(err)
				}
				// Put the actual context outside its parent so allowed-name checks pass.
				outside := filepath.Join(t.TempDir(), "context")
				if err := os.Rename(saved, outside); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, directory); err != nil {
					t.Fatal(err)
				}
			case "parentPermissions":
				if err := os.Chmod(filepath.Dir(directory), 0755); err != nil {
					t.Fatal(err)
				}
			case "rootPermissions":
				if err := os.Chmod(store.registry.root, 0755); err != nil {
					t.Fatal(err)
				}
			case "lockSymlink":
				lock := filepath.Join(bindingDir, "holder.lock")
				if err := os.Remove(lock); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(t.TempDir(), "outside"), lock); err != nil {
					t.Fatal(err)
				}
			}
			evidence, err := store.Prepare(request, "https://example.test", session)
			if err == nil || evidence.HolderID != "" {
				t.Fatal("unsafe or interrupted state exposed evidence")
			}
		})
	}
}

func TestNativeShareHolderStoreConcurrentRetry(t *testing.T) {
	store, identity, request, session := nativeShareStoreFixture(t)
	// A second manager has independent memory but shares the durable binding lock.
	secondRegistry, err := OpenNativeWorkerRegistry(filepath.Dir(store.registry.root))
	if err != nil {
		t.Fatal(err)
	}
	defer secondRegistry.Close()
	second, err := NewNativeShareHolderStore(secondRegistry, identity)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	replies := make(chan transport.NativeShareBindingPreparedPayload, 2)
	failures := make(chan error, 2)
	for _, manager := range []*NativeShareHolderStore{store, second} {
		wg.Add(1)
		go func(s *NativeShareHolderStore) {
			defer wg.Done()
			reply, err := s.Prepare(request, "https://example.test", session)
			if err != nil {
				failures <- err
				return
			}
			replies <- reply
		}(manager)
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	first, _ := json.Marshal(<-replies)
	last, _ := json.Marshal(<-replies)
	if !bytes.Equal(first, last) {
		t.Fatal("concurrent exact retries created different holders")
	}
}

func TestNativeShareHolderStoreRecoveryWhileWaiting(t *testing.T) {
	store, _, request, session := nativeShareStoreFixture(t)
	// Precreate only private namespace/lock directories; no holder exists yet.
	bindingPath := nativeShareStorePath(store, request)
	if err := os.MkdirAll(bindingPath, 0700); err != nil {
		t.Fatal(err)
	}
	binding, err := nativeShareHolderDirectory(bindingPath)
	if err != nil {
		t.Fatal(err)
	}
	defer binding.Close()
	lock, err := nativeShareHolderLock(binding)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	writer, err := OpenNativeWorkerRegistry(filepath.Dir(store.registry.root))
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	reachedLock := make(chan struct{})
	calls := 0
	store.now = func() time.Time {
		calls++
		if calls == 2 {
			close(reachedLock)
		}
		return time.Now()
	}
	type result struct {
		evidence transport.NativeShareBindingPreparedPayload
		err      error
	}
	done := make(chan result, 1)
	go func() {
		evidence, err := store.Prepare(request, "https://example.test", session)
		done <- result{evidence, err}
	}()
	select {
	case <-reachedLock:
	case <-time.After(5 * time.Second):
		t.Fatal("prepare did not reach holder lock")
	}
	// A permanent recovery fence is committed through an independent handle after
	// the initial authority reads, while preparation cannot pass the binding lock.
	if _, err := writer.db.Exec(`INSERT INTO native_worker_recoveries(recovery_id,instance_id,original_generation,prepare_boot_identity,phase) VALUES(?,?,?,?,?)`, "20000000-0000-4000-8000-000000000001", string(request.Binding.InstanceID), request.Binding.NativeGeneration, "test-original-boot", "prepared"); err != nil {
		t.Fatal(err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-done:
		if result.err == nil || result.evidence.HolderID != "" {
			t.Fatal("returned evidence after a recovery fence committed while waiting")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("prepare did not resume after holder lock released")
	}
	if _, err := os.Stat(filepath.Join(nativeShareStorePath(store, request), "holder.json")); !os.IsNotExist(err) {
		t.Fatal("created a holder after recovery fence", err)
	}
}
