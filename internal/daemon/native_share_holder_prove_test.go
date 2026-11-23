//go:build linux || darwin

package daemon

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/e2ee"
	hostcrypto "github.com/pagnet-code/pagnet/internal/crypto"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

func nativeShareProveChallenge(t *testing.T, prepared transport.NativeShareBindingPreparedPayload) (transport.NativeShareBindingProvePayload, []byte) {
	t.Helper()
	request := transport.NativeShareBindingProvePayload{Version: 1, BindingID: prepared.Prepare.Binding.BindingID, CommandID: "30000000-0000-4000-8000-000000000001", ChallengeID: "30000000-0000-4000-8000-000000000002", BindingDigest: prepared.BindingDigest}
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		t.Fatal(err)
	}
	nativeShareSealChallenge(t, &request, prepared.HolderX25519, challenge)
	return request, challenge
}

func nativeShareSealChallenge(t *testing.T, request *transport.NativeShareBindingProvePayload, public string, challenge []byte) {
	t.Helper()
	key, err := hex.DecodeString(public)
	if err != nil {
		t.Fatal(err)
	}
	aad, err := request.ChallengeAAD()
	if err != nil {
		t.Fatal(err)
	}
	request.Challenge.Enc, request.Challenge.Ciphertext, err = e2ee.HPKEWrap(key, []byte(transport.NativeShareBindingChallengeInfo), aad, challenge)
	if err != nil {
		t.Fatal(err)
	}
}

func nativeShareProveFixture(t *testing.T) (*NativeShareHolderStore, *hostcrypto.HostIdentity, transport.NativeShareBindingPreparedPayload, transport.HostSessionPayload, transport.NativeShareBindingProvePayload, []byte) {
	t.Helper()
	store, identity, prepare, session := nativeShareStoreFixture(t)
	prepared, err := store.Prepare(prepare, "https://example.test", session)
	if err != nil {
		t.Fatal(err)
	}
	request, challenge := nativeShareProveChallenge(t, prepared)
	return store, identity, prepared, session, request, challenge
}

// Compare names, modes and content hashes, including lock files, without putting
// private fixture key material into test output. Access timestamps are irrelevant.
func nativeShareHolderSnapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	snapshot := map[string]string{}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		value := info.Mode().String()
		if info.Mode().IsRegular() {
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			digest := sha256.Sum256(raw)
			clear(raw)
			value += hex.EncodeToString(digest[:])
		}
		snapshot[relative] = value
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func TestNativeShareHolderProveRestartAndExactRetry(t *testing.T) {
	store, identity, prepared, session, request, challenge := nativeShareProveFixture(t)
	root := filepath.Join(store.registry.root, "closed-share-bindings")
	before := nativeShareHolderSnapshot(t, root)
	// No retained prepare input is supplied to Prove after restart.
	if err := store.registry.Close(); err != nil {
		t.Fatal(err)
	}
	registry, err := OpenNativeWorkerRegistry(filepath.Dir(store.registry.root))
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	restarted, err := NewNativeShareHolderStore(registry, identity)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := restarted.Prove(request, "https://example.test", session)
	if err != nil {
		t.Fatal(err)
	}
	if err := reply.Verify(request, challenge, identity.Ed25519Verifier()); err != nil {
		t.Fatal(err)
	}
	retry, err := restarted.Prove(request, "https://example.test", session)
	if err != nil || !reflect.DeepEqual(reply, retry) {
		t.Fatal("exact prove retry changed reply", err)
	}
	if !reflect.DeepEqual(before, nativeShareHolderSnapshot(t, root)) {
		t.Fatal("proof mutated persisted holder state")
	}
	// The binding-ID directory contains the immutable record directly.
	entries, err := os.ReadDir(nativeShareStorePath(restarted, prepared.Prepare))
	if err != nil || len(entries) != 2 {
		t.Fatal("unexpected holder layout", err)
	}
}

func TestNativeShareHolderProveRejectsSubstitutionWithoutMutation(t *testing.T) {
	for _, name := range []string{"binding", "digest", "challengeID", "commandID", "prepareCommand", "missingBinding", "missingCommand", "missingChallengeID", "ciphertext", "enc", "endpoint", "tenant", "account", "host", "admission", "runner", "runnerEpoch", "boot", "expired", "generation", "profile", "partial", "missingLock", "permissions", "recordSymlink"} {
		t.Run(name, func(t *testing.T) {
			store, _, prepared, session, request, challenge := nativeShareProveFixture(t)
			endpoint := "https://example.test"
			switch name {
			case "binding":
				request.BindingID = "20000000-0000-4000-8000-000000000001"
			case "digest":
				request.BindingDigest = strings.Repeat("ab", 32)
			case "challengeID":
				request.ChallengeID = "20000000-0000-4000-8000-000000000001"
			case "commandID":
				request.CommandID = "20000000-0000-4000-8000-000000000001"
			case "prepareCommand":
				request.CommandID = prepared.Prepare.CommandID
				nativeShareSealChallenge(t, &request, prepared.HolderX25519, challenge)
			case "missingBinding":
				request.BindingID = ""
			case "missingCommand":
				request.CommandID = ""
			case "missingChallengeID":
				request.ChallengeID = ""
			case "ciphertext":
				request.Challenge.Ciphertext[0] ^= 1
			case "enc":
				request.Challenge.Enc = nil
			case "endpoint":
				endpoint = "https://other.example.test"
			case "tenant":
				session.TenantID = "20000000-0000-4000-8000-000000000001"
			case "account":
				session.AccountID = "20000000-0000-4000-8000-000000000001"
			case "host":
				session.HostID = "20000000-0000-4000-8000-000000000001"
			case "admission":
				session.NativeAdmissionID = "20000000-0000-4000-8000-000000000001"
			case "runner":
				session.RunnerID = "20000000-0000-4000-8000-000000000001"
			case "runnerEpoch":
				session.RunnerEpoch = session.RunnerEpoch.Add(time.Nanosecond)
			case "boot":
				session.BootID = "changed-boot"
			case "expired":
				expiry, _ := time.Parse(time.RFC3339Nano, prepared.Prepare.Binding.ExpiresAt)
				store.now = func() time.Time { return expiry }
			case "generation", "profile":
				worker, err := store.registry.Lookup(string(prepared.Prepare.Binding.InstanceID))
				if err != nil {
					t.Fatal(err)
				}
				if name == "generation" {
					worker.Scope.Generation = "changed-generation"
					worker.Dir = store.registry.Dir(worker.Scope)
				} else {
					worker.Spec.Workspace = "/changed-profile"
					worker.ProfileFingerprint = sessionworker.NativeProfileFingerprint(worker.Spec)
				}
				raw, err := json.Marshal(worker)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := store.registry.db.Exec(`UPDATE native_workers SET payload=? WHERE instance_id=?`, raw, worker.Scope.InstanceID); err != nil {
					t.Fatal(err)
				}
			case "partial":
				if err := os.WriteFile(filepath.Join(nativeShareStorePath(store, prepared.Prepare), "holder.pending"), []byte("partial"), 0600); err != nil {
					t.Fatal(err)
				}
			case "permissions":
				if err := os.Chmod(filepath.Join(nativeShareStorePath(store, prepared.Prepare), "holder.json"), 0640); err != nil {
					t.Fatal(err)
				}
			case "recordSymlink":
				target := filepath.Join(nativeShareStorePath(store, prepared.Prepare), "holder.json")
				outside := filepath.Join(t.TempDir(), "outside")
				if err := os.Rename(target, outside); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, target); err != nil {
					t.Fatal(err)
				}
			case "missingLock":
				if err := os.Remove(filepath.Join(nativeShareStorePath(store, prepared.Prepare), "holder.lock")); err != nil {
					t.Fatal(err)
				}
			}
			root := filepath.Join(store.registry.root, "closed-share-bindings")
			before := nativeShareHolderSnapshot(t, root)
			reply, err := store.Prove(request, endpoint, session)
			if err == nil || !reflect.DeepEqual(reply, transport.NativeShareBindingProvedPayload{}) {
				t.Fatal("invalid proof attempt returned evidence")
			}
			if !reflect.DeepEqual(before, nativeShareHolderSnapshot(t, root)) {
				t.Fatal("failed proof mutated holder state")
			}
		})
	}
}

func TestNativeShareHolderProveWrongHolderAndInstance(t *testing.T) {
	store, _, first, session, firstRequest, challenge := nativeShareProveFixture(t)
	_, _, worker := nativeShareValidationFixture()
	secondPrepare := first.Prepare
	secondPrepare.CommandID = "20000000-0000-4000-8000-000000000001"
	secondPrepare.Binding.BindingID = "20000000-0000-4000-8000-000000000002"
	secondPrepare.Binding.InstanceID = "20000000-0000-4000-8000-000000000003"
	secondPrepare.Binding.ContextID = "20000000-0000-4000-8000-000000000004"
	worker.Scope.InstanceID = string(secondPrepare.Binding.InstanceID)
	if _, err := store.registry.Reserve(worker.Scope, worker.Spec, "original", ""); err != nil {
		t.Fatal(err)
	}
	second, err := store.Prepare(secondPrepare, "https://example.test", session)
	if err != nil {
		t.Fatal(err)
	}
	request := firstRequest
	request.BindingID = second.Prepare.Binding.BindingID
	request.BindingDigest = second.BindingDigest
	// The metadata targets the second binding but the challenge is sealed to the
	// first holder. Correct metadata/AAD alone cannot prove possession of its key.
	nativeShareSealChallenge(t, &request, first.HolderX25519, challenge)
	root := filepath.Join(store.registry.root, "closed-share-bindings")
	before := nativeShareHolderSnapshot(t, root)
	if reply, err := store.Prove(request, "https://example.test", session); err == nil || reply.BindingID != "" {
		t.Fatal("accepted challenge encrypted to another instance's holder")
	}
	// Copying a valid signed holder record into another binding's slot also fails.
	firstPath := filepath.Join(nativeShareStorePath(store, first.Prepare), "holder.json")
	secondPath := filepath.Join(nativeShareStorePath(store, second.Prepare), "holder.json")
	raw, err := os.ReadFile(firstPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secondPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	clear(raw)
	substituted := nativeShareHolderSnapshot(t, root)
	if reply, err := store.Prove(request, "https://example.test", session); err == nil || reply.BindingID != "" {
		t.Fatal("accepted persisted transcript in another binding's slot")
	}
	if reflect.DeepEqual(before, substituted) || !reflect.DeepEqual(substituted, nativeShareHolderSnapshot(t, root)) {
		t.Fatal("failed proof unexpectedly mutated substituted records")
	}
}

func TestNativeShareHolderProveRecoveryWhileWaiting(t *testing.T) {
	store, _, prepared, session, request, _ := nativeShareProveFixture(t)
	binding, err := nativeShareHolderDirectory(nativeShareStorePath(store, prepared.Prepare))
	if err != nil {
		t.Fatal(err)
	}
	defer binding.Close()
	lock, err := nativeShareHolderLockMode(binding, false)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	writer, err := OpenNativeWorkerRegistry(filepath.Dir(store.registry.root))
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	done := make(chan error, 1)
	go func() {
		reply, err := store.Prove(request, "https://example.test", session)
		if err == nil || reply.BindingID != "" {
			done <- nil
		} else {
			done <- err
		}
	}()
	// The holder lock prevents the in-flight proof from passing its authority
	// transaction until this independent registry handle commits the recovery fence.
	if _, err := writer.db.Exec(`INSERT INTO native_worker_recoveries(recovery_id,instance_id,original_generation,prepare_boot_identity,phase) VALUES(?,?,?,?,?)`, "20000000-0000-4000-8000-000000000001", string(prepared.Prepare.Binding.InstanceID), prepared.Prepare.Binding.NativeGeneration, "test-original-boot", "prepared"); err != nil {
		t.Fatal(err)
	}
	before := nativeShareHolderSnapshot(t, filepath.Join(store.registry.root, "closed-share-bindings"))
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("returned proof despite committed recovery fence")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("proof did not resume after lock released")
	}
	if !reflect.DeepEqual(before, nativeShareHolderSnapshot(t, filepath.Join(store.registry.root, "closed-share-bindings"))) {
		t.Fatal("recovery-fenced proof mutated holder state")
	}
}

func TestNativeShareHolderProveMissingHolderNoCreation(t *testing.T) {
	store, _, prepare, session := nativeShareStoreFixture(t)
	request := transport.NativeShareBindingProvePayload{Version: 1, BindingID: prepare.Binding.BindingID, CommandID: "30000000-0000-4000-8000-000000000001", ChallengeID: "30000000-0000-4000-8000-000000000002", BindingDigest: strings.Repeat("ab", 32), Challenge: transport.CryptoHPKEWrap{Enc: make([]byte, 32), Ciphertext: make([]byte, 48)}}
	namespace := filepath.Join(store.registry.root, "closed-share-bindings")
	if _, err := os.Stat(namespace); !os.IsNotExist(err) {
		t.Fatal("unexpected preexisting holder namespace", err)
	}
	if reply, err := store.Prove(request, "https://example.test", session); err == nil || reply.BindingID != "" {
		t.Fatal("returned proof for missing holder")
	}
	if _, err := os.Stat(namespace); !os.IsNotExist(err) {
		t.Fatal("proof created missing holder namespace", err)
	}
}
