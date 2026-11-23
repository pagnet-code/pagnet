//go:build linux || darwin

package daemon

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	hostcrypto "github.com/pagnet-code/pagnet/internal/crypto"
	"github.com/pagnet-code/pagnet/transport"
)

func nativeEpochProofChallenge(t *testing.T, f *nativeEpochStoreFixture) transport.NativeShareEpochProofChallenge {
	t.Helper()
	receipt, err := f.stage()
	if err != nil {
		t.Fatal(err)
	}
	return transport.NativeShareEpochProofChallenge{
		Version: 1, BindingID: receipt.BindingID, StageDigest: receipt.Digest, Metadata: f.auth.Expected,
		CommandID: "30000000-0000-4000-8000-000000000004", ChallengeID: "30000000-0000-4000-8000-000000000005",
		Nonce: bytes.Repeat([]byte{7}, 32), ExpiresAt: f.now.Add(30 * time.Second).Format(time.RFC3339Nano),
	}
}

func nativeEpochProofReject(t *testing.T, proof transport.NativeShareEpochProof, err error) {
	t.Helper()
	if err == nil || !reflect.DeepEqual(proof, transport.NativeShareEpochProof{}) {
		t.Fatal("rejected proof returned success or evidence")
	}
}

// Snapshot names, permissions, symlink targets and content hashes without following
// links. SQLite bookkeeping is checked through the retained worker payload below.
func nativeEpochProofSnapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	snapshot := make(map[string]string)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if strings.HasPrefix(entry.Name(), "registry.sqlite") {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		value := info.Mode().String()
		if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			value += target
		} else if info.Mode().IsRegular() {
			digest := sha256.Sum256(nativeEpochRead(t, path))
			value += hex.EncodeToString(digest[:])
		}
		snapshot[path] = value
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func TestNativeShareEpochProofStoreRestartRetryAndIsolation(t *testing.T) {
	f := newNativeEpochStoreFixture(t)
	challenge := nativeEpochProofChallenge(t, f)
	stateDir := filepath.Dir(f.store.registry.root)
	keyringPath, err := hostcrypto.KeyringPath(stateDir, string(f.auth.Expected.NetworkID))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(keyringPath); !os.IsNotExist(err) {
		t.Fatal("fixture unexpectedly has an ambient keyring", err)
	}
	before := nativeEpochProofSnapshot(t, stateDir)
	var workerBefore []byte
	if err := f.store.registry.db.QueryRow(`SELECT payload FROM native_workers WHERE instance_id=?`, string(f.auth.Prepared.Prepare.Binding.InstanceID)).Scan(&workerBefore); err != nil {
		t.Fatal(err)
	}
	first, err := f.store.Prove(challenge, challenge, f.auth)
	if err != nil {
		t.Fatal(err)
	}
	epochKey, err := hex.DecodeString(f.auth.Expected.EpochPossessionVerifier)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Verify(challenge, epochKey, f.identity.Ed25519Verifier(), f.now); err != nil {
		t.Fatal("proof failed pinned-key verification", err)
	}
	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if first.Verify(challenge, other, f.identity.Ed25519Verifier(), f.now) == nil || first.Verify(challenge, epochKey, other, f.now) == nil {
		t.Fatal("accepted an unpinned epoch or host key")
	}
	for _, name := range []string{"epoch", "host"} {
		changed := first
		changed.EpochSignature = append([]byte(nil), first.EpochSignature...)
		changed.HostSignature = append([]byte(nil), first.HostSignature...)
		if name == "epoch" {
			changed.EpochSignature[0] ^= 1
		} else {
			changed.HostSignature[0] ^= 1
		}
		if changed.Verify(challenge, epochKey, f.identity.Ed25519Verifier(), f.now) == nil {
			t.Fatal("accepted changed", name, "signature")
		}
	}
	if err := f.store.registry.Close(); err != nil {
		t.Fatal(err)
	}
	registry, err := OpenNativeWorkerRegistry(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	holders, err := NewNativeShareHolderStore(registry, f.identity)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := NewNativeShareEpochStore(registry, holders, holders.signer, func() time.Time { return f.now })
	if err != nil {
		t.Fatal(err)
	}
	again, err := restarted.Prove(challenge, challenge, f.auth)
	if err != nil || !reflect.DeepEqual(first, again) {
		t.Fatal("restart changed exact retry proof", err)
	}
	if !reflect.DeepEqual(before, nativeEpochProofSnapshot(t, stateDir)) {
		t.Fatal("proof changed disk state or created an ambient keyring")
	}
	var workerAfter []byte
	if err := registry.db.QueryRow(`SELECT payload FROM native_workers WHERE instance_id=?`, string(f.auth.Prepared.Prepare.Binding.InstanceID)).Scan(&workerAfter); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(workerBefore, workerAfter) {
		t.Fatal("proof changed worker registry")
	}
}

func TestNativeShareEpochProofStoreIndependentExpectedChallenge(t *testing.T) {
	for _, name := range []string{"nonce", "challenge", "command", "digest", "binding", "metadata", "expiry", "prepareCommand", "stageCommand", "missingCallback"} {
		t.Run(name, func(t *testing.T) {
			f := newNativeEpochStoreFixture(t)
			expected := nativeEpochProofChallenge(t, f)
			request := expected
			request.Nonce = append([]byte(nil), expected.Nonce...)
			switch name {
			case "nonce":
				request.Nonce[0] ^= 1
			case "challenge":
				request.ChallengeID = "30000000-0000-4000-8000-000000000009"
			case "command":
				request.CommandID = "30000000-0000-4000-8000-000000000009"
			case "digest":
				request.StageDigest = strings.Repeat("a", 64)
			case "binding":
				request.BindingID = "30000000-0000-4000-8000-000000000009"
			case "metadata":
				request.Metadata.GrantGeneration++
			case "expiry":
				request.ExpiresAt = f.now.Add(20 * time.Second).Format(time.RFC3339Nano)
			case "prepareCommand":
				request.CommandID = f.auth.Prepared.Prepare.CommandID
				expected = request
			case "stageCommand":
				request.CommandID = f.auth.Expected.CommandID
				expected = request
			case "missingCallback":
				f.auth.Reauthorize = nil
			}
			before := nativeEpochProofSnapshot(t, filepath.Dir(f.store.registry.root))
			proof, err := f.store.Prove(request, expected, f.auth)
			nativeEpochProofReject(t, proof, err)
			if !reflect.DeepEqual(before, nativeEpochProofSnapshot(t, filepath.Dir(f.store.registry.root))) {
				t.Fatal("rejected challenge mutated disk")
			}
		})
	}
}

func TestNativeShareEpochProofStoreRejectsTamperedStage(t *testing.T) {
	for _, name := range []string{"whitespace", "unknownField", "duplicateField", "session", "digest", "receipt", "metadata", "source", "ciphertext"} {
		t.Run(name, func(t *testing.T) {
			f := newNativeEpochStoreFixture(t)
			challenge := nativeEpochProofChallenge(t, f)
			path := filepath.Join(f.directory(), "stage.json")
			raw := nativeEpochRead(t, path)
			var record nativeShareEpochStageRecord
			if err := json.Unmarshal(raw, &record); err != nil {
				t.Fatal(err)
			}
			switch name {
			case "whitespace":
				raw = append(raw, ' ')
			case "unknownField":
				raw = append([]byte(`{"unexpected":true,`), raw[1:]...)
			case "duplicateField":
				raw = append([]byte(`{"version":1,`), raw[1:]...)
			default:
				switch name {
				case "session":
					record.Session.HostCredentialID = "changed-credential"
				case "digest":
					record.Digest = strings.Repeat("a", 64)
				case "receipt":
					record.Receipt.Signature[0] ^= 1
				case "metadata":
					record.Expected.GrantGeneration++
				case "source":
					record.TrustedSource[0] ^= 1
				case "ciphertext":
					record.Package[len(record.Package)/2] ^= 1
				}
				var err error
				raw, err = json.Marshal(record)
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			before := nativeEpochProofSnapshot(t, filepath.Dir(f.store.registry.root))
			proof, err := f.store.Prove(challenge, challenge, f.auth)
			nativeEpochProofReject(t, proof, err)
			if !reflect.DeepEqual(before, nativeEpochProofSnapshot(t, filepath.Dir(f.store.registry.root))) {
				t.Fatal("rejected stored stage mutated disk")
			}
		})
	}
}

func TestNativeShareEpochProofStoreUnsafePathsCreateNothing(t *testing.T) {
	for _, name := range []string{"pending", "stageSymlink", "stageHardlink", "directorySymlink", "lockSymlink", "lockHardlink", "missingLock", "missingStage", "missingDirectory", "missingNamespace"} {
		t.Run(name, func(t *testing.T) {
			f := newNativeEpochStoreFixture(t)
			challenge := nativeEpochProofChallenge(t, f)
			directory := f.directory()
			stage := filepath.Join(directory, "stage.json")
			lock := filepath.Join(directory, "stage.lock")
			outside := filepath.Join(t.TempDir(), "outside")
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			switch name {
			case "pending":
				must(os.WriteFile(filepath.Join(directory, "stage.pending"), []byte("uncertain"), 0600))
			case "stageSymlink":
				must(os.Rename(stage, outside))
				must(os.Symlink(outside, stage))
			case "stageHardlink":
				must(os.Link(stage, outside))
			case "directorySymlink":
				must(os.Rename(directory, outside))
				must(os.Symlink(outside, directory))
			case "lockSymlink":
				must(os.Remove(lock))
				must(os.Symlink(outside, lock))
			case "lockHardlink":
				must(os.Link(lock, outside))
			case "missingLock":
				must(os.Remove(lock))
			case "missingStage":
				must(os.Remove(stage))
			case "missingDirectory":
				must(os.RemoveAll(directory))
			case "missingNamespace":
				must(os.RemoveAll(filepath.Join(f.store.registry.root, "staged-share-epochs")))
			}
			root := filepath.Dir(f.store.registry.root)
			before := nativeEpochProofSnapshot(t, root)
			outsideBefore := nativeEpochProofSnapshot(t, filepath.Dir(outside))
			proof, err := f.store.Prove(challenge, challenge, f.auth)
			nativeEpochProofReject(t, proof, err)
			if !reflect.DeepEqual(before, nativeEpochProofSnapshot(t, root)) || !reflect.DeepEqual(outsideBefore, nativeEpochProofSnapshot(t, filepath.Dir(outside))) {
				t.Fatal("unsafe proof created or changed files")
			}
		})
	}
}

func TestNativeShareEpochProofStoreRechecksAuthorityAfterCrypto(t *testing.T) {
	for _, name := range []string{"revoked", "challengeExpired", "deadlineExpired", "bindingExpired"} {
		t.Run(name, func(t *testing.T) {
			f := newNativeEpochStoreFixture(t)
			challenge := nativeEpochProofChallenge(t, f)
			trusted := f.auth.Reauthorize
			calls := 0
			f.auth.Reauthorize = func(a NativeShareEpochStageAuthorization) error {
				calls++
				if err := trusted(a); err != nil {
					return err
				}
				if calls == 2 {
					if name == "revoked" {
						return errors.New("authority revoked")
					}
					expires := challenge.ExpiresAt
					if name == "deadlineExpired" {
						expires = f.auth.Expected.Deadline
					} else if name == "bindingExpired" {
						expires = f.auth.Prepared.Prepare.Binding.ExpiresAt
					}
					now, err := time.Parse(time.RFC3339Nano, expires)
					if err != nil {
						return err
					}
					f.store.now = func() time.Time { return now }
				}
				return nil
			}
			before := nativeEpochProofSnapshot(t, filepath.Dir(f.store.registry.root))
			proof, err := f.store.Prove(challenge, challenge, f.auth)
			nativeEpochProofReject(t, proof, err)
			if calls != 2 {
				t.Fatal("did not reach authorization after cryptographic work", calls)
			}
			if !reflect.DeepEqual(before, nativeEpochProofSnapshot(t, filepath.Dir(f.store.registry.root))) {
				t.Fatal("late rejection mutated disk")
			}
		})
	}
}

func TestNativeShareEpochProofStoreRejectsChangedCurrentAuthority(t *testing.T) {
	for _, name := range []string{"source", "commandConnection", "authorityConnection", "previousEpoch", "grant", "recovery"} {
		t.Run(name, func(t *testing.T) {
			f := newNativeEpochStoreFixture(t)
			challenge := nativeEpochProofChallenge(t, f)
			current := f.auth
			current.TrustedSource = append(ed25519.PublicKey(nil), f.auth.TrustedSource...)
			switch name {
			case "source":
				current.TrustedSource[0] ^= 1
			case "commandConnection":
				current.Expected.CommandConnectionID = "new-command-connection"
			case "authorityConnection":
				current.Expected.AuthorityConnectionID = "new-authority-connection"
			case "previousEpoch":
				current.Expected.PreviousEpochID = "30000000-0000-4000-8000-000000000009"
			case "grant":
				current.Expected.GrantGeneration++
			case "recovery":
				b := f.auth.Prepared.Prepare.Binding
				if _, err := f.store.registry.db.Exec(`INSERT INTO native_worker_recoveries(recovery_id,instance_id,original_generation,prepare_boot_identity,phase) VALUES(?,?,?,?,?)`, "30000000-0000-4000-8000-000000000009", string(b.InstanceID), b.NativeGeneration, "original-boot", "prepared"); err != nil {
					t.Fatal(err)
				}
			}
			trusted := f.auth.Reauthorize
			calls := 0
			f.auth.Reauthorize = func(a NativeShareEpochStageAuthorization) error {
				calls++
				if err := trusted(a); err != nil {
					return err
				}
				// Current independent authority has changed since staging. Matching
				// request and retained challenge cannot replace this live check.
				if a.Expected != current.Expected || !bytes.Equal(a.TrustedSource, current.TrustedSource) {
					return errors.New("current authority changed")
				}
				return nil
			}
			before := nativeEpochProofSnapshot(t, filepath.Dir(f.store.registry.root))
			proof, err := f.store.Prove(challenge, challenge, f.auth)
			nativeEpochProofReject(t, proof, err)
			if name != "recovery" && calls != 1 {
				t.Fatal("did not consult current authority", calls)
			}
			if !reflect.DeepEqual(before, nativeEpochProofSnapshot(t, filepath.Dir(f.store.registry.root))) {
				t.Fatal("authority rejection mutated disk")
			}
		})
	}
}

func TestNativeShareEpochProofStoreConcurrentStageRegistries(t *testing.T) {
	f := newNativeEpochStoreFixture(t)
	challenge := nativeEpochProofChallenge(t, f)
	registry, err := OpenNativeWorkerRegistry(filepath.Dir(f.store.registry.root))
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	holders, err := NewNativeShareHolderStore(registry, f.identity)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewNativeShareEpochStore(registry, holders, holders.signer, func() time.Time { return f.now })
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	done := make(chan error, 2)
	go func() {
		<-start
		_, err := f.store.Prove(challenge, challenge, f.auth)
		done <- err
	}()
	go func() {
		<-start
		_, err := second.Stage(f.auth.Prepared.Prepare.Binding.BindingID, f.raw, f.auth)
		done <- err
	}()
	close(start)
	for i := 0; i < 2; i++ {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("proof and stage did not complete across registries")
		}
	}
}
