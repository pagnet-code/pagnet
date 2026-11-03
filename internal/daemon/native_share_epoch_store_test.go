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
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/e2ee"
	hostcrypto "github.com/pagnet-code/pagnet/internal/crypto"
	"github.com/pagnet-code/pagnet/transport"
)

type nativeEpochStoreFixture struct {
	store    *NativeShareEpochStore
	holders  *NativeShareHolderStore
	identity *hostcrypto.HostIdentity
	auth     NativeShareEpochStageAuthorization
	raw      []byte
	source   ed25519.PrivateKey
	now      time.Time
}

func newNativeEpochStoreFixture(t *testing.T) *nativeEpochStoreFixture {
	t.Helper()
	holders, identity, request, session := nativeShareStoreFixture(t)
	prepared, err := holders.Prepare(request, "https://example.test", session)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	store, err := NewNativeShareEpochStore(holders.registry, holders, holders.signer, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	_, source, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &nativeEpochStoreFixture{store: store, holders: holders, identity: identity, source: source, now: now}
	fresh, err := hostcrypto.NewFreshNativeShareEpoch()
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Destroy()
	b := request.Binding
	m := transport.NativeShareEpochMetadata{
		Version: 1, OperationID: "30000000-0000-4000-8000-000000000001", TenantID: prepared.Subject.TenantID, NetworkID: b.NetworkID,
		PreviousEpochID: "30000000-0000-4000-8000-000000000002", EpochID: fresh.ID(), ProposalRevision: b.ProposalRevision,
		GrantGeneration: b.GrantGeneration, BindingDigest: prepared.BindingDigest, HolderID: prepared.HolderID, HolderX25519: prepared.HolderX25519,
		CommandID: "30000000-0000-4000-8000-000000000003", CommandConnectionID: "trusted-command", AuthorityConnectionID: "trusted-authority", Deadline: now.Add(time.Minute).Format(time.RFC3339Nano),
	}
	verifier, err := fresh.PossessionVerifier(m.NetworkID)
	if err != nil {
		t.Fatal(err)
	}
	m.EpochPossessionVerifier = hex.EncodeToString(verifier)
	p, err := hostcrypto.SealNativeShareEpoch(fresh, m, source, now)
	if err != nil {
		t.Fatal(err)
	}
	f.raw, err = json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	f.auth = NativeShareEpochStageAuthorization{Prepared: prepared, Expected: m, TrustedSource: source.Public().(ed25519.PublicKey), ServerURL: "https://example.test", Session: session}
	// This authority is captured before accepting a package and never inferred from it.
	pinned := f.auth
	f.auth.Reauthorize = func(got NativeShareEpochStageAuthorization) error {
		if got.Expected != pinned.Expected || !reflect.DeepEqual(got.Prepared, pinned.Prepared) || !bytes.Equal(got.TrustedSource, pinned.TrustedSource) || got.ServerURL != pinned.ServerURL || !reflect.DeepEqual(got.Session, pinned.Session) {
			return errors.New("independent authority changed")
		}
		return nil
	}
	return f
}

func (f *nativeEpochStoreFixture) directory() string {
	return filepath.Join(f.store.registry.root, "staged-share-epochs", string(f.auth.Prepared.Prepare.Binding.BindingID), string(f.auth.Expected.OperationID))
}
func (f *nativeEpochStoreFixture) stage() (NativeShareEpochStageReceipt, error) {
	return f.store.Stage(f.auth.Prepared.Prepare.Binding.BindingID, f.raw, f.auth)
}
func nativeEpochReject(t *testing.T, receipt NativeShareEpochStageReceipt, err error) {
	t.Helper()
	if err == nil || !reflect.DeepEqual(receipt, NativeShareEpochStageReceipt{}) {
		t.Fatal("rejected stage returned success or evidence")
	}
}
func nativeEpochRead(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestNativeShareEpochStoreRestartRetryAndIsolation(t *testing.T) {
	f := newNativeEpochStoreFixture(t)
	holderPath := filepath.Join(nativeShareStorePath(f.holders, f.auth.Prepared.Prepare), "holder.json")
	holderBefore := sha256.Sum256(nativeEpochRead(t, holderPath))
	var registryBefore []byte
	if err := f.store.registry.db.QueryRow(`SELECT payload FROM native_workers WHERE instance_id=?`, string(f.auth.Prepared.Prepare.Binding.InstanceID)).Scan(&registryBefore); err != nil {
		t.Fatal(err)
	}
	workspace := filepath.Join(f.store.registry.root, "workspace-sentinel")
	if err := os.WriteFile(workspace, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	first, err := f.stage()
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(f.identity.Ed25519Verifier(), nativeShareEpochStageReceiptBytes(first), first.Signature) {
		t.Fatal("invalid stage receipt signature")
	}
	stageBefore := nativeEpochRead(t, filepath.Join(f.directory(), "stage.json"))
	var record nativeShareEpochStageRecord
	if err := json.Unmarshal(stageBefore, &record); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(record.Package, f.raw) || record.Expected != f.auth.Expected {
		t.Fatal("ciphertext or retained metadata changed")
	}
	// The entire serialized record is reconstructed from ciphertext and public evidence.
	want := nativeShareEpochStageRecord{Session: nativeShareEpochStageSessionSnapshot(f.auth.Session), Version: 1, Package: f.raw, Expected: f.auth.Expected, TrustedSource: f.auth.TrustedSource, Prepared: f.auth.Prepared, Digest: first.Digest, Receipt: first}
	publicOnly, err := json.Marshal(want)
	if err != nil || !bytes.Equal(publicOnly, stageBefore) || bytes.Contains(stageBefore, []byte("privateKey")) || bytes.Contains(stageBefore, []byte("epochKey")) {
		t.Fatal("unexpected secret or noncanonical stage material")
	}
	root := f.store.registry.root
	if err := f.store.registry.Close(); err != nil {
		t.Fatal(err)
	}
	registry, err := OpenNativeWorkerRegistry(filepath.Dir(root))
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
	again, err := restarted.Stage(f.auth.Prepared.Prepare.Binding.BindingID, f.raw, f.auth)
	if err != nil || !reflect.DeepEqual(first, again) {
		t.Fatal("restart changed receipt", err)
	}
	if !bytes.Equal(stageBefore, nativeEpochRead(t, filepath.Join(f.directory(), "stage.json"))) || holderBefore != sha256.Sum256(nativeEpochRead(t, holderPath)) || string(nativeEpochRead(t, workspace)) != "unchanged" {
		t.Fatal("stage mutated existing state")
	}
	var registryAfter []byte
	if err := registry.db.QueryRow(`SELECT payload FROM native_workers WHERE instance_id=?`, string(f.auth.Prepared.Prepare.Binding.InstanceID)).Scan(&registryAfter); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(registryBefore, registryAfter) {
		t.Fatal("stage mutated worker registry")
	}
}

func TestNativeShareEpochStoreConcurrentRegistries(t *testing.T) {
	f := newNativeEpochStoreFixture(t)
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
	var wg sync.WaitGroup
	receipts := make(chan NativeShareEpochStageReceipt, 2)
	failures := make(chan error, 2)
	for _, store := range []*NativeShareEpochStore{f.store, second} {
		wg.Add(1)
		go func(store *NativeShareEpochStore) {
			defer wg.Done()
			r, e := store.Stage(f.auth.Prepared.Prepare.Binding.BindingID, f.raw, f.auth)
			receipts <- r
			failures <- e
		}(store)
	}
	wg.Wait()
	for i := 0; i < 2; i++ {
		if err := <-failures; err != nil {
			t.Fatal(err)
		}
	}
	if !reflect.DeepEqual(<-receipts, <-receipts) {
		t.Fatal("concurrent retry receipts differ")
	}
}

func TestNativeShareEpochStoreRejectsUntrustedOrStaleInputs(t *testing.T) {
	for _, name := range []string{"missingCallback", "source", "signature", "ciphertext", "metadata", "context", "connections", "previousEpoch", "expired", "bindingExpired", "recovery", "rawConflict"} {
		t.Run(name, func(t *testing.T) {
			f := newNativeEpochStoreFixture(t)
			if name == "rawConflict" {
				if _, err := f.stage(); err != nil {
					t.Fatal(err)
				}
			}
			switch name {
			case "missingCallback":
				f.auth.Reauthorize = nil
			case "source":
				other, _, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				f.auth.TrustedSource = other
			case "signature", "ciphertext":
				var p transport.NativeShareEpochPackage
				if err := json.Unmarshal(f.raw, &p); err != nil {
					t.Fatal(err)
				}
				if name == "signature" {
					p.Signature[0] ^= 1
				} else {
					p.Wrapped.Ciphertext[0] ^= 1
				}
				f.raw, _ = json.Marshal(p)
			case "metadata":
				f.auth.Expected.GrantGeneration++
			case "context":
				f.auth.Prepared.Prepare.Binding.ContextID = "30000000-0000-4000-8000-000000000009"
			case "connections":
				f.auth.Expected.CommandConnectionID = "replaced-command"
			case "previousEpoch":
				f.auth.Expected.PreviousEpochID = "30000000-0000-4000-8000-000000000009"
			case "expired":
				deadline, _ := time.Parse(time.RFC3339Nano, f.auth.Expected.Deadline)
				f.store.now = func() time.Time { return deadline }
			case "bindingExpired":
				expiry, _ := time.Parse(time.RFC3339Nano, f.auth.Prepared.Prepare.Binding.ExpiresAt)
				f.store.now = func() time.Time { return expiry }
			case "recovery":
				b := f.auth.Prepared.Prepare.Binding
				if _, err := f.store.registry.db.Exec(`INSERT INTO native_worker_recoveries(recovery_id,instance_id,original_generation,prepare_boot_identity,phase) VALUES(?,?,?,?,?)`, "30000000-0000-4000-8000-000000000009", string(b.InstanceID), b.NativeGeneration, "original-boot", "prepared"); err != nil {
					t.Fatal(err)
				}
			case "rawConflict":
				f.raw = append(f.raw, ' ')
			}
			r, err := f.stage()
			nativeEpochReject(t, r, err)
		})
	}
}

func TestNativeShareEpochStoreCallbackFailures(t *testing.T) {
	for _, failAt := range []int{1, 2, 3, 4} {
		t.Run(string(rune('0'+failAt)), func(t *testing.T) {
			f := newNativeEpochStoreFixture(t)
			trusted := f.auth.Reauthorize
			calls := 0
			f.auth.Reauthorize = func(a NativeShareEpochStageAuthorization) error {
				calls++
				if err := trusted(a); err != nil {
					return err
				}
				if calls >= failAt {
					return errors.New("authority revoked")
				}
				return nil
			}
			r, err := f.stage()
			nativeEpochReject(t, r, err)
			_, statErr := os.Stat(filepath.Join(f.directory(), "stage.json"))
			if failAt < 4 && !os.IsNotExist(statErr) {
				t.Fatal("published before authorization", statErr)
			}
			if failAt == 4 {
				if statErr != nil {
					t.Fatal("final-check fixture did not reach publication", statErr)
				}
				// Published ciphertext grants no receipt while authority continues to reject.
				r, err = f.stage()
				nativeEpochReject(t, r, err)
			}
		})
	}
}

func TestNativeShareEpochStoreUnsafeState(t *testing.T) {
	for _, name := range []string{"pending", "malformed", "unknownField", "duplicateField", "trailing", "targetPermissions", "targetSymlink", "targetHardlink", "directoryPermissions", "directorySymlink", "rootPermissions", "lockSymlink"} {
		t.Run(name, func(t *testing.T) {
			f := newNativeEpochStoreFixture(t)
			if _, err := f.stage(); err != nil {
				t.Fatal(err)
			}
			directory := f.directory()
			target := filepath.Join(directory, "stage.json")
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			switch name {
			case "pending":
				must(os.WriteFile(filepath.Join(directory, "stage.pending"), []byte("uncertain"), 0600))
			case "malformed":
				must(os.WriteFile(target, []byte(`{"version":`), 0600))
			case "unknownField":
				raw := nativeEpochRead(t, target)
				raw = append([]byte(`{"unexpected":true,`), raw[1:]...)
				must(os.WriteFile(target, raw, 0600))
			case "duplicateField":
				raw := nativeEpochRead(t, target)
				raw = append([]byte(`{"version":1,`), raw[1:]...)
				must(os.WriteFile(target, raw, 0600))
			case "trailing":
				must(os.WriteFile(target, append(nativeEpochRead(t, target), []byte(` {}`)...), 0600))
			case "targetPermissions":
				must(os.Chmod(target, 0640))
			case "targetSymlink":
				outside := filepath.Join(t.TempDir(), "saved")
				must(os.Rename(target, outside))
				must(os.Symlink(outside, target))
			case "targetHardlink":
				must(os.Link(target, filepath.Join(t.TempDir(), "linked")))
			case "directoryPermissions":
				must(os.Chmod(directory, 0755))
			case "directorySymlink":
				outside := filepath.Join(t.TempDir(), "saved")
				must(os.Rename(directory, outside))
				must(os.Symlink(outside, directory))
			case "rootPermissions":
				must(os.Chmod(f.store.registry.root, 0755))
			case "lockSymlink":
				lock := filepath.Join(directory, "stage.lock")
				must(os.Remove(lock))
				must(os.Symlink(filepath.Join(t.TempDir(), "outside"), lock))
			}
			r, err := f.stage()
			nativeEpochReject(t, r, err)
		})
	}
}

func TestNativeShareEpochStagePublishNoOverwrite(t *testing.T) {
	directoryPath := t.TempDir()
	if err := os.Chmod(directoryPath, 0700); err != nil {
		t.Fatal(err)
	}
	directory, err := nativeShareHolderDirectory(directoryPath)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	target := filepath.Join(directoryPath, "stage.json")
	original := []byte("existing immutable stage")
	if err := os.WriteFile(target, original, 0600); err != nil {
		t.Fatal(err)
	}
	pending := []byte("new uncertain publication")
	if err := nativeShareEpochStagePublish(directory, pending); err == nil {
		t.Fatal("overwrote existing stage")
	}
	if !bytes.Equal(nativeEpochRead(t, target), original) || !bytes.Equal(nativeEpochRead(t, filepath.Join(directoryPath, "stage.pending")), pending) {
		t.Fatal("publication failure overwrote or discarded state")
	}
	if err := nativeShareEpochStagePublish(directory, []byte(strings.Repeat("x", 8))); err == nil {
		t.Fatal("retried over pending publication")
	}
}

func TestNativeShareEpochStoreRechecksAuthorityWhileWaiting(t *testing.T) {
	f := newNativeEpochStoreFixture(t)
	if err := os.MkdirAll(f.directory(), 0700); err != nil {
		t.Fatal(err)
	}
	directory, err := nativeShareHolderDirectory(f.directory())
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	lock, err := nativeShareEpochStageLock(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	writer, err := OpenNativeWorkerRegistry(filepath.Dir(f.store.registry.root))
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	reached := make(chan struct{}, 1)
	trusted := f.auth.Reauthorize
	f.auth.Reauthorize = func(a NativeShareEpochStageAuthorization) error {
		if err := trusted(a); err != nil {
			return err
		}
		select {
		case reached <- struct{}{}:
		default:
		}
		return nil
	}
	type result struct {
		receipt NativeShareEpochStageReceipt
		err     error
	}
	done := make(chan result, 1)
	go func() { r, e := f.stage(); done <- result{r, e} }()
	select {
	case <-reached:
	case <-time.After(5 * time.Second):
		t.Fatal("stage did not reach initial authorization")
	}
	b := f.auth.Prepared.Prepare.Binding
	if _, err := writer.db.Exec(`INSERT INTO native_worker_recoveries(recovery_id,instance_id,original_generation,prepare_boot_identity,phase) VALUES(?,?,?,?,?)`, "30000000-0000-4000-8000-000000000009", string(b.InstanceID), b.NativeGeneration, "original-boot", "prepared"); err != nil {
		t.Fatal(err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-done:
		nativeEpochReject(t, got.receipt, got.err)
	case <-time.After(5 * time.Second):
		t.Fatal("stage did not resume after flock released")
	}
	if _, err := os.Stat(filepath.Join(f.directory(), "stage.json")); !os.IsNotExist(err) {
		t.Fatal("published after recovery fence", err)
	}
}

func TestNativeShareEpochStoreRequiresExistingHolder(t *testing.T) {
	f := newNativeEpochStoreFixture(t)
	holder := nativeShareStorePath(f.holders, f.auth.Prepared.Prepare)
	if err := os.RemoveAll(holder); err != nil {
		t.Fatal(err)
	}
	r, err := f.stage()
	nativeEpochReject(t, r, err)
	if _, err := os.Stat(holder); !os.IsNotExist(err) {
		t.Fatal("recreated missing holder", err)
	}
	if _, err := os.Stat(filepath.Join(f.store.registry.root, "staged-share-epochs")); !os.IsNotExist(err) {
		t.Fatal("created stage namespace without holder", err)
	}
}

func TestNativeShareEpochStoreRejectsSignedInvalidCiphertextAndRepinnedContext(t *testing.T) {
	for _, name := range []string{"ciphertext", "trustedContext"} {
		t.Run(name, func(t *testing.T) {
			f := newNativeEpochStoreFixture(t)
			var p transport.NativeShareEpochPackage
			if err := json.Unmarshal(f.raw, &p); err != nil {
				t.Fatal(err)
			}
			if name == "ciphertext" {
				p.Wrapped.Ciphertext[0] ^= 1
			} else {
				// A correctly signed package and matching supplied metadata cannot replace
				// independently retained connection authority in the mandatory callback.
				p.Metadata.CommandConnectionID = "attacker-command"
				f.auth.Expected = p.Metadata
			}
			signed, err := p.SignatureBytes()
			if err != nil {
				t.Fatal(err)
			}
			p.Signature = ed25519.Sign(f.source, signed)
			f.raw, err = json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			r, err := f.stage()
			nativeEpochReject(t, r, err)
			if _, err := os.Stat(filepath.Join(f.directory(), "stage.json")); !os.IsNotExist(err) {
				t.Fatal("published invalid ciphertext or context", err)
			}
		})
	}
}

func TestNativeShareEpochStoreCopiesSessionFeatures(t *testing.T) {
	f := newNativeEpochStoreFixture(t)
	original := []string{"pinned-feature"}
	f.auth.Session.ProtocolFeatures = original
	pinned := f.auth
	pinned.Session.ProtocolFeatures = append([]string(nil), original...)
	calls := 0
	f.auth.Reauthorize = func(a NativeShareEpochStageAuthorization) error {
		calls++
		if !reflect.DeepEqual(a.Session, pinned.Session) || !reflect.DeepEqual(a.Prepared, pinned.Prepared) || a.Expected != pinned.Expected || !bytes.Equal(a.TrustedSource, pinned.TrustedSource) || a.ServerURL != pinned.ServerURL {
			return errors.New("authority changed")
		}
		if calls == 1 {
			original[0] = "caller-mutated-feature"
		}
		return nil
	}
	if _, err := f.stage(); err != nil {
		t.Fatal(err)
	}
	if calls != 4 {
		t.Fatal("did not exercise all authorization boundaries")
	}
}

func TestNativeShareEpochStoreCallbackExpiry(t *testing.T) {
	for _, expireAt := range []int{1, 4} {
		t.Run(string(rune('0'+expireAt)), func(t *testing.T) {
			f := newNativeEpochStoreFixture(t)
			trusted := f.auth.Reauthorize
			deadline, err := time.Parse(time.RFC3339Nano, f.auth.Expected.Deadline)
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			f.auth.Reauthorize = func(a NativeShareEpochStageAuthorization) error {
				calls++
				if err := trusted(a); err != nil {
					return err
				}
				if calls == expireAt {
					f.store.now = func() time.Time { return deadline }
				}
				return nil
			}
			r, err := f.stage()
			nativeEpochReject(t, r, err)
			_, err = os.Stat(filepath.Join(f.directory(), "stage.json"))
			if expireAt == 1 && !os.IsNotExist(err) {
				t.Fatal("published after initial callback expiry", err)
			}
			if expireAt == 4 && err != nil {
				t.Fatal("final expiry did not reach publication", err)
			}
		})
	}
}

func TestNativeShareEpochStoreRecomputesPossessionVerifier(t *testing.T) {
	f := newNativeEpochStoreFixture(t)
	verifier, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := f.auth.Expected
	m.EpochPossessionVerifier = hex.EncodeToString(verifier)
	f.auth.Expected = m
	trusted := f.auth
	f.auth.Reauthorize = func(a NativeShareEpochStageAuthorization) error {
		if a.Expected != trusted.Expected || !reflect.DeepEqual(a.Prepared, trusted.Prepared) || !reflect.DeepEqual(a.Session, trusted.Session) || !bytes.Equal(a.TrustedSource, trusted.TrustedSource) || a.ServerURL != trusted.ServerURL {
			return errors.New("authority changed")
		}
		return nil
	}
	holder, err := hex.DecodeString(m.HolderX25519)
	if err != nil {
		t.Fatal(err)
	}
	aad, err := m.AAD()
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	enc, ct, err := e2ee.HPKEWrap(holder, []byte(transport.NativeShareEpochInfo), aad, key)
	if err != nil {
		t.Fatal(err)
	}
	p := transport.NativeShareEpochPackage{Metadata: m, Wrapped: transport.CryptoHPKEWrap{Enc: enc, Ciphertext: ct}}
	signed, err := p.SignatureBytes()
	if err != nil {
		t.Fatal(err)
	}
	p.Signature = ed25519.Sign(f.source, signed)
	f.raw, err = json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	// The source signature and HPKE ciphertext are valid. Only possession
	// recomputation distinguishes this forged verifier from the real epoch key.
	if err := p.Verify(m, f.auth.TrustedSource, f.now); err != nil {
		t.Fatal(err)
	}
	r, err := f.stage()
	nativeEpochReject(t, r, err)
	if _, err := os.Stat(filepath.Join(f.directory(), "stage.json")); !os.IsNotExist(err) {
		t.Fatal("published a forged possession verifier", err)
	}
}

func TestNativeShareEpochStoreRetrySessionContext(t *testing.T) {
	f := newNativeEpochStoreFixture(t)
	f.auth.Session.ProtocolFeatures = []string{"b", "a", "b"}
	pinned := f.auth
	pinned.Session.ProtocolFeatures = nil
	f.auth.Reauthorize = func(a NativeShareEpochStageAuthorization) error {
		session := a.Session
		session.ProtocolFeatures = nil
		if a.Expected != pinned.Expected || !reflect.DeepEqual(a.Prepared, pinned.Prepared) || !bytes.Equal(a.TrustedSource, pinned.TrustedSource) || a.ServerURL != pinned.ServerURL || !reflect.DeepEqual(session, pinned.Session) {
			return errors.New("authority changed")
		}
		seen := map[string]bool{}
		for _, feature := range a.Session.ProtocolFeatures {
			if feature != "a" && feature != "b" {
				return errors.New("feature authority changed")
			}
			seen[feature] = true
		}
		if !seen["a"] || !seen["b"] {
			return errors.New("feature authority missing")
		}
		return nil
	}
	first, err := f.stage()
	if err != nil {
		t.Fatal(err)
	}
	f.auth.Session.ProtocolFeatures = []string{"a", "b"}
	again, err := f.stage()
	if err != nil || !reflect.DeepEqual(first, again) {
		t.Fatal("equivalent session feature set changed receipt", err)
	}
	for _, name := range []string{"credential", "ownership", "features"} {
		t.Run(name, func(t *testing.T) {
			changed := f.auth
			switch name {
			case "credential":
				changed.Session.HostCredentialID = "30000000-0000-4000-8000-000000000009"
			case "ownership":
				if changed.Session.OwnershipScope == "personal" {
					changed.Session.OwnershipScope = "organization"
				} else {
					changed.Session.OwnershipScope = "personal"
				}
			case "features":
				changed.Session.ProtocolFeatures = []string{"a", "b", "c"}
			}
			// Current trusted authority may independently approve this changed context;
			// an immutable cached receipt still belongs to the originally staged session.
			approved := changed.Session
			changed.Reauthorize = func(a NativeShareEpochStageAuthorization) error {
				if a.Expected != pinned.Expected || !reflect.DeepEqual(a.Prepared, pinned.Prepared) || !bytes.Equal(a.TrustedSource, pinned.TrustedSource) || a.ServerURL != pinned.ServerURL || !reflect.DeepEqual(a.Session, approved) {
					return errors.New("authority changed")
				}
				return nil
			}
			r, err := f.store.Stage(changed.Prepared.Prepare.Binding.BindingID, f.raw, changed)
			nativeEpochReject(t, r, err)
		})
	}
}
