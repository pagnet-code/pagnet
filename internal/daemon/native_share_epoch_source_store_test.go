//go:build linux || darwin

package daemon

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	hostcrypto "github.com/pagnet-code/pagnet/internal/crypto"
	"github.com/pagnet-code/pagnet/transport"
)

type nativeEpochSourceStoreFixture struct {
	store   *NativeShareEpochSourceStore
	holders *NativeShareHolderStore
	auth    NativeShareEpochSourceAuthorization
	private []byte
	ring    *hostcrypto.Keyring
	now     time.Time
}

func newNativeEpochSourceStoreFixture(t *testing.T) *nativeEpochSourceStoreFixture {
	t.Helper()
	holders, identity, request, session := nativeShareStoreFixture(t)
	session.HostCredentialID = "source-and-recipient-credential"
	prepared, err := holders.Prepare(request, "https://example.test", session)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	store, err := NewNativeShareEpochSourceStore(holders.registry, holders.signer, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	ring := hostcrypto.NewKeyring(string(request.Binding.NetworkID))
	active, err := ring.Activate(now)
	if err != nil {
		t.Fatal(err)
	}
	if err := hostcrypto.SaveKeyring(filepath.Dir(holders.registry.root), ring); err != nil {
		t.Fatal(err)
	}
	signer, err := hostcrypto.EpochPossessionSigner(ring, active.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(signer)
	holder, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b := request.Binding
	intent := NativeShareEpochSourceIntent{
		Prepared: prepared, RecipientHostKey: identity.Ed25519Verifier(), RecipientServerURL: "https://example.test", RecipientSession: session,
		RecipientConnectionID: "recipient-command", RecipientAuthorityConnectionID: "recipient-authority",
		Expected:      transport.NativeShareEpochMetadata{Version: 1, OperationID: "30000000-0000-4000-8000-000000000001", TenantID: prepared.Subject.TenantID, NetworkID: b.NetworkID, PreviousEpochID: domain.ID(active.ID), ProposalRevision: b.ProposalRevision, GrantGeneration: b.GrantGeneration, BindingDigest: prepared.BindingDigest, HolderID: prepared.HolderID, HolderX25519: prepared.HolderX25519, CommandID: "30000000-0000-4000-8000-000000000003", CommandConnectionID: "recipient-command", AuthorityConnectionID: "recipient-authority", Deadline: now.Add(time.Minute).Format(time.RFC3339Nano)},
		Source:        transport.NativeShareEpochSourceContext{Subject: prepared.Subject, ConnectedAt: now.Format(time.RFC3339Nano), HostCredentialID: session.HostCredentialID, OwnershipScope: session.OwnershipScope, ConnectionID: "source-command", AuthorityConnectionID: "source-authority", HolderID: "30000000-0000-4000-8000-000000000004", HolderX25519: hex.EncodeToString(holder.PublicKey().Bytes()), SigningKey: hex.EncodeToString(identity.Ed25519Verifier()), ProposalID: b.ProposalID, GrantID: b.GrantID, BindingID: b.BindingID},
		SourceSession: session, SourceInstanceID: b.InstanceID, SourceNativeGeneration: b.NativeGeneration, CommittedVerifier: signer.Public().(ed25519.PublicKey),
	}
	f := &nativeEpochSourceStoreFixture{store: store, holders: holders, private: holder.Bytes(), ring: ring, now: now}
	f.auth = NativeShareEpochSourceAuthorization{NativeShareEpochSourceIntent: intent, Reauthorize: func(got NativeShareEpochSourceIntent) error {
		if !reflect.DeepEqual(got, intent) {
			return errors.New("independent authority changed")
		}
		return nil
	}}
	return f
}
func (f *nativeEpochSourceStoreFixture) directory() string {
	return filepath.Join(f.holders.registry.root, "prepared-share-epochs", string(f.auth.Expected.OperationID))
}
func (f *nativeEpochSourceStoreFixture) prepare() (transport.NativeShareEpochPackage, error) {
	return f.store.Prepare(f.auth, f.private)
}
func nativeEpochSourceReject(t *testing.T, p transport.NativeShareEpochPackage, err error) {
	t.Helper()
	if err == nil || !reflect.DeepEqual(p, transport.NativeShareEpochPackage{}) {
		t.Fatal("rejected prepare returned success or package")
	}
}

func TestNativeShareEpochSourceStoreRestartAndIsolation(t *testing.T) {
	f := newNativeEpochSourceStoreFixture(t)
	if f.auth.Source.ConnectionID == f.auth.RecipientConnectionID || f.auth.Source.AuthorityConnectionID == f.auth.RecipientAuthorityConnectionID {
		t.Fatal("fixture must use distinct source and recipient connection pairs")
	}
	keyringPath, err := hostcrypto.KeyringPath(filepath.Dir(f.holders.registry.root), f.ring.NetworkID)
	if err != nil {
		t.Fatal(err)
	}
	ringBefore := nativeEpochRead(t, keyringPath)
	holderPath := filepath.Join(nativeShareStorePath(f.holders, f.auth.Prepared.Prepare), "holder.json")
	holderBefore := nativeEpochRead(t, holderPath)
	var registryBefore []byte
	if err := f.holders.registry.db.QueryRow(`SELECT payload FROM native_workers WHERE instance_id=?`, string(f.auth.SourceInstanceID)).Scan(&registryBefore); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(f.holders.registry.root, "workspace-sentinel")
	if err := os.WriteFile(sentinel, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	first, err := f.prepare()
	if err != nil {
		t.Fatal(err)
	}
	if first.Metadata.EpochID == "" || first.Metadata.EpochID == f.auth.Expected.PreviousEpochID || first.Metadata.EpochPossessionVerifier == "" {
		t.Fatal("missing fresh prospective epoch")
	}
	raw := nativeEpochRead(t, filepath.Join(f.directory(), "source.json"))
	var record nativeShareEpochSourceRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(record.Package, first) {
		t.Fatal("retained package differs")
	}
	var holder nativeShareHolderRecord
	if err := json.Unmarshal(holderBefore, &holder); err != nil {
		t.Fatal(err)
	}
	recipient, err := hostcrypto.OpenNativeShareEpoch(first, first.Metadata, f.holders.signer.Public().(ed25519.PublicKey), holder.PrivateKey, f.now)
	if err != nil {
		t.Fatal(err)
	}
	defer recipient.Destroy()
	source, err := hostcrypto.OpenNativeShareEpochSource(record.SourceEnvelope, record.SourceEnvelope.Metadata, f.holders.signer.Public().(ed25519.PublicKey), f.private, f.now)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Destroy()
	if !bytes.Equal(recipient.Key, source.Key) || recipient.EpochID != source.EpochID {
		t.Fatal("source and recipient disagree")
	}
	for _, secret := range [][]byte{recipient.Key, f.private} {
		encoded, _ := json.Marshal(secret)
		if bytes.Contains(raw, encoded) {
			t.Fatal("persisted plaintext key")
		}
	}
	registry, err := OpenNativeWorkerRegistry(filepath.Dir(f.holders.registry.root))
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	restarted, err := NewNativeShareEpochSourceStore(registry, f.holders.signer, func() time.Time { return f.now })
	if err != nil {
		t.Fatal(err)
	}
	again, err := restarted.Prepare(f.auth, f.private)
	if err != nil || !reflect.DeepEqual(first, again) {
		t.Fatal("restart changed package", err)
	}
	again.Signature[0] ^= 1
	retry, err := f.prepare()
	if err != nil || !reflect.DeepEqual(first, retry) {
		t.Fatal("returned package aliases retained state", err)
	}
	if !bytes.Equal(raw, nativeEpochRead(t, filepath.Join(f.directory(), "source.json"))) || !bytes.Equal(ringBefore, nativeEpochRead(t, keyringPath)) || !bytes.Equal(holderBefore, nativeEpochRead(t, holderPath)) || string(nativeEpochRead(t, sentinel)) != "unchanged" {
		t.Fatal("prepare mutated ambient state")
	}
	var registryAfter []byte
	if err := registry.db.QueryRow(`SELECT payload FROM native_workers WHERE instance_id=?`, string(f.auth.SourceInstanceID)).Scan(&registryAfter); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(registryBefore, registryAfter) {
		t.Fatal("prepare mutated registry")
	}
}

func TestNativeShareEpochSourceStoreConcurrentHandles(t *testing.T) {
	f := newNativeEpochSourceStoreFixture(t)
	registry, err := OpenNativeWorkerRegistry(filepath.Dir(f.holders.registry.root))
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	second, err := NewNativeShareEpochSourceStore(registry, f.holders.signer, func() time.Time { return f.now })
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	packages := make(chan transport.NativeShareEpochPackage, 2)
	failures := make(chan error, 2)
	for _, store := range []*NativeShareEpochSourceStore{f.store, second} {
		wg.Add(1)
		go func(store *NativeShareEpochSourceStore) {
			defer wg.Done()
			p, e := store.Prepare(f.auth, f.private)
			packages <- p
			failures <- e
		}(store)
	}
	wg.Wait()
	for i := 0; i < 2; i++ {
		if err := <-failures; err != nil {
			t.Fatal(err)
		}
	}
	if !reflect.DeepEqual(<-packages, <-packages) {
		t.Fatal("concurrent handles minted different packages")
	}
}

func TestNativeShareEpochSourceStoreRejectsChangedAuthority(t *testing.T) {
	for _, name := range []string{"missingCallback", "revoked", "private", "hostKey", "verifier", "rotated", "expired", "sourceSession", "sourceConnection", "recipientConnection", "recipientAuthority", "sourceGeneration", "changedIntent", "suppliedEpoch", "suppliedVerifier"} {
		t.Run(name, func(t *testing.T) {
			f := newNativeEpochSourceStoreFixture(t)
			if name == "changedIntent" {
				if _, err := f.prepare(); err != nil {
					t.Fatal(err)
				}
			}
			switch name {
			case "missingCallback":
				f.auth.Reauthorize = nil
			case "revoked":
				f.auth.Reauthorize = func(NativeShareEpochSourceIntent) error { return errors.New("revoked") }
			case "private":
				key, err := ecdh.X25519().GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				f.private = key.Bytes()
			case "hostKey":
				key, _, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				f.auth.RecipientHostKey = key
			case "verifier":
				key, _, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				f.auth.CommittedVerifier = key
			case "rotated":
				if _, err := f.ring.Rotate(f.now.Add(time.Second)); err != nil {
					t.Fatal(err)
				}
				if err := hostcrypto.SaveKeyring(filepath.Dir(f.holders.registry.root), f.ring); err != nil {
					t.Fatal(err)
				}
			case "expired":
				deadline, _ := time.Parse(time.RFC3339Nano, f.auth.Expected.Deadline)
				f.store.now = func() time.Time { return deadline }
			case "sourceSession":
				f.auth.SourceSession.BootID = "changed-boot"
			case "sourceConnection":
				f.auth.Source.ConnectionID = "changed-source"
			case "recipientConnection":
				f.auth.Expected.CommandConnectionID = "wrong-recipient-command"
				f.auth.Reauthorize = func(NativeShareEpochSourceIntent) error { return nil }
			case "recipientAuthority":
				f.auth.Expected.AuthorityConnectionID = "wrong-recipient-authority"
				f.auth.Reauthorize = func(NativeShareEpochSourceIntent) error { return nil }
			case "sourceGeneration":
				f.auth.SourceNativeGeneration = "changed-generation"
			case "changedIntent":
				f.auth.RecipientConnectionID = "changed-recipient"
				f.auth.Expected.CommandConnectionID = "changed-recipient"
				approved := f.auth.NativeShareEpochSourceIntent
				f.auth.Reauthorize = func(got NativeShareEpochSourceIntent) error {
					if !reflect.DeepEqual(got, approved) {
						return errors.New("changed")
					}
					return nil
				}
			case "suppliedEpoch":
				f.auth.Expected.EpochID = "30000000-0000-4000-8000-000000000009"
			case "suppliedVerifier":
				f.auth.Expected.EpochPossessionVerifier = hex.EncodeToString(f.auth.CommittedVerifier)
			}
			p, err := f.prepare()
			nativeEpochSourceReject(t, p, err)
		})
	}
}

func TestNativeShareEpochSourceStoreUnsafeState(t *testing.T) {
	for _, name := range []string{"pending", "malformed", "unknownField", "duplicateField", "trailing", "targetPermissions", "targetSymlink", "targetHardlink", "directoryPermissions", "directorySymlink", "rootPermissions", "lockSymlink"} {
		t.Run(name, func(t *testing.T) {
			f := newNativeEpochSourceStoreFixture(t)
			if _, err := f.prepare(); err != nil {
				t.Fatal(err)
			}
			directory := f.directory()
			target := filepath.Join(directory, "source.json")
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			switch name {
			case "pending":
				must(os.WriteFile(filepath.Join(directory, "source.pending"), []byte("uncertain"), 0600))
			case "malformed":
				must(os.WriteFile(target, []byte(`{"version":`), 0600))
			case "unknownField":
				raw := nativeEpochRead(t, target)
				must(os.WriteFile(target, append([]byte(`{"unexpected":true,`), raw[1:]...), 0600))
			case "duplicateField":
				raw := nativeEpochRead(t, target)
				must(os.WriteFile(target, append([]byte(`{"version":1,`), raw[1:]...), 0600))
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
				must(os.Chmod(f.holders.registry.root, 0755))
			case "lockSymlink":
				lock := filepath.Join(directory, "source.lock")
				must(os.Remove(lock))
				must(os.Symlink(filepath.Join(t.TempDir(), "outside"), lock))
			}
			p, err := f.prepare()
			nativeEpochSourceReject(t, p, err)
		})
	}
}

func TestNativeShareEpochSourceStoreSyncFailures(t *testing.T) {
	for failAt := 1; failAt <= 9; failAt++ {
		t.Run(string(rune('0'+failAt)), func(t *testing.T) {
			f := newNativeEpochSourceStoreFixture(t)
			syncCalls, freshCalls := 0, 0
			f.store.sync = func(file *os.File) error {
				syncCalls++
				if syncCalls == failAt {
					return errors.New("injected sync failure")
				}
				return file.Sync()
			}
			f.store.fresh = func() (*hostcrypto.FreshNativeShareEpoch, error) {
				freshCalls++
				return hostcrypto.NewFreshNativeShareEpoch()
			}
			p, err := f.prepare()
			nativeEpochSourceReject(t, p, err)
			expectedFresh := 0
			if failAt >= 5 {
				expectedFresh = 1
			}
			if freshCalls != expectedFresh {
				t.Fatal("unexpected generation before sync failure")
			}
			f.store.sync = func(file *os.File) error { return file.Sync() }
			p, err = f.prepare()
			if failAt >= 3 && failAt <= 6 {
				nativeEpochSourceReject(t, p, err)
				if freshCalls != expectedFresh {
					t.Fatal("retry regenerated after uncertain pending publication")
				}
			} else {
				if err != nil {
					t.Fatal("safe retry failed", err)
				}
				if freshCalls != 1 {
					t.Fatal("retry minted extra prospective epochs")
				}
			}
		})
	}
}

func TestNativeShareEpochSourceStoreRechecksRevocationAndExpiry(t *testing.T) {
	for _, name := range []string{"revoked", "expired"} {
		for failAt := 1; failAt <= 4; failAt++ {
			t.Run(name+string(rune('0'+failAt)), func(t *testing.T) {
				f := newNativeEpochSourceStoreFixture(t)
				trusted := f.auth.Reauthorize
				calls := 0
				deadline, _ := time.Parse(time.RFC3339Nano, f.auth.Expected.Deadline)
				f.auth.Reauthorize = func(a NativeShareEpochSourceIntent) error {
					calls++
					if err := trusted(a); err != nil {
						return err
					}
					if calls == failAt {
						if name == "revoked" {
							return errors.New("authority revoked")
						}
						f.store.now = func() time.Time { return deadline }
					}
					return nil
				}
				p, err := f.prepare()
				nativeEpochSourceReject(t, p, err)
				if calls != failAt {
					t.Fatal("did not reach intended authorization boundary")
				}
			})
		}
	}
}

func TestNativeShareEpochSourceStoreIndependentRecipient(t *testing.T) {
	f := newNativeEpochSourceStoreFixture(t)
	recipientKey, recipientSigner, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := &f.auth.Prepared
	p.Prepare.Binding.InstanceID = "40000000-0000-4000-8000-000000000001"
	p.Prepare.Binding.NativeGeneration = "remote-recipient-generation"
	p.Subject.TenantID = "40000000-0000-4000-8000-000000000005"
	p.Subject.AccountID = "40000000-0000-4000-8000-000000000006"
	p.Subject.HostID = "40000000-0000-4000-8000-000000000002"
	p.Subject.NativeAdmissionID = "40000000-0000-4000-8000-000000000003"
	p.Subject.RunnerID = "40000000-0000-4000-8000-000000000004"
	p.Subject.BootID = "remote-recipient-boot"
	p.Subject.RunnerEpoch = f.now.Add(-time.Minute).Format(time.RFC3339Nano)
	p.BindingDigest, err = p.Digest()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := p.SignatureBytes()
	if err != nil {
		t.Fatal(err)
	}
	p.Signature = ed25519.Sign(recipientSigner, signed)
	f.auth.RecipientHostKey = recipientKey
	f.auth.Expected.BindingDigest = p.BindingDigest
	f.auth.Expected.TenantID = p.Subject.TenantID
	session := &f.auth.RecipientSession
	session.TenantID = string(p.Subject.TenantID)
	session.AccountID = string(p.Subject.AccountID)
	session.HostID = string(p.Subject.HostID)
	session.NativeAdmissionID = string(p.Subject.NativeAdmissionID)
	session.RunnerID = string(p.Subject.RunnerID)
	session.BootID = p.Subject.BootID
	session.RunnerEpoch = f.now.Add(-time.Minute)
	session.HostCredentialID = "remote-recipient-credential"
	pinned := f.auth.NativeShareEpochSourceIntent
	f.auth.Reauthorize = func(got NativeShareEpochSourceIntent) error {
		if !reflect.DeepEqual(got, pinned) {
			return errors.New("independent recipient authority changed")
		}
		return nil
	}
	if f.auth.Source.Subject.TenantID == p.Subject.TenantID {
		t.Fatal("fixture did not exercise a cross-tenant recipient")
	}
	result, err := f.prepare()
	if err != nil {
		t.Fatal(err)
	}
	if result.Metadata.BindingDigest != p.BindingDigest {
		t.Fatal("package omitted remote recipient binding")
	}
	retry, err := f.prepare()
	if err != nil || !reflect.DeepEqual(result, retry) {
		t.Fatal("remote recipient retry changed package", err)
	}
}

func TestNativeShareEpochSourceStoreCallbackCopies(t *testing.T) {
	f := newNativeEpochSourceStoreFixture(t)
	f.auth.RecipientSession.ProtocolFeatures = []string{"recipient-feature"}
	f.auth.SourceSession.ProtocolFeatures = []string{"source-feature"}
	pinned, err := json.Marshal(f.auth.NativeShareEpochSourceIntent)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	f.auth.Reauthorize = func(got NativeShareEpochSourceIntent) error {
		calls++
		raw, err := json.Marshal(got)
		if err != nil {
			return err
		}
		if !bytes.Equal(raw, pinned) {
			return errors.New("callback mutation leaked into retained intent")
		}
		got.Prepared.Signature[0] ^= 1
		got.RecipientHostKey[0] ^= 1
		got.CommittedVerifier[0] ^= 1
		got.RecipientSession.ProtocolFeatures[0] = "mutated-recipient-feature"
		got.SourceSession.ProtocolFeatures[0] = "mutated-source-feature"
		return nil
	}
	first, err := f.prepare()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(f.auth.NativeShareEpochSourceIntent)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, pinned) {
		t.Fatal("callback mutated caller authority")
	}
	again, err := f.prepare()
	if err != nil || !reflect.DeepEqual(first, again) {
		t.Fatal("callback mutation changed retry", err)
	}
	if calls < 5 {
		t.Fatal("callback copies did not exercise creation and retry boundaries")
	}
}

func TestNativeShareEpochSourceStoreFormatting(t *testing.T) {
	store := &NativeShareEpochSourceStore{signer: ed25519.PrivateKey(bytes.Repeat([]byte("synthetic-signer-sentinel"), 3))}
	for _, value := range []any{store, *store} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X"} {
			if got := fmt.Sprintf(verb, value); got != "NativeShareEpochSourceStore{closed}" {
				t.Fatal("store formatting did not return the fixed safe representation")
			}
		}
	}
}

func TestNativeShareEpochSourceStoreRejectsDuplicateEpochIDs(t *testing.T) {
	f := newNativeEpochSourceStoreFixture(t)
	if err := nativeShareEpochSourceAuthority(f.ring, f.auth.NativeShareEpochSourceIntent); err != nil {
		t.Fatal("valid committed authority rejected", err)
	}
	duplicate := f.ring.Epochs[0]
	duplicate.Key = make([]byte, 32)
	if _, err := rand.Read(duplicate.Key); err != nil {
		t.Fatal(err)
	}
	defer clear(duplicate.Key)
	f.ring.Epochs[0].State = hostcrypto.EpochRotated
	f.ring.Epochs = append(f.ring.Epochs, duplicate)
	// EpochPossessionSigner finds the rotated first entry, whose verifier still
	// matches the pin. A second active entry with the same ID must not authorize it.
	if err := nativeShareEpochSourceAuthority(f.ring, f.auth.NativeShareEpochSourceIntent); err == nil {
		t.Fatal("duplicate epoch IDs authorized the wrong active key")
	}
}

func TestNativeShareEpochSourceStorePublishedRetryRechecksAuthority(t *testing.T) {
	for _, name := range []string{"revoked", "verifier", "rotated"} {
		t.Run(name, func(t *testing.T) {
			f := newNativeEpochSourceStoreFixture(t)
			if _, err := f.prepare(); err != nil {
				t.Fatal(err)
			}
			f.store.fresh = func() (*hostcrypto.FreshNativeShareEpoch, error) {
				t.Fatal("published retry generated another epoch")
				return nil, errors.New("unexpected generation")
			}
			switch name {
			case "revoked":
				f.auth.Reauthorize = func(NativeShareEpochSourceIntent) error { return errors.New("revoked") }
			case "verifier":
				key, _, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				f.auth.CommittedVerifier = key
				f.auth.Reauthorize = func(NativeShareEpochSourceIntent) error { return nil }
			case "rotated":
				if _, err := f.ring.Rotate(f.now.Add(time.Second)); err != nil {
					t.Fatal(err)
				}
				if err := hostcrypto.SaveKeyring(filepath.Dir(f.holders.registry.root), f.ring); err != nil {
					t.Fatal(err)
				}
			}
			p, err := f.prepare()
			nativeEpochSourceReject(t, p, err)
		})
	}
}

func TestNativeShareEpochSourceStoreRejectsTamperedPublishedRecord(t *testing.T) {
	for _, name := range []string{"packageSignature", "sourceCiphertext", "sourceSignature"} {
		t.Run(name, func(t *testing.T) {
			f := newNativeEpochSourceStoreFixture(t)
			if _, err := f.prepare(); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(f.directory(), "source.json")
			var record nativeShareEpochSourceRecord
			if err := json.Unmarshal(nativeEpochRead(t, path), &record); err != nil {
				t.Fatal(err)
			}
			switch name {
			case "packageSignature":
				record.Package.Signature[0] ^= 1
			case "sourceCiphertext":
				record.SourceEnvelope.Wrapped.Ciphertext[0] ^= 1
			case "sourceSignature":
				record.SourceEnvelope.Signature[0] ^= 1
			}
			raw, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			f.store.fresh = func() (*hostcrypto.FreshNativeShareEpoch, error) {
				t.Fatal("tampered published retry regenerated an epoch")
				return nil, errors.New("unexpected generation")
			}
			p, err := f.prepare()
			nativeEpochSourceReject(t, p, err)
		})
	}
}
