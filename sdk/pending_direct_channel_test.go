//go:build linux || darwin

package sdk

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/pagnet-code/pagnet/transport"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
)

func journalFixture(t *testing.T) (*keyring, pendingDirectChannel, *directMaterial, *directMaterial, []byte) {
	t.Helper()
	k, err := newKeyring(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s, p, publication, _ := directMaterials(t)
	r, err := pendingDirectChannelFor(s, publication)
	if err != nil {
		t.Fatal(err)
	}
	return k, r, s, p, publication
}
func storeJournal(t *testing.T, k *keyring, r pendingDirectChannel) pendingDirectChannel {
	t.Helper()
	got, err := k.storePendingDirectChannel(r)
	if err != nil {
		t.Fatal(err)
	}
	return got
}
func activateJournal(t *testing.T, k *keyring, r pendingDirectChannel) {
	t.Helper()
	if err := k.markDirectChannelActive(directAuthoritativeStatus{"ACTIVE", r.ChannelID, r.Descriptor, sha256.Sum256(r.Publication)}); err != nil {
		t.Fatal(err)
	}
}
func TestPendingDirectRestartRetryAndNoEnrollment(t *testing.T) {
	k, r, s, _, _ := journalFixture(t)
	if err := k.StoreEpoch(s.descriptor.NetworkID, "old-epoch", [32]byte{1}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := k.ActiveEpoch(s.descriptor.NetworkID); err != nil {
		t.Fatal(err)
	}
	storeJournal(t, k, r)
	// Retry randomized source material must return the original material.
	retry := r
	retry.ChannelKey = bytes.Repeat([]byte{9}, 32)
	var pkg directPackage
	json.Unmarshal(retry.Publication, &pkg)
	pkg.Enc = directB64(bytes.Repeat([]byte{8}, 32))
	retry.Publication, _ = json.Marshal(pkg)
	reopened := &keyring{root: k.root}
	got := storeJournal(t, reopened, retry)
	if !reflect.DeepEqual(got, r) {
		t.Fatal("retry replaced original material")
	}
	for _, status := range []directAuthoritativeStatus{{"PENDING", r.ChannelID, r.Descriptor, sha256.Sum256(r.Publication)}, {"ACTIVE", directB64(make([]byte, 32)), r.Descriptor, sha256.Sum256(r.Publication)}, {"ACTIVE", r.ChannelID, append(append([]byte(nil), r.Descriptor...), ' '), sha256.Sum256(r.Publication)}, {"ACTIVE", r.ChannelID, r.Descriptor, [32]byte{}}} {
		if reopened.markDirectChannelActive(status) == nil {
			t.Fatal("inexact ACTIVE accepted")
		}
	}
	activateJournal(t, reopened, r)
	got, err := reopened.loadPendingDirectChannel(r.ChannelID)
	if err != nil || !got.Active {
		t.Fatalf("active: %v", err)
	}
	if _, id, err := k.ActiveEpoch(s.descriptor.NetworkID); err != nil || id != "old-epoch" {
		t.Fatalf("network keyring changed: %s %v", id, err)
	}
	if _, err := os.Stat(filepath.Join(k.root, "networks", s.descriptor.NetworkID, "epoch-"+s.descriptor.EpochID+".key")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("direct key enrolled")
	}
	if _, err := os.Stat(filepath.Join(k.root, "pending-pairs")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("sharing pair store touched")
	}
}
func TestPendingDirectBindingConflicts(t *testing.T) {
	k, r, _, p, _ := journalFixture(t)
	storeJournal(t, k, r)
	changed := r
	var d directDescriptor
	json.Unmarshal(changed.Descriptor, &d)
	d.Limits.MaxMessagesPerDay-- // Channel ID intentionally excludes policy.
	changed.Descriptor, _ = json.Marshal(d)
	changed.DescriptorHash = sha256.Sum256(changed.Descriptor)
	var pkg directPackage
	json.Unmarshal(changed.Publication, &pkg)
	pkg.Descriptor = d
	changed.Publication, _ = json.Marshal(pkg)
	if _, err := k.storePendingDirectChannel(changed); err == nil {
		t.Fatal("changed complete binding accepted")
	}
	peer, err := pendingDirectChannelFor(p, r.Publication)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = k.storePendingDirectChannel(peer); err == nil {
		t.Fatal("role conflict accepted")
	}
	// A peer must retain the received exact key, rather than accept a replacement.
	kp, _ := newKeyring(t.TempDir())
	storeJournal(t, kp, peer)
	peer.ChannelKey = bytes.Repeat([]byte{7}, 32)
	if _, err = kp.storePendingDirectChannel(peer); err == nil {
		t.Fatal("peer key conflict accepted")
	}
}
func TestPendingDirectTamperMissingAndPermissions(t *testing.T) {
	cases := []string{"missing-record", "missing-directory", "missing-index", "missing-auth", "bad-record-MAC", "bad-index-MAC", "record-mode", "directory-mode", "store-mode", "key-mode", "lock-mode"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			k, r, _, _, _ := journalFixture(t)
			storeJournal(t, k, r)
			dir := k.pendingDirectChannelDir(r.ChannelID)
			base := filepath.Dir(dir)
			for path, want := range map[string]os.FileMode{base: 0700, dir: 0700, filepath.Join(dir, "record.json"): 0600, filepath.Join(base, "auth.key"): 0600, filepath.Join(base, "index.json"): 0600, filepath.Join(k.root, "pending-direct-channels.lock"): 0600} {
				info, err := os.Stat(path)
				if err != nil || info.Mode().Perm() != want {
					t.Fatalf("permissions %s: %v", path, err)
				}
			}
			switch name {
			case "missing-record":
				os.Remove(filepath.Join(dir, "record.json"))
			case "missing-directory":
				os.RemoveAll(dir)
			case "missing-index":
				os.Remove(filepath.Join(base, "index.json"))
			case "missing-auth":
				os.Remove(filepath.Join(base, "auth.key"))
			case "bad-record-MAC":
				b, _ := os.ReadFile(filepath.Join(dir, "record.json"))
				var f pendingDirectChannelFile
				json.Unmarshal(b, &f)
				f.Record.ChannelKey[0] ^= 1
				b, _ = json.Marshal(f)
				os.WriteFile(filepath.Join(dir, "record.json"), b, 0600)
			case "bad-index-MAC":
				path := filepath.Join(base, "index.json")
				b, _ := os.ReadFile(path)
				var f pendingDirectChannelIndex
				json.Unmarshal(b, &f)
				f.MAC[0] ^= 1
				b, _ = json.Marshal(f)
				os.WriteFile(path, b, 0600)
			case "record-mode":
				os.Chmod(filepath.Join(dir, "record.json"), 0644)
			case "directory-mode":
				os.Chmod(dir, 0755)
			case "store-mode":
				os.Chmod(base, 0755)
			case "key-mode":
				os.Chmod(filepath.Join(base, "auth.key"), 0644)
			case "lock-mode":
				os.Chmod(filepath.Join(k.root, "pending-direct-channels.lock"), 0644)
			}
			restarted := &keyring{root: k.root}
			if _, err := restarted.loadPendingDirectChannel(r.ChannelID); err == nil {
				t.Fatal("unsafe load succeeded")
			}
			if _, err := restarted.storePendingDirectChannel(r); err == nil {
				t.Fatal("unsafe state regenerated")
			}
		})
	}
}
func TestPendingDirectCrashBoundaries(t *testing.T) {
	for _, point := range []string{"reservation", "child", "record"} {
		t.Run(point, func(t *testing.T) {
			k, r, _, _, _ := journalFixture(t)
			// Initialize store so injection targets channel creation only.
			unlock, err := k.lockPendingDirectChannels()
			if err != nil {
				t.Fatal(err)
			}
			unlock()
			dir := k.pendingDirectChannelDir(r.ChannelID)
			injected := false
			k.pendingDirectChannelSyncDir = func(path string) error {
				fail := false
				if point == "reservation" && path == filepath.Dir(dir) {
					b, _ := os.ReadFile(filepath.Join(path, "index.json"))
					var f pendingDirectChannelIndex
					json.Unmarshal(b, &f)
					_, exists := f.Bindings[r.ChannelID]
					_, childErr := os.Stat(dir)
					fail = exists && errors.Is(childErr, os.ErrNotExist)
				}
				if point == "child" && path == filepath.Dir(dir) {
					_, err := os.Stat(dir)
					fail = err == nil
				}
				if point == "record" && path == dir {
					fail = true
				}
				if fail {
					injected = true
					return errors.New("simulated crash")
				}
				return syncPairDir(path)
			}
			if _, err := k.storePendingDirectChannel(r); err == nil || !injected {
				t.Fatalf("crash not injected: %v", err)
			}
			restarted := &keyring{root: k.root}
			got, err := restarted.storePendingDirectChannel(r)
			if point == "record" {
				if err != nil || !reflect.DeepEqual(got, r) {
					t.Fatalf("complete renamed record not recovered: %v", err)
				}
			} else if err == nil {
				t.Fatal("incomplete reserved record regenerated")
			}
		})
	}
}
func TestPendingDirectConcurrentWrites(t *testing.T) {
	k, _ := newKeyring(t.TempDir())
	d, raw, private, _, now := directFixture(t)
	const count = 12
	results := make(chan pendingDirectChannel, count)
	errs := make(chan error, count)
	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			m, publication, err := directPrepare(raw, d, private, now)
			if err != nil {
				errs <- err
				results <- pendingDirectChannel{}
				return
			}
			candidate, err := pendingDirectChannelFor(m, publication)
			if err != nil {
				errs <- err
				results <- pendingDirectChannel{}
				return
			}
			independent := &keyring{root: k.root}
			got, err := independent.storePendingDirectChannel(candidate)
			results <- got
			errs <- err
		}(i)
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var first *pendingDirectChannel
	for got := range results {
		if first == nil {
			copy := got
			first = &copy
		} else if !reflect.DeepEqual(got, *first) {
			t.Fatal("concurrent retry changed material")
		}
	}
}
func TestDirectJournalOutboxASKAndREPLY(t *testing.T) {
	s, p, publication, now := directMaterials(t)
	ask, err := s.seal("ASK", directTestAskID, directTestAskID, nil, []byte("secret question"), now)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := p.seal("REPLY", directTestReplyID, directTestAskID, ask, []byte("secret answer"), now)
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"S", "P"} {
		t.Run(role, func(t *testing.T) {
			m, pub, wire := s, publication, ask
			if role == "P" {
				m, pub, wire = p, publication, reply
			}
			k, _ := newKeyring(t.TempDir())
			r, err := pendingDirectChannelFor(m, pub)
			if err != nil {
				t.Fatal(err)
			}
			storeJournal(t, k, r)
			if _, err := k.storeDirectOutgoing(r.ChannelID, wire); err == nil {
				t.Fatal("pending channel sent")
			}
			activateJournal(t, k, r)
			got, err := k.storeDirectOutgoing(r.ChannelID, wire)
			if err != nil || !bytes.Equal(got, wire) {
				t.Fatalf("outbox: %v", err)
			}
			restarted := &keyring{root: k.root}
			got, err = restarted.storeDirectOutgoing(r.ChannelID, wire)
			if err != nil || !bytes.Equal(got, wire) {
				t.Fatalf("retry: %v", err)
			}
			var changed []byte
			if role == "S" {
				changed, err = s.seal("ASK", directTestAskID, directTestAskID, nil, []byte("different question"), now)
			} else {
				changed, err = p.seal("REPLY", directTestReplyID, directTestAskID, ask, []byte("different answer"), now)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err = restarted.storeDirectOutgoing(r.ChannelID, changed); err == nil {
				t.Fatal("changed message ID bytes accepted")
			}
			if _, err = restarted.storeDirectOutgoing(r.ChannelID, []byte("plaintext")); err == nil {
				t.Fatal("plaintext accepted")
			}
			b, _ := os.ReadFile(filepath.Join(k.pendingDirectChannelDir(r.ChannelID), "record.json"))
			for _, plaintext := range []string{"secret question", "secret answer", "different question", "different answer"} {
				if bytes.Contains(b, []byte(plaintext)) {
					t.Fatal("plaintext persisted")
				}
			}
			// Crash after rename, before fsync must recover exact original wire.
			var next []byte
			if role == "S" {
				next, err = s.seal("ASK", directTestSecondAskID, directTestSecondAskID, nil, []byte("another"), now)
			} else {
				next, err = p.seal("REPLY", directTestSecondReplyID, directTestAskID, ask, []byte("another"), now)
			}
			if err != nil {
				t.Fatal(err)
			}
			restarted.pendingDirectChannelSyncDir = func(path string) error {
				if path == k.pendingDirectChannelDir(r.ChannelID) {
					b, _ := os.ReadFile(filepath.Join(path, "record.json"))
					var f pendingDirectChannelFile
					json.Unmarshal(b, &f)
					if len(f.Record.Outbox) == 2 {
						return errors.New("crash after rename")
					}
				}
				return syncPairDir(path)
			}
			if _, err = restarted.storeDirectOutgoing(r.ChannelID, next); err == nil {
				t.Fatal("crash not injected")
			}
			recovered := &keyring{root: k.root}
			got, err = recovered.storeDirectOutgoing(r.ChannelID, next)
			if err != nil || !bytes.Equal(got, next) {
				t.Fatalf("outbox recovery: %v", err)
			}
		})
	}
}
func TestDirectJournalConcurrentOutbox(t *testing.T) {
	k, r, s, _, _ := journalFixture(t)
	storeJournal(t, k, r)
	activateJournal(t, k, r)
	_, _, _, now := directMaterials(t)
	const count = 8
	var wg sync.WaitGroup
	errs := make(chan error, count)
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := fmt.Sprintf("%08x-1111-4111-8111-111111111111", i+1)
			wire, err := s.seal("ASK", id, id, nil, []byte("secret"), now)
			if err == nil {
				_, err = (&keyring{root: k.root}).storeDirectOutgoing(r.ChannelID, wire)
			}
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	got, err := k.loadPendingDirectChannel(r.ChannelID)
	if err != nil || len(got.Outbox) != count {
		t.Fatalf("lost outbox writes: %d %v", len(got.Outbox), err)
	}
}

func TestPendingDirectPeerRequiresAcceptedPublication(t *testing.T) {
	s, p, publication, _ := directMaterials(t)
	for _, role := range []string{"S", "P"} {
		t.Run(role, func(t *testing.T) {
			m := s
			if role == "P" {
				m = p
			}
			if _, err := pendingDirectChannelFor(m, publication); err != nil {
				t.Fatal(err)
			}
			if _, err := pendingDirectChannelFor(m, nil); err == nil {
				t.Fatal("missing accepted publication allowed")
			}
			var pkg directPackage
			json.Unmarshal(publication, &pkg)
			pkg.Ciphertext = directB64(bytes.Repeat([]byte{7}, 48))
			changed, _ := json.Marshal(pkg)
			if _, err := pendingDirectChannelFor(m, changed); err == nil {
				t.Fatal("unopened publication allowed")
			}
			uninstalled, err := directMaterialFor(m.descriptor, rDescriptorBytes(t, pkg.Descriptor), m.key[:], role)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := pendingDirectChannelFor(uninstalled, publication); err == nil {
				t.Fatal("uninstalled material accepted")
			}
		})
	}
}

func TestPendingDirectActiveRequiresExactAuthoritativePublication(t *testing.T) {
	s, p, publication, _ := directMaterials(t)
	for _, role := range []string{"S", "P"} {
		t.Run(role, func(t *testing.T) {
			m := s
			if role == "P" {
				m = p
			}
			k, _ := newKeyring(t.TempDir())
			r, err := pendingDirectChannelFor(m, publication)
			if err != nil {
				t.Fatal(err)
			}
			storeJournal(t, k, r)
			status := directAuthoritativeStatus{"ACTIVE", r.ChannelID, r.Descriptor, sha256.Sum256([]byte("different exact publication"))}
			if err := k.markDirectChannelActive(status); err == nil {
				t.Fatal("wrong publication digest activated")
			}
			got, err := k.loadPendingDirectChannel(r.ChannelID)
			if err != nil || got.Active {
				t.Fatalf("wrong publication changed marker: %v", err)
			}
			status.PublicationHash = sha256.Sum256(publication)
			if err := k.markDirectChannelActive(status); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filepath.Join(k.pendingDirectChannelDir(r.ChannelID), "record.json")); err != nil {
				t.Fatal(err)
			}
			if err := (&keyring{root: k.root}).markDirectChannelActive(status); err == nil {
				t.Fatal("missing local material activated")
			}
		})
	}
}

func TestPendingDirectRolledBackReservationNeedsAuthoritativePublication(t *testing.T) {
	k, _ := newKeyring(t.TempDir())
	d, raw, private, _, now := directFixture(t)
	unlock, err := k.lockPendingDirectChannels()
	if err != nil {
		t.Fatal(err)
	}
	unlock()
	indexPath := filepath.Join(k.root, "pending-direct-channels", "index.json")
	oldIndex, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatal(err)
	}
	m, publication, err := directPrepare(raw, d, private, now)
	if err != nil {
		t.Fatal(err)
	}
	original, err := pendingDirectChannelFor(m, publication)
	if err != nil {
		t.Fatal(err)
	}
	storeJournal(t, k, original)
	authoritative := directAuthoritativeStatus{"ACTIVE", original.ChannelID, original.Descriptor, sha256.Sum256(publication)}
	// Replay a valid older authenticated index and remove its child. Local MACs
	// cannot distinguish this from first reservation, so remote status must anchor
	// the original publication before the regenerated candidate can become active.
	if err := os.WriteFile(indexPath, oldIndex, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(k.pendingDirectChannelDir(original.ChannelID)); err != nil {
		t.Fatal(err)
	}
	replacementMaterial, replacementPublication, err := directPrepare(raw, d, private, now)
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := pendingDirectChannelFor(replacementMaterial, replacementPublication)
	if err != nil {
		t.Fatal(err)
	}
	restarted := &keyring{root: k.root}
	got := storeJournal(t, restarted, replacement)
	if bytes.Equal(got.Publication, publication) {
		t.Fatal("fixture did not generate different material")
	}
	if err := restarted.markDirectChannelActive(authoritative); err == nil {
		t.Fatal("regenerated publication activated against old authoritative status")
	}
	got, err = restarted.loadPendingDirectChannel(original.ChannelID)
	if err != nil || got.Active {
		t.Fatalf("replacement became active: %v", err)
	}
}

func TestDirectJournalRecordRollbackRequiresRemoteWireConflict(t *testing.T) {
	k, r, s, _, _ := journalFixture(t)
	_, _, _, now := directMaterials(t)
	storeJournal(t, k, r)
	activateJournal(t, k, r)
	path := filepath.Join(k.pendingDirectChannelDir(r.ChannelID), "record.json")
	oldRecord, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := s.seal("ASK", directTestAskID, directTestAskID, nil, []byte("original"), now)
	if err != nil {
		t.Fatal(err)
	}
	retainedWire, err := k.storeDirectOutgoing(r.ChannelID, wire)
	if err != nil {
		t.Fatal(err)
	}
	// Model the remote immutable wire contract. The remote identity stays the
	// same across local rollback; byte disagreement is terminal, never a new ID.
	remoteRetry := func(id string, candidate []byte) error {
		if id != directTestAskID || !bytes.Equal(retainedWire, candidate) {
			return errors.New("remote immutable wire conflict")
		}
		return nil
	}
	if err := os.WriteFile(path, oldRecord, 0600); err != nil {
		t.Fatal(err)
	}
	restarted := &keyring{root: k.root}
	changed, err := s.seal("ASK", directTestAskID, directTestAskID, nil, []byte("changed after rollback"), now)
	if err != nil {
		t.Fatal(err)
	}
	local, err := restarted.storeDirectOutgoing(r.ChannelID, changed)
	if err != nil {
		t.Fatal(err)
	}
	if err := remoteRetry(directTestAskID, local); err == nil {
		t.Fatal("rollback retry treated as a new send")
	}
	if err := remoteRetry(directTestAskID, wire); err != nil {
		t.Fatal("exact remote retry rejected")
	}
}

func rDescriptorBytes(t *testing.T, d directDescriptor) []byte {
	t.Helper()
	raw, err := d.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestPendingDirectReadinessReloadExactPublication(t *testing.T) {
	s, p, publication, now := directMaterials(t)
	for _, m := range []*directMaterial{s, p} {
		t.Run(m.role, func(t *testing.T) {
			k, err := newKeyring(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			r, err := pendingDirectChannelFor(m, publication)
			if err != nil {
				t.Fatal(err)
			}
			storeJournal(t, k, r)
			challenge := directReadinessChallenge(m, now)
			raw, err := challenge.CanonicalBytes()
			if err != nil {
				t.Fatal(err)
			}
			original, err := m.readinessProof(raw, challenge.CredentialID, now)
			if err != nil {
				t.Fatal(err)
			}
			got, err := (&keyring{root: k.root}).loadPendingDirectChannel(r.ChannelID)
			if err != nil {
				t.Fatal(err)
			}
			restored, err := got.material()
			if err != nil {
				t.Fatal(err)
			}
			proof, err := restored.readinessProof(raw, challenge.CredentialID, now)
			if err != nil || !bytes.Equal(proof, original) || restored.publicationHash != m.publicationHash || !bytes.Equal(got.Publication, publication) {
				t.Fatalf("exact publication readiness reload: %v", err)
			}
			// Canonical publication alone is insufficient when its descriptor differs.
			changed := got
			var pkg directPackage
			if err := json.Unmarshal(changed.Publication, &pkg); err != nil {
				t.Fatal(err)
			}
			pkg.Descriptor.Limits.MaxMessagesPerDay--
			changed.Publication, _ = json.Marshal(pkg)
			if _, err := changed.material(); err == nil {
				t.Fatal("restored publication hash for inexact descriptor")
			}
			changed = got
			changed.Publication = append(append([]byte(nil), changed.Publication...), ' ')
			if _, err := changed.material(); err == nil {
				t.Fatal("restored noncanonical publication")
			}
			changed = got
			changed.Publication = nil
			if _, err := changed.material(); err == nil {
				t.Fatal("restored absent publication")
			}
		})
	}
}

func TestPendingDirectV1ReservedRecordRemainsUntouched(t *testing.T) {
	k, r, s, _, _ := journalFixture(t)
	// Install a correctly MACed historical record under its V1 reservation.
	// The disk record/index format is retained; the descriptor is genuinely V1.
	legacy := r
	legacy.Descriptor = directLegacyDescriptor(t, s.descriptor)
	legacy.DescriptorHash = sha256.Sum256(legacy.Descriptor)
	var identity struct {
		Domain        string          `json:"domain"`
		ParentGrantID string          `json:"parentGrantId"`
		Generation    string          `json:"generation"`
		S             json.RawMessage `json:"s"`
		P             json.RawMessage `json:"p"`
		EpochID       string          `json:"epochId"`
	}
	if err := json.Unmarshal(legacy.Descriptor, &identity); err != nil {
		t.Fatal(err)
	}
	identity.Domain = "pagnet/direct_ask_reply_v1/channel-id"
	identityRaw, _ := json.Marshal(identity)
	identityHash := sha256.Sum256(identityRaw)
	legacy.ChannelID = directB64(identityHash[:])
	unlock, err := k.lockPendingDirectChannels()
	if err != nil {
		t.Fatal(err)
	}
	index, key, err := k.readPendingDirectChannelIndex()
	if err != nil {
		unlock()
		t.Fatal(err)
	}
	index[legacy.ChannelID] = true
	if err := k.writePendingDirectChannelIndex(index, key); err != nil {
		unlock()
		t.Fatal(err)
	}
	if err := os.Mkdir(k.pendingDirectChannelDir(legacy.ChannelID), 0700); err != nil {
		unlock()
		t.Fatal(err)
	}
	unlock()

	var pub struct {
		Descriptor json.RawMessage `json:"descriptor"`
		Enc        string          `json:"enc"`
		Ciphertext string          `json:"ciphertext"`
	}
	if err := json.Unmarshal(r.Publication, &pub); err != nil {
		t.Fatal(err)
	}
	pub.Descriptor = legacy.Descriptor
	legacy.Publication, _ = json.Marshal(pub)
	if err := k.writePendingDirectChannel(legacy, key); err != nil {
		t.Fatal(err)
	}
	paths := []string{filepath.Join(k.pendingDirectChannelDir(legacy.ChannelID), "record.json"), filepath.Join(k.root, "pending-direct-channels", "index.json"), filepath.Join(k.root, "pending-direct-channels", "auth.key")}
	before := make(map[string][]byte)
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		before[path] = raw
	}
	restarted := &keyring{root: k.root}
	if _, err := restarted.loadPendingDirectChannel(legacy.ChannelID); err == nil {
		t.Fatal("loaded V1 reserved record")
	}
	candidate := r
	candidate.ChannelID = legacy.ChannelID
	if _, err := restarted.storePendingDirectChannel(candidate); err == nil {
		t.Fatal("regenerated V1 reservation with V2 material")
	}
	if _, err := restarted.storePendingDirectChannel(legacy); err == nil {
		t.Fatal("rewrote V1 reserved record")
	}
	for _, path := range paths {
		after, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(after, before[path]) {
			t.Fatalf("legacy disk data changed at %s: %v", path, err)
		}
	}
}

func TestDirectJournalRejectsIncompatibleOutboxWithoutMutation(t *testing.T) {
	for _, mode := range []string{"unversioned", "wrong-role", "message-id", "ciphertext"} {
		t.Run(mode, func(t *testing.T) {
			k, r, s, _, _ := journalFixture(t)
			_, _, _, now := directMaterials(t)
			const id = "11111111-1111-4111-8111-111111111111"
			wire, err := s.seal("ASK", id, id, nil, nil, now)
			if err != nil {
				t.Fatal(err)
			}
			storeJournal(t, k, r)
			activateJournal(t, k, r)
			stored, err := k.loadPendingDirectChannel(r.ChannelID)
			if err != nil {
				t.Fatal(err)
			}
			w, err := transport.DecodeDirectChannelMessageV2(wire)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "unversioned":
				// Retain the exact pre-versioned shape, including embedded endpoints.
				old := struct {
					Header struct {
						Domain         string      `json:"domain"`
						Kind           string      `json:"kind"`
						ChannelID      string      `json:"channelId"`
						DescriptorHash string      `json:"descriptorHash"`
						MessageID      string      `json:"messageId"`
						RootID         string      `json:"rootId"`
						From           directParty `json:"from"`
						To             directParty `json:"to"`
						AskID          string      `json:"askId"`
						AskWireHash    string      `json:"askWireHash"`
					} `json:"header"`
					Nonce      string `json:"nonce"`
					Ciphertext string `json:"ciphertext"`
				}{}
				old.Header.Domain, old.Header.Kind = w.Header.Domain, w.Header.Kind
				old.Header.ChannelID, old.Header.DescriptorHash = w.Header.ChannelID, w.Header.DescriptorHash
				old.Header.MessageID, old.Header.RootID = id, id
				old.Header.From, old.Header.To = s.descriptor.S, s.descriptor.P
				old.Nonce = w.Nonce
				aead, err := s.aead("ASK")
				if err != nil {
					t.Fatal(err)
				}
				nonce, _ := directBinary(old.Nonce, 12)
				aad, _ := json.Marshal(old.Header)
				old.Ciphertext = directB64(aead.Seal(nil, nonce, nil, aad))
				wire, _ = json.Marshal(old)
			case "wrong-role":
				w.Header.SenderRole = "P"
				wire, _ = json.Marshal(w)
			case "message-id":
				w.Header.MessageID = "22222222-2222-4222-8222-222222222222"
				w.Header.RootID = w.Header.MessageID
				wire, _ = json.Marshal(w)
			case "ciphertext":
				ct, _ := directBinary(w.Ciphertext, -1)
				ct[0] ^= 1
				w.Ciphertext = directB64(ct)
				wire, _ = w.CanonicalBytes()
			}
			if _, err := k.storeDirectOutgoing(r.ChannelID, wire); err == nil {
				t.Fatal("invalid outgoing wire stored")
			}
			stored.Outbox[id] = wire
			_, key, err := k.readPendingDirectChannelIndex()
			if err != nil {
				t.Fatal(err)
			}
			if err := k.writePendingDirectChannel(stored, key); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(k.pendingDirectChannelDir(r.ChannelID), "record.json")
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			restarted := &keyring{root: k.root}
			if _, err := restarted.loadPendingDirectChannel(r.ChannelID); err == nil {
				t.Fatal("invalid outbox reloaded")
			}
			if _, err := restarted.storeDirectOutgoing(r.ChannelID, wire); err == nil {
				t.Fatal("invalid outbox retried")
			}
			if _, err := restarted.storePendingDirectChannel(r); err == nil {
				t.Fatal("invalid record regenerated")
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("incompatible pending record changed")
			}
		})
	}
}
