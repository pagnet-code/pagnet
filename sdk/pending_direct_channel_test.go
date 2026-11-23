//go:build linux || darwin

package sdk

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
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
	if err := k.markDirectChannelActive(directAuthoritativeStatus{"ACTIVE", r.ChannelID, r.Descriptor}); err != nil {
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
	for _, status := range []directAuthoritativeStatus{{"PENDING", r.ChannelID, r.Descriptor}, {"ACTIVE", directB64(make([]byte, 32)), r.Descriptor}, {"ACTIVE", r.ChannelID, append(append([]byte(nil), r.Descriptor...), ' ')}} {
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
	d.Limits.MaxAsksPerDay++ // Channel ID intentionally excludes policy.
	changed.Descriptor, _ = json.Marshal(d)
	changed.DescriptorHash = sha256.Sum256(changed.Descriptor)
	var pkg directPackage
	json.Unmarshal(changed.Publication, &pkg)
	pkg.Descriptor = changed.Descriptor
	changed.Publication, _ = json.Marshal(pkg)
	if _, err := k.storePendingDirectChannel(changed); err == nil {
		t.Fatal("changed complete binding accepted")
	}
	peer, err := pendingDirectChannelFor(p, nil)
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
	ask, err := s.seal("ASK", "ask-1", "root", nil, []byte("secret question"), now)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := p.seal("REPLY", "reply-1", "root", ask, []byte("secret answer"), now)
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"S", "P"} {
		t.Run(role, func(t *testing.T) {
			m, pub, wire := s, publication, ask
			if role == "P" {
				m, pub, wire = p, nil, reply
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
				changed, err = s.seal("ASK", "ask-1", "root", nil, []byte("different question"), now)
			} else {
				changed, err = p.seal("REPLY", "reply-1", "root", ask, []byte("different answer"), now)
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
				next, err = s.seal("ASK", "ask-2", "root", nil, []byte("another"), now)
			} else {
				next, err = p.seal("REPLY", "reply-2", "root", ask, []byte("another"), now)
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
			wire, err := s.seal("ASK", fmt.Sprintf("ask-%d", i), "root", nil, []byte("secret"), now)
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
