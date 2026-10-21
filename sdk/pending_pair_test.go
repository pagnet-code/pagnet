//go:build linux || darwin

package sdk

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
)

func testPendingPair() pendingPairEpoch {
	descriptor := []byte(`{"version":1,"immutable":"exact bytes"}`)
	return pendingPairEpoch{GrantID: "grant", Generation: 1, NetworkID: "net", EpochID: "epoch-2", Descriptor: descriptor, DescriptorHash: sha256.Sum256(descriptor), EpochKey: bytes.Repeat([]byte{3}, 32), Publication: []byte("exact AuthHPKE package"), IssuerFingerprint: sha256.Sum256([]byte("issuer")), RecipientFingerprint: sha256.Sum256([]byte("recipient"))}
}

func TestPendingPairRestartRetryAndActivation(t *testing.T) {
	dir := t.TempDir()
	k, _ := newKeyring(dir)
	p := testPendingPair()
	if err := k.StoreEpoch(p.NetworkID, "epoch-1", [32]byte{1}); err != nil {
		t.Fatal(err)
	}
	if _, err := k.storePendingPairEpoch(p); err != nil {
		t.Fatal(err)
	}
	if got := fileMode(t, filepath.Join(k.pendingPairDir(p.GrantID, p.Generation), "record.json")); got != 0600 {
		t.Fatalf("mode %o", got)
	}
	// Warm cache must still choose the enrolled epoch.
	if _, id, err := k.ActiveEpoch(p.NetworkID); err != nil || id != "epoch-1" {
		t.Fatalf("pending epoch became active: %q, %v", id, err)
	}
	k, _ = newKeyring(dir)
	loaded, err := k.loadPendingPairEpoch(p.GrantID, p.Generation)
	if err != nil || !reflect.DeepEqual(loaded, p) {
		t.Fatalf("restart did not preserve record: %v", err)
	}
	retry := p
	retry.EpochKey = bytes.Repeat([]byte{9}, 32)
	retry.Publication = []byte("new randomized package")
	got, err := k.storePendingPairEpoch(retry)
	if err != nil || !reflect.DeepEqual(got, p) {
		t.Fatalf("retry changed durable bytes: %v", err)
	}
	if _, id, err := k.ActiveEpoch(p.NetworkID); err != nil || id != "epoch-1" {
		t.Fatalf("restart exposed pending epoch: %q %v", id, err)
	}
	if err := k.activatePendingPairEpoch(p.GrantID, p.Generation, p.NetworkID, p.EpochID, [32]byte{}); err == nil {
		t.Fatal("activated mismatched descriptor")
	}
	if err := k.activatePendingPairEpoch(p.GrantID, p.Generation, p.NetworkID, p.EpochID, p.DescriptorHash); err != nil {
		t.Fatal(err)
	}
	if err := k.activatePendingPairEpoch(p.GrantID, p.Generation, p.NetworkID, p.EpochID, p.DescriptorHash); err != nil {
		t.Fatal("activation retry:", err)
	}
	k, _ = newKeyring(dir)
	key, id, err := k.ActiveEpoch(p.NetworkID)
	if err != nil || id != p.EpochID || !bytes.Equal(key[:], p.EpochKey) {
		t.Fatalf("activation missing: %q %v", id, err)
	}
}

func TestPendingPairBindingConflicts(t *testing.T) {
	mutations := map[string]func(*pendingPairEpoch){
		"descriptor": func(p *pendingPairEpoch) {
			p.Descriptor = []byte("changed")
			p.DescriptorHash = sha256.Sum256(p.Descriptor)
		},
		"network":   func(p *pendingPairEpoch) { p.NetworkID = "other" },
		"epoch":     func(p *pendingPairEpoch) { p.EpochID = "other" },
		"issuer":    func(p *pendingPairEpoch) { p.IssuerFingerprint[0]++ },
		"recipient": func(p *pendingPairEpoch) { p.RecipientFingerprint[0]++ },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			k := newTestKeyring(t)
			p := testPendingPair()
			if _, err := k.storePendingPairEpoch(p); err != nil {
				t.Fatal(err)
			}
			mutate(&p)
			if _, err := k.storePendingPairEpoch(p); err == nil {
				t.Fatal("binding conflict accepted")
			}
		})
	}
}

func TestPendingPairCorruptOrMissingFailsClosed(t *testing.T) {
	for _, kind := range []string{"missing", "truncated", "checksum", "permissions", "descriptor_hash"} {
		t.Run(kind, func(t *testing.T) {
			k := newTestKeyring(t)
			p := testPendingPair()
			if _, err := k.storePendingPairEpoch(p); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(k.pendingPairDir(p.GrantID, p.Generation), "record.json")
			switch kind {
			case "missing":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "truncated":
				if err := os.WriteFile(path, []byte("{"), 0600); err != nil {
					t.Fatal(err)
				}
			case "permissions":
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			default:
				b, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				var f pendingPairFile
				if err := json.Unmarshal(b, &f); err != nil {
					t.Fatal(err)
				}
				if kind == "checksum" {
					f.Record.Publication[0]++
				} else {
					f.Record.DescriptorHash[0]++
					payload, _ := json.Marshal(f.Record)
					key, keyErr := readPrivatePairFile(filepath.Join(k.root, "pending-pairs", "auth.key"))
					if keyErr != nil {
						t.Fatal(keyErr)
					}
					f.MAC = pendingPairMAC(key, "record", payload)
				}
				b, _ = json.Marshal(f)
				if err := os.WriteFile(path, b, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := k.loadPendingPairEpoch(p.GrantID, p.Generation); err == nil {
				t.Fatal("loaded missing/corrupt record")
			}
			if _, err := k.storePendingPairEpoch(p); err == nil {
				t.Fatal("regenerated missing/corrupt record")
			}
			if err := k.activatePendingPairEpoch(p.GrantID, p.Generation, p.NetworkID, p.EpochID, p.DescriptorHash); err == nil {
				t.Fatal("activated missing/corrupt record")
			}
			if _, _, err := k.ActiveEpoch(p.NetworkID); err == nil {
				t.Fatal("corrupt record leaked to active epochs")
			}
		})
	}
	k := newTestKeyring(t)
	if _, err := k.loadPendingPairEpoch("unknown", 1); err == nil {
		t.Fatal("missing record accepted")
	}
}

func TestPendingPairRecipient(t *testing.T) {
	k := newTestKeyring(t)
	p := testPendingPair()
	p.Publication = nil
	if _, err := k.storePendingPairEpoch(p); err != nil {
		t.Fatal(err)
	}
	got, err := k.loadPendingPairEpoch(p.GrantID, p.Generation)
	if err != nil || !reflect.DeepEqual(got, p) {
		t.Fatalf("recipient record: %v", err)
	}
	if _, _, err := k.ActiveEpoch(p.NetworkID); err == nil {
		t.Fatal("recipient key active before server activation")
	}
	p.EpochKey = bytes.Repeat([]byte{9}, 32)
	if _, err := k.storePendingPairEpoch(p); err == nil {
		t.Fatal("recipient accepted a different key on retry")
	}
}

func TestPendingPairProcessConcurrency(t *testing.T) {
	if dir := os.Getenv("PAGNET_PENDING_PAIR_TEST_DIR"); dir != "" {
		k, err := newKeyring(dir)
		if err != nil {
			t.Fatal(err)
		}
		p := testPendingPair()
		p.Publication = []byte(os.Getenv("PAGNET_PENDING_PAIR_TEST_CANDIDATE"))
		if _, err := k.storePendingPairEpoch(p); err != nil {
			t.Fatal(err)
		}
		return
	}
	dir := t.TempDir()
	const count = 6
	cmds := make([]*exec.Cmd, count)
	var outputs [count]bytes.Buffer
	for i := range cmds {
		cmds[i] = exec.Command(os.Args[0], "-test.run=^TestPendingPairProcessConcurrency$")
		cmds[i].Env = append(os.Environ(), "PAGNET_PENDING_PAIR_TEST_DIR="+dir, "PAGNET_PENDING_PAIR_TEST_CANDIDATE="+string(rune('a'+i)))
		cmds[i].Stdout = &outputs[i]
		cmds[i].Stderr = &outputs[i]
		if err := cmds[i].Start(); err != nil {
			t.Fatal(err)
		}
	}
	for i, cmd := range cmds {
		if err := cmd.Wait(); err != nil {
			t.Fatalf("child %d: %v\n%s", i, err, outputs[i].String())
		}
	}
	k, _ := newKeyring(dir)
	p := testPendingPair()
	got, err := k.loadPendingPairEpoch(p.GrantID, p.Generation)
	if err != nil || len(got.Publication) != 1 {
		t.Fatalf("concurrent store: %v", err)
	}
	for i := 0; i < count; i++ {
		p.Publication = []byte{byte('a' + i)}
		retry, err := k.storePendingPairEpoch(p)
		if err != nil || !reflect.DeepEqual(retry, got) {
			t.Fatalf("winner changed: %v", err)
		}
	}
}

func TestPendingPairActivationKeyConflict(t *testing.T) {
	k := newTestKeyring(t)
	p := testPendingPair()
	if _, err := k.storePendingPairEpoch(p); err != nil {
		t.Fatal(err)
	}
	existing := [32]byte{9}
	if err := k.StoreEpoch(p.NetworkID, p.EpochID, existing); err != nil {
		t.Fatal(err)
	}
	if err := k.activatePendingPairEpoch(p.GrantID, p.Generation, p.NetworkID, p.EpochID, p.DescriptorHash); err == nil {
		t.Fatal("overwrote an existing epoch key")
	}
	got, err := k.EpochKey(p.NetworkID, p.EpochID)
	if err != nil || got != existing {
		t.Fatal("existing key changed")
	}
}

func TestPendingPairRetrySyncsRenamedRecord(t *testing.T) {
	k := newTestKeyring(t)
	p := testPendingPair()
	bindingDir := k.pendingPairDir(p.GrantID, p.Generation)
	fault := errors.New("injected directory fsync failure")
	k.pendingPairSyncDir = func(path string) error {
		if path == bindingDir {
			return fault
		}
		return syncPairDir(path)
	}
	// The file is fsynced and renamed, but its directory sync fails (the same
	// observable state as a predecessor dying immediately after the rename).
	if _, err := k.storePendingPairEpoch(p); !errors.Is(err, fault) {
		t.Fatalf("writer fault: %v", err)
	}
	if _, err := os.Stat(filepath.Join(bindingDir, "record.json")); err != nil {
		t.Fatal("fault did not occur after rename:", err)
	}
	if _, err := k.storePendingPairEpoch(p); !errors.Is(err, fault) {
		t.Fatalf("retry returned before syncing renamed record: %v", err)
	}
	if _, err := k.loadPendingPairEpoch(p.GrantID, p.Generation); !errors.Is(err, fault) {
		t.Fatalf("load returned before syncing renamed record: %v", err)
	}
	k.pendingPairSyncDir = nil
	if _, err := k.loadPendingPairEpoch(p.GrantID, p.Generation); err != nil {
		t.Fatal(err)
	}
}

func TestPendingPairMissingDirectoryFailsClosed(t *testing.T) {
	dir := t.TempDir()
	k, _ := newKeyring(dir)
	p := testPendingPair()
	if _, err := k.storePendingPairEpoch(p); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(k.pendingPairDir(p.GrantID, p.Generation)); err != nil {
		t.Fatal(err)
	}
	k, _ = newKeyring(dir)
	if _, err := k.storePendingPairEpoch(p); err == nil {
		t.Fatal("regenerated deleted binding directory")
	}
	if _, err := k.loadPendingPairEpoch(p.GrantID, p.Generation); err == nil {
		t.Fatal("loaded deleted binding directory")
	}
}

func TestPendingPairMetadataFailsClosed(t *testing.T) {
	for _, kind := range []string{"missing_key", "missing_index", "rewritten_key", "rewritten_index", "rewritten_record"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			k, _ := newKeyring(dir)
			p := testPendingPair()
			if _, err := k.storePendingPairEpoch(p); err != nil {
				t.Fatal(err)
			}
			storeDir := filepath.Join(k.root, "pending-pairs")
			switch kind {
			case "missing_key":
				if err := os.Remove(filepath.Join(storeDir, "auth.key")); err != nil {
					t.Fatal(err)
				}
			case "missing_index":
				if err := os.Remove(filepath.Join(storeDir, "index.json")); err != nil {
					t.Fatal(err)
				}
			case "rewritten_key":
				if err := os.WriteFile(filepath.Join(storeDir, "auth.key"), bytes.Repeat([]byte{5}, 32), 0600); err != nil {
					t.Fatal(err)
				}
			case "rewritten_index":
				path := filepath.Join(storeDir, "index.json")
				b, _ := os.ReadFile(path)
				var index pendingPairIndex
				if err := json.Unmarshal(b, &index); err != nil {
					t.Fatal(err)
				}
				index.Bindings = map[string]bool{}
				b, _ = json.Marshal(index)
				if err := os.WriteFile(path, b, 0600); err != nil {
					t.Fatal(err)
				}
			case "rewritten_record":
				path := filepath.Join(k.pendingPairDir(p.GrantID, p.Generation), "record.json")
				b, _ := os.ReadFile(path)
				var record pendingPairFile
				if err := json.Unmarshal(b, &record); err != nil {
					t.Fatal(err)
				}
				record.Record.Descriptor = []byte("rewritten immutable descriptor")
				record.Record.DescriptorHash = sha256.Sum256(record.Record.Descriptor)
				// An editor may recompute public hashes, but cannot repair the MAC
				// without the retained store authentication key.
				b, _ = json.Marshal(record)
				if err := os.WriteFile(path, b, 0600); err != nil {
					t.Fatal(err)
				}
			}
			k, _ = newKeyring(dir)
			if _, err := k.storePendingPairEpoch(p); err == nil {
				t.Fatal("accepted damaged metadata")
			}
			if _, err := k.loadPendingPairEpoch(p.GrantID, p.Generation); err == nil {
				t.Fatal("loaded damaged metadata")
			}
			if err := k.activatePendingPairEpoch(p.GrantID, p.Generation, p.NetworkID, p.EpochID, p.DescriptorHash); err == nil {
				t.Fatal("activated damaged metadata")
			}
		})
	}
}

func TestPendingPairRejectsPathIdentifiers(t *testing.T) {
	for _, id := range []string{"", ".", "..", "../other", "a/b", `a\b`, "/tmp", "bad\x00id", "a b", "a\n", "c:other"} {
		for _, field := range []string{"network", "epoch"} {
			t.Run(field+"/"+strconv.Quote(id), func(t *testing.T) {
				k := newTestKeyring(t)
				p := testPendingPair()
				if field == "network" {
					p.NetworkID = id
				} else {
					p.EpochID = id
				}
				if _, err := k.storePendingPairEpoch(p); err == nil {
					t.Fatal("accepted invalid path identifier")
				}
				if err := k.activatePendingPairEpoch(p.GrantID, p.Generation, p.NetworkID, p.EpochID, p.DescriptorHash); err == nil {
					t.Fatal("activation accepted invalid path identifier")
				}
				if _, err := os.Stat(filepath.Join(k.root, "networks")); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("invalid activation created network path: %v", err)
				}
			})
		}
	}
}

func TestPendingPairReservationRenameFaultFailsClosed(t *testing.T) {
	k := newTestKeyring(t)
	p := testPendingPair()
	// Initialize the store before injecting a fault in the reservation update.
	if _, err := k.loadPendingPairEpoch("unknown", 1); err == nil {
		t.Fatal("unexpected record")
	}
	storeDir := filepath.Join(k.root, "pending-pairs")
	bindingDir := k.pendingPairDir(p.GrantID, p.Generation)
	fault := errors.New("injected reservation fsync failure")
	k.pendingPairSyncDir = func(path string) error {
		if path == storeDir {
			b, err := os.ReadFile(filepath.Join(storeDir, "index.json"))
			if err != nil {
				return err
			}
			var index pendingPairIndex
			if err := json.Unmarshal(b, &index); err != nil {
				return err
			}
			if index.Bindings[filepath.Base(bindingDir)] {
				return fault
			}
		}
		return syncPairDir(path)
	}
	if _, err := k.storePendingPairEpoch(p); !errors.Is(err, fault) {
		t.Fatalf("reservation fault: %v", err)
	}
	if _, err := os.Stat(bindingDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("created child before durable reservation: %v", err)
	}
	k.pendingPairSyncDir = nil
	// A restart can make the renamed reservation durable, but must fail closed
	// because there is no original key/package to resume.
	if _, err := k.storePendingPairEpoch(p); err == nil {
		t.Fatal("regenerated key after interrupted reservation")
	}
}
