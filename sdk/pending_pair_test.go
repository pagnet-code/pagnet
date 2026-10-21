//go:build linux || darwin

package sdk

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
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
					f.Checksum = sha256.Sum256(payload)
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
