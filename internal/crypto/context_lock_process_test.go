//go:build linux || darwin

package crypto

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/e2ee"
)

func TestContextAuthorityProcessLock(t *testing.T) {
	if raw := os.Getenv("PAGNET_CONTEXT_LOCK_FIXTURE"); raw != "" {
		var binding e2ee.ProtectedContext
		if err := json.Unmarshal([]byte(raw), &binding); err != nil {
			t.Fatal(err)
		}
		err := WithContextKeyring(context.Background(), os.Getenv("PAGNET_CONTEXT_LOCK_STATE"), binding, func(*ContextKeyring) error {
			fmt.Println("locked")
			_, err := io.Copy(io.Discard, os.Stdin)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return
	}
	state := t.TempDir()
	binding := e2ee.ProtectedContext{Kind: e2ee.OwnerContextKind, ID: uuid.NewString(), TenantID: uuid.NewString(), OwnerUserID: uuid.NewString(), HostID: uuid.NewString()}
	ring := &ContextKeyring{Context: binding, Epochs: []KeyEpoch{{ID: uuid.NewString(), State: EpochActive, Key: bytes.Repeat([]byte{7}, 32), CreatedAt: time.Now().UTC()}}}
	if err := SaveContextKeyring(state, ring); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(binding)
	child := exec.Command(os.Args[0], "-test.run=^TestContextAuthorityProcessLock$")
	child.Env = append(os.Environ(), "PAGNET_CONTEXT_LOCK_FIXTURE="+string(raw), "PAGNET_CONTEXT_LOCK_STATE="+state)
	input, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Process.Kill(); _ = child.Wait() })
	line, err := bufio.NewReader(output).ReadString('\n')
	if err != nil || line != "locked\n" {
		t.Fatalf("child authority admission: %q %v", line, err)
	}
	// Revocation cannot pass an approval's shared authority gate in another
	// process. Once the native action releases it, the new epoch state wins.
	ring.Epochs[0].State = EpochRevoked
	saved := make(chan error, 1)
	go func() { saved <- SaveContextKeyring(state, ring) }()
	select {
	case err := <-saved:
		t.Fatalf("rotation crossed native approval gate: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err = input.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-saved:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("writer stayed blocked after native release")
	}
	latest, err := LoadContextKeyring(state, binding)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := latest.EpochByID(ring.Epochs[0].ID); ok {
		t.Fatal("revoked epoch still available")
	}
}

func TestContextLockRejectsAncestorSymlinkBeforeCreatingFile(t *testing.T) {
	root := t.TempDir()
	target := t.TempDir()
	if err := os.MkdirAll(filepath.Join(target, "contexts", "authority"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, "e2ee")); err != nil {
		t.Fatal(err)
	}
	_, err := lockContextKeyring(context.Background(), filepath.Join(root, "e2ee", "contexts", "authority", "keyring.json"), false)
	if err == nil {
		t.Fatal("substituted ancestor accepted")
	}
	if _, err = os.Stat(filepath.Join(target, "contexts", "authority", "authority.lock")); !os.IsNotExist(err) {
		t.Fatal("lock file created outside authority")
	}
}
