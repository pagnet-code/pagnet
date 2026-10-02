//go:build linux || darwin

package sessionworker

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestControllerDiscoveryRejectsStateMutationAndForeignIdentity(t *testing.T) {
	for _, scenario := range []string{"exact", "missing", "account", "generation", "directory_mode", "ancestor_symlink", "key_symlink", "key_fifo", "manifest_fifo"} {
		t.Run(scenario, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "worker")
			bootstrap := Bootstrap{Protocol: Protocol, Scope: testScope()}
			key := bytes.Repeat([]byte{7}, 32)
			if scenario != "missing" {
				if err := PrepareBootstrap(dir, bootstrap, key); err != nil {
					t.Fatal(err)
				}
			}
			expected := bootstrap.Scope
			switch scenario {
			case "account":
				expected.AccountID = "another-account"
			case "generation":
				expected.Generation = "another-lifetime"
			case "directory_mode":
				if err := os.Chmod(dir, 0755); err != nil {
					t.Fatal(err)
				}
			case "ancestor_symlink":
				link := filepath.Join(t.TempDir(), "alias")
				if err := os.Symlink(filepath.Dir(dir), link); err != nil {
					t.Fatal(err)
				}
				dir = filepath.Join(link, "worker")
			case "key_symlink":
				path := filepath.Join(dir, "control.key")
				if err := os.Rename(path, path+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".original", path); err != nil {
					t.Fatal(err)
				}
			case "key_fifo", "manifest_fifo":
				name := "control.key"
				if scenario == "manifest_fifo" {
					name = "bootstrap.json"
				}
				path := filepath.Join(dir, name)
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := unix.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
				// Unblock an old implementation on failure so the test process
				// remains cancellable; the fixed reader never opens a FIFO blocking.
				t.Cleanup(func() {
					fd, err := unix.Open(path, unix.O_WRONLY|unix.O_NONBLOCK, 0)
					if err == nil {
						_ = unix.Close(fd)
					}
				})
			}
			type result struct {
				b   Bootstrap
				key []byte
				err error
			}
			done := make(chan result, 1)
			go func() { b, loaded, err := LoadControllerBootstrap(dir, expected); done <- result{b, loaded, err} }()
			select {
			case got := <-done:
				defer clear(got.key)
				if scenario == "exact" {
					if got.err != nil || got.b.Scope != expected || !bytes.Equal(got.key, key) {
						t.Fatalf("exact private identity rejected: %v", got.err)
					}
				} else if got.err == nil || got.key != nil {
					t.Fatal("invalid private state exposed a key", scenario)
				}
			case <-time.After(time.Second):
				t.Fatal("discovery blocked on non-regular private state", scenario)
			}
			if scenario == "missing" {
				if _, err := os.Stat(dir); !os.IsNotExist(err) {
					t.Fatal("discovery created missing state", err)
				}
			}
		})
	}
}

func TestNativeProfileFingerprintDoesNotPersistEnvironment(t *testing.T) {
	a := NativeSpec{Binary: "/bin/agent", Env: []string{"API_KEY=private-value"}}
	b := a
	b.Env = []string{"API_KEY=other-private-value"}
	if NativeProfileFingerprint(a) != NativeProfileFingerprint(b) {
		t.Fatal("memory-only environment became durable profile identity")
	}
	b.PrefixArgs = []string{"--profile", "other"}
	if NativeProfileFingerprint(a) == NativeProfileFingerprint(b) {
		t.Fatal("profile arguments not bound")
	}
}
