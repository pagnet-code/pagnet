//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package inbox

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

var testKey = Key{NetworkID: "network", PrincipalID: "principal", MessageID: "message"}

func statePath(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(root, "inbox")
}
func mustOpen(t *testing.T, path string, l Limits) *Store {
	t.Helper()
	s, err := Open(path, l)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}
func TestReopenEncryptedRecord(t *testing.T) {
	path := statePath(t)
	s := mustOpen(t, path, Limits{})
	payload := []byte("confidential payload unique to this message")
	created, err := s.Put(testKey, payload)
	if err != nil || !created {
		t.Fatalf("Put = %v, %v", created, err)
	}
	files, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		info, err := f.Info()
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("%s mode = %o", f.Name(), info.Mode().Perm())
		}
		data, err := os.ReadFile(filepath.Join(path, f.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, payload) {
			t.Fatalf("plaintext in %s", f.Name())
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = mustOpen(t, path, Limits{})
	got, err := s.Get(testKey)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("Get = %q, %v", got, err)
	}
	keys, err := s.List()
	if err != nil || len(keys) != 1 || keys[0] != testKey {
		t.Fatalf("List = %v, %v", keys, err)
	}
}
func TestImmutableDuplicatesAndScopedKeys(t *testing.T) {
	s := mustOpen(t, statePath(t), Limits{})
	if _, err := s.Put(testKey, []byte("first")); err != nil {
		t.Fatal(err)
	}
	if created, err := s.Put(testKey, []byte("first")); err != nil || created {
		t.Fatalf("duplicate = %v, %v", created, err)
	}
	if _, err := s.Put(testKey, []byte("second")); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed duplicate = %v", err)
	}
	for _, key := range []Key{{"other", testKey.PrincipalID, testKey.MessageID}, {testKey.NetworkID, "other", testKey.MessageID}} {
		if created, err := s.Put(key, []byte("separate")); err != nil || !created {
			t.Fatalf("scoped Put = %v, %v", created, err)
		}
	}
	got, err := s.Get(testKey)
	if err != nil || string(got) != "first" {
		t.Fatalf("original = %q, %v", got, err)
	}
}
func TestTamperingFailsClosed(t *testing.T) {
	for _, kind := range []string{"ciphertext", "key", "binding", "missing-key"} {
		t.Run(kind, func(t *testing.T) {
			path := statePath(t)
			s := mustOpen(t, path, Limits{})
			if _, err := s.Put(testKey, []byte("secret")); err != nil {
				t.Fatal(err)
			}
			s.Close()
			aad, _ := keyData(testKey)
			name := filepath.Join(path, recordName(aad))
			switch kind {
			case "ciphertext":
				data, err := os.ReadFile(name)
				if err != nil {
					t.Fatal(err)
				}
				// A valid JSON record with an altered GCM tag must fail authentication.
				var r diskRecord
				if err := json.Unmarshal(data, &r); err != nil {
					t.Fatal(err)
				}
				r.Sealed[len(r.Sealed)-1] ^= 1
				data, _ = json.Marshal(r)
				if err := os.WriteFile(name, data, 0600); err != nil {
					t.Fatal(err)
				}
			case "binding":
				data, err := os.ReadFile(name)
				if err != nil {
					t.Fatal(err)
				}
				var r diskRecord
				if err := json.Unmarshal(data, &r); err != nil {
					t.Fatal(err)
				}
				r.Key.NetworkID = "attacker"
				data, _ = json.Marshal(r)
				changedAAD, _ := keyData(r.Key)
				if err := os.Remove(name); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(path, recordName(changedAAD)), data, 0600); err != nil {
					t.Fatal(err)
				}
			case "key":
				if err := os.WriteFile(filepath.Join(path, "key"), bytes.Repeat([]byte{7}, 32), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing-key":
				if err := os.Remove(filepath.Join(path, "key")); err != nil {
					t.Fatal(err)
				}
			}
			if reopened, err := Open(path, Limits{}); !errors.Is(err, ErrCorrupt) {
				if reopened != nil {
					reopened.Close()
				}
				t.Fatalf("Open = %v", err)
			}
		})
	}
}
func TestExclusiveOwnership(t *testing.T) {
	path := statePath(t)
	s := mustOpen(t, path, Limits{})
	if second, err := Open(path, Limits{}); !errors.Is(err, ErrLocked) {
		if second != nil {
			second.Close()
		}
		t.Fatalf("second Open = %v", err)
	}
	s.Close()
	mustOpen(t, path, Limits{})
}
func TestBoundsNeverEvict(t *testing.T) {
	for _, limits := range []Limits{{MaxRecords: 1}, {MaxPayloadBytes: 3}, {MaxTotalBytes: 3}} {
		t.Run("bound", func(t *testing.T) {
			path := statePath(t)
			s := mustOpen(t, path, limits)
			if _, err := s.Put(testKey, []byte("abc")); err != nil {
				t.Fatal(err)
			}
			key := testKey
			key.MessageID = "second"
			if _, err := s.Put(key, []byte("long")); !errors.Is(err, ErrFull) {
				t.Fatalf("bound = %v", err)
			}
			if _, err := s.Put(testKey, []byte("abc")); err != nil {
				t.Fatalf("duplicate at bound = %v", err)
			}
			s.Close()
			s = mustOpen(t, path, limits)
			got, err := s.Get(testKey)
			if err != nil || string(got) != "abc" {
				t.Fatalf("retained = %q, %v", got, err)
			}
			keys, _ := s.List()
			if len(keys) != 1 {
				t.Fatalf("records = %d", len(keys))
			}
		})
	}
}
func TestUnsafeStateRejected(t *testing.T) {
	for _, kind := range []string{"directory", "key", "symlink", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			path := statePath(t)
			s := mustOpen(t, path, Limits{})
			s.Close()
			switch kind {
			case "directory":
				if err := os.Chmod(path, 0755); err != nil {
					t.Fatal(err)
				}
			case "key":
				if err := os.Chmod(filepath.Join(path, "key"), 0644); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Rename(path, path+"-real"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+"-real", path); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(filepath.Join(path, "key"), filepath.Join(path, "extra")); err != nil {
					t.Fatal(err)
				}
			}
			if reopened, err := Open(path, Limits{}); !errors.Is(err, ErrPrivate) {
				if reopened != nil {
					reopened.Close()
				}
				t.Fatalf("Open = %v", err)
			}
		})
	}
}
