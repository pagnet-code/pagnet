package sdk

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestDirectMessageTempCrashRecovery(t *testing.T) {
	const crashRoot = "PAGNET_DIRECT_TEMP_CRASH_ROOT"
	if root := os.Getenv(crashRoot); root != "" {
		// Exit without closing the journal transaction or running deferred cleanup,
		// at the boundary after a temp file is durable and before its rename.
		k, err := newKeyring(root)
		if err != nil {
			t.Fatal(err)
		}
		unlock, err := k.lockDirectMessages()
		if err != nil {
			t.Fatal(err)
		}
		defer unlock()
		for i := 0; i < 256; i++ {
			f, err := os.CreateTemp(k.directMessageDir(), ".direct-v2-*")
			if err != nil {
				t.Fatal(err)
			}
			if _, err = f.Write([]byte("unfinished journal write")); err != nil {
				t.Fatal(err)
			}
			if err = f.Sync(); err != nil {
				t.Fatal(err)
			}
			if err = f.Close(); err != nil {
				t.Fatal(err)
			}
		}
		k.directMessageBeforeRename = func() { os.Exit(73) }
		if err = k.writeDirectMessageFile(filepath.Join(k.directMessageDir(), "manifest.json"), []byte("unfinished manifest write")); err != nil {
			t.Fatal(err)
		}
		t.Fatal("before-rename crash hook did not run")
	}
	for _, state := range []string{"prepared", "tombstone", "incomplete"} {
		t.Run(state, func(t *testing.T) {
			s, _, _, now := directMaterials(t)
			root := t.TempDir()
			k, err := newKeyring(root)
			if err != nil {
				t.Fatal(err)
			}
			h, err := s.prepareHeader("ASK", directTestAskID, directTestAskID, nil, now)
			if err != nil {
				t.Fatal(err)
			}
			prepared, err := k.prepareDirectMessage(s, s.descriptor.S, h, nil, nil, []byte("hello"), now)
			if err != nil {
				t.Fatal(err)
			}
			switch state {
			case "tombstone":
				if err = k.updateDirectMessage(prepared, true, true); err != nil {
					t.Fatal(err)
				}
			case "incomplete":
				unlock, err := k.lockDirectMessages()
				if err != nil {
					t.Fatal(err)
				}
				records, key, err := k.readDirectMessages()
				if err != nil {
					t.Fatal(err)
				}
				r := records[h.MessageID]
				r.WireBytes = 0
				r.WireDigest = [32]byte{}
				records[h.MessageID] = r
				if err = k.writeDirectMessages(records, key); err != nil {
					t.Fatal(err)
				}
				clear(key)
				if err = os.Remove(k.directMessagePath(h.MessageID)); err != nil {
					t.Fatal(err)
				}
				unlock()
			}
			manifestPath := filepath.Join(k.directMessageDir(), "manifest.json")
			manifest, err := os.ReadFile(manifestPath)
			if err != nil {
				t.Fatal(err)
			}
			for crash := 0; crash < 3; crash++ {
				cmd := exec.Command(os.Args[0], "-test.run=^TestDirectMessageTempCrashRecovery$")
				cmd.Env = append(os.Environ(), crashRoot+"="+root)
				if out, err := cmd.CombinedOutput(); err == nil {
					t.Fatal("crash subprocess exited normally")
				} else if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 73 {
					t.Fatalf("crash subprocess: %v %s", err, out)
				}
				entries, err := os.ReadDir(k.directMessageDir())
				if err != nil || len(entries) < 257 {
					t.Fatalf("crash did not leave temp files: %d entries, %v", len(entries), err)
				}
				unlock, err := k.lockDirectMessages()
				if err != nil {
					t.Fatal(err)
				}
				unlock()
				entries, err = os.ReadDir(k.directMessageDir())
				if err != nil {
					t.Fatal(err)
				}
				wantEntries := 2
				if state == "prepared" {
					wantEntries++
				}
				if len(entries) != wantEntries {
					t.Fatalf("journal grew after crash %d: %d entries, want %d", crash, len(entries), wantEntries)
				}
				after, err := os.ReadFile(manifestPath)
				if err != nil || !bytes.Equal(manifest, after) {
					t.Fatalf("recovery changed reservations: %v", err)
				}
				retry, err := k.prepareDirectMessage(s, s.descriptor.S, h, nil, nil, []byte("hello"), now)
				if state == "prepared" {
					if err != nil || retry == nil || !bytes.Equal(prepared.wire, retry.wire) {
						t.Fatalf("prepared retry changed after crash: %v", err)
					}
				} else if err == nil || retry != nil {
					t.Fatalf("%s reservation encrypted again", state)
				}
				if state != "prepared" {
					if _, err := os.Lstat(k.directMessagePath(h.MessageID)); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("%s reservation acquired wire file: %v", state, err)
					}
				}
			}
		})
	}
}

func TestDirectMessageSuspiciousTemps(t *testing.T) {
	for _, kind := range []string{"empty-suffix", "nondigit-suffix", "extra-suffix", "symlink", "directory", "public-mode", "owner"} {
		t.Run(kind, func(t *testing.T) {
			k, err := newKeyring(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			unlock, err := k.lockDirectMessages()
			if err != nil {
				t.Fatal(err)
			}
			unlock()
			name := ".direct-v2-12345"
			switch kind {
			case "empty-suffix":
				name = ".direct-v2-"
			case "nondigit-suffix":
				name = ".direct-v2-surprise"
			case "extra-suffix":
				name = ".direct-v2-12345.extra"
			}
			path := filepath.Join(k.directMessageDir(), name)
			data := []byte("must remain untouched")
			switch kind {
			case "symlink":
				target := filepath.Join(k.root, "target")
				if err = os.WriteFile(target, data, 0600); err == nil {
					err = os.Symlink(target, path)
				}
			case "directory":
				err = os.Mkdir(path, 0700)
			default:
				err = os.WriteFile(path, data, 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if kind == "public-mode" {
				if err = os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "owner" {
				if err = os.Chown(path, os.Getuid()+1, -1); err != nil {
					t.Skip("changing ownership is unavailable")
				}
			}
			unlock, err = k.lockDirectMessages()
			if err == nil {
				unlock()
				t.Fatal("suspicious temp accepted")
			}
			if _, err = os.Lstat(path); err != nil {
				t.Fatalf("suspicious entry removed: %v", err)
			}
			if kind != "directory" {
				after, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(data, after) {
					t.Fatalf("suspicious entry changed: %v", err)
				}
			}
		})
	}
}

func TestDirectMessageUnknownFilesPreserved(t *testing.T) {
	k, err := newKeyring(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	unlock, err := k.lockDirectMessages()
	if err != nil {
		t.Fatal(err)
	}
	unlock()
	for i, name := range []string{"notes", ".direct-v1-123", "unknown.json"} {
		path := filepath.Join(k.directMessageDir(), name)
		data := []byte(fmt.Sprintf("unknown file %d", i))
		if err = os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		unlock, err = k.lockDirectMessages()
		if err == nil {
			unlock()
		}
		after, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(data, after) {
			t.Fatalf("unknown file %q changed: %v", name, err)
		}
	}
}
