package sdk

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/transport"
)

func TestDirectMessageRetryBindingAndDependencies(t *testing.T) {
	s, p, _, now := directMaterials(t)
	k, _ := newKeyring(t.TempDir())
	h, _ := s.prepareHeader("ASK", directTestAskID, directTestAskID, nil, now)
	prepare := func(text string) (*directPreparedMessage, error) {
		return k.prepareDirectMessage(s, s.descriptor.S, h, nil, nil, []byte(text), now)
	}
	a, err := prepare("hello")
	if err != nil {
		t.Fatal(err)
	}
	b, err := prepare("hello")
	if err != nil || !bytes.Equal(a.wire, b.wire) {
		t.Fatalf("retry %v", err)
	}
	if _, err = prepare("changed"); err == nil {
		t.Fatal("plaintext conflict accepted")
	}
	bad := s.descriptor.S
	bad.CredentialID = uuid.NewString()
	if _, err = k.prepareDirectMessage(s, bad, h, nil, nil, []byte("hello"), now); err == nil {
		t.Fatal("wrong local credential")
	}
	if err = k.updateDirectMessage(a, true, false); err != nil {
		t.Fatal(err)
	}
	b, err = prepare("hello")
	if err != nil || !bytes.Equal(a.wire, b.wire) {
		t.Fatal("admission removed ASK", err)
	}
	rh, _ := p.prepareHeader("REPLY", directTestReplyID, h.RootID, a.wire, now)
	rp, err := k.prepareDirectMessage(p, p.descriptor.P, rh, a.wire, nil, []byte("answer"), now)
	if err != nil {
		t.Fatal(err)
	}
	reply := rp.wire
	if _, err = s.open("REPLY", directTestReplyID, h.RootID, b.wire, reply, now); err != nil {
		t.Fatal(err)
	}
	ch, err := s.prepareContinuationHeader(directTestSecondAskID, a.wire, reply, now)
	if err != nil {
		t.Fatal(err)
	}
	c, err := k.prepareDirectMessage(s, s.descriptor.S, ch, a.wire, reply, []byte("next"), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = k.prepareDirectMessage(s, s.descriptor.S, ch, a.wire, append(reply, ' '), []byte("next"), now); err == nil {
		t.Fatal("changed predecessor")
	}
	otherReply, err := p.seal("REPLY", directTestSecondReplyID, h.RootID, a.wire, []byte("other"), now)
	if err != nil {
		t.Fatal(err)
	}
	otherHeader, err := s.prepareContinuationHeader(directTestSecondAskID, a.wire, otherReply, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = k.prepareDirectMessage(s, s.descriptor.S, otherHeader, a.wire, otherReply, []byte("next"), now); err == nil {
		t.Fatal("valid changed header under reserved ID")
	}
	changed := h
	changed.RootID = directTestSecondAskID
	if _, err = k.prepareDirectMessage(s, s.descriptor.S, changed, nil, nil, []byte("hello"), now); err == nil {
		t.Fatal("changed header")
	}
	if err = k.updateDirectMessage(a, false, true); err != nil {
		t.Fatal(err)
	}
	if _, err = prepare("hello"); err == nil {
		t.Fatal("tombstone reused")
	}
	if _, err = os.Stat(k.directMessagePath(h.MessageID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("wire retained after release")
	}
	if len(c.wire) == 0 {
		t.Fatal("missing continuation")
	}
}

func TestDirectMessageCorruption(t *testing.T) {
	for _, mode := range []string{"missing", "corrupt", "oversized-wire", "oversized-manifest", "missing-manifest", "missing-key"} {
		t.Run(mode, func(t *testing.T) {
			s, _, _, now := directMaterials(t)
			k, _ := newKeyring(t.TempDir())
			h, _ := s.prepareHeader("ASK", directTestAskID, directTestAskID, nil, now)
			prep := func() error {
				_, err := k.prepareDirectMessage(s, s.descriptor.S, h, nil, nil, []byte("hello"), now)
				return err
			}
			if err := prep(); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "missing":
				os.Remove(k.directMessagePath(h.MessageID))
			case "corrupt":
				os.WriteFile(k.directMessagePath(h.MessageID), []byte("bad"), 0600)
			case "oversized-wire":
				os.Truncate(k.directMessagePath(h.MessageID), 2*transport.DirectChannelMessageMaxBytesV2+1)
			case "oversized-manifest":
				os.Truncate(filepath.Join(k.directMessageDir(), "manifest.json"), directMessageIndexLimit+1)
			case "missing-manifest":
				os.Remove(filepath.Join(k.directMessageDir(), "manifest.json"))
			case "missing-key":
				os.Remove(filepath.Join(k.directMessageDir(), "auth.key"))
			}
			if err := prep(); err == nil {
				t.Fatal("corrupt store accepted")
			}
		})
	}
}

func TestDirectMessageCrashBoundaries(t *testing.T) {
	// Enumerate every directory-fsync boundary of a fresh prepare, including
	// initialization, reservation, wire, final manifest, and prepared reread.
	for boundary := 1; boundary <= 12; boundary++ {
		t.Run(fmt.Sprint(boundary), func(t *testing.T) {
			s, _, _, now := directMaterials(t)
			k, _ := newKeyring(t.TempDir())
			h, _ := s.prepareHeader("ASK", directTestAskID, directTestAskID, nil, now)
			calls := 0
			hit := false
			k.directMessageSyncDir = func(path string) error {
				calls++
				if calls == boundary {
					hit = true
					return errors.New("crash")
				}
				return syncPairDir(path)
			}
			first, err := k.prepareDirectMessage(s, s.descriptor.S, h, nil, nil, []byte("hello"), now)
			if !hit {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || first != nil {
				t.Fatal("fault returned prepared handle")
			}
			k.directMessageSyncDir = nil
			// A persisted reservation may only reload an already committed exact wire;
			// incomplete store/reservation must fail. It may never freshly encrypt.
			manifest, key, e := k.readDirectMessages()
			if e != nil {
				return
			}
			r, ok := manifest[h.MessageID]
			if !ok {
				return
			}
			retry, e := k.prepareDirectMessage(s, s.descriptor.S, h, nil, nil, []byte("hello"), now)
			if r.WireBytes == 0 {
				if e == nil {
					t.Fatal("incomplete reservation encrypted")
				}
				return
			}
			expected, e := k.readDirectMessage(r, key)
			if e != nil {
				t.Fatal(e)
			}
			if retry == nil || !bytes.Equal(retry.wire, expected) {
				t.Fatal("retry bytes changed")
			}
		})
	}
}

func TestDirectMessageQuotaAndTombstones(t *testing.T) {
	s, _, _, now := directMaterials(t)
	k, _ := newKeyring(t.TempDir())
	h, _ := s.prepareHeader("ASK", directTestAskID, directTestAskID, nil, now)
	a, err := k.prepareDirectMessage(s, s.descriptor.S, h, nil, nil, []byte("hello"), now)
	if err != nil {
		t.Fatal(err)
	}
	if err = k.updateDirectMessage(a, true, true); err != nil {
		t.Fatal(err)
	}
	unlock, err := k.lockDirectMessages()
	if err != nil {
		t.Fatal(err)
	}
	records, key, err := k.readDirectMessages()
	if err != nil {
		t.Fatal(err)
	}
	template := records[h.MessageID]
	for len(records) < directMessageRecordLimit {
		r := template
		id := uuid.NewString()
		r.Binding.Header.MessageID = id
		r.Binding.Header.RootID = id
		records[id] = r
	}
	if err = k.writeDirectMessages(records, key); err != nil {
		t.Fatal(err)
	}
	unlock()
	fresh, _ := s.prepareHeader("ASK", directTestSecondAskID, directTestSecondAskID, nil, now)
	if _, err = k.prepareDirectMessage(s, s.descriptor.S, fresh, nil, nil, []byte("hello"), now); err == nil {
		t.Fatal("tombstones excluded from quota")
	}
	// Authenticated oversize metadata is rejected before reading any wire file.
	unlock, _ = k.lockDirectMessages()
	records, key, _ = k.readDirectMessages()
	r := records[h.MessageID]
	r.ReservedBytes = transport.DirectChannelMessageMaxBytesV2 + 1
	records[h.MessageID] = r
	k.writeDirectMessages(records, key)
	unlock()
	if _, _, err = k.readDirectMessages(); err == nil {
		t.Fatal("invalid record size")
	}
}

func TestDirectMessageProcessConcurrency(t *testing.T) {
	if root := os.Getenv("PAGNET_DIRECT_JOURNAL_TEST_ROOT"); root != "" {
		raw, err := os.ReadFile(filepath.Join(root, "fixture.json"))
		if err != nil {
			t.Fatal(err)
		}
		var f struct {
			Descriptor             directDescriptor
			Hash, Key, Publication [32]byte
			Now                    string
		}
		if json.Unmarshal(raw, &f) != nil {
			t.Fatal("fixture")
		}
		m := &directMaterial{descriptor: f.Descriptor, hash: f.Hash, key: f.Key, publicationHash: f.Publication, role: "S"}
		now, _ := time.Parse(time.RFC3339Nano, f.Now)
		k, _ := newKeyring(root)
		h, _ := m.prepareHeader("ASK", directTestAskID, directTestAskID, nil, now)
		a, err := k.prepareDirectMessage(m, m.descriptor.S, h, nil, nil, []byte("same"), now)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(root, os.Getenv("PAGNET_DIRECT_JOURNAL_TEST_OUTPUT")), a.wire, 0600); err != nil {
			t.Fatal(err)
		}
		return
	}
	s, _, _, now := directMaterials(t)
	root := t.TempDir()
	raw, _ := json.Marshal(struct {
		Descriptor             directDescriptor
		Hash, Key, Publication [32]byte
		Now                    string
	}{s.descriptor, s.hash, s.key, s.publicationHash, now.Format("2006-01-02T15:04:05.999999999Z07:00")})
	os.WriteFile(filepath.Join(root, "fixture.json"), raw, 0600)
	var wg sync.WaitGroup
	fail := make(chan string, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cmd := exec.Command(os.Args[0], "-test.run=^TestDirectMessageProcessConcurrency$")
			cmd.Env = append(os.Environ(), "PAGNET_DIRECT_JOURNAL_TEST_ROOT="+root, fmt.Sprintf("PAGNET_DIRECT_JOURNAL_TEST_OUTPUT=wire%d", i))
			if out, err := cmd.CombinedOutput(); err != nil {
				fail <- fmt.Sprintf("%v %s", err, out)
			}
		}(i)
	}
	wg.Wait()
	close(fail)
	for e := range fail {
		t.Fatal(e)
	}
	a, _ := os.ReadFile(filepath.Join(root, "wire0"))
	b, _ := os.ReadFile(filepath.Join(root, "wire1"))
	if len(a) == 0 || !bytes.Equal(a, b) {
		t.Fatal("concurrent encryption diverged")
	}
}
