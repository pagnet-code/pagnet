package sdk

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func ownerTextTestReceipt(prepared PreparedOwnerTextProjectMessage) OwnerTextProjectMessageReceipt {
	digest := sha256.Sum256(prepared.Wire)
	return OwnerTextProjectMessageReceipt{MessageID: prepared.ID, AdmissionSeq: 1, RequestDigest: digest[:], Status: "pending", CreatedAt: time.Now().UTC()}
}
func reopenOwnerTextClient(t *testing.T, c *Client) *Client {
	t.Helper()
	kr, err := newKeyring(filepath.Dir(c.kr.root))
	if err != nil {
		t.Fatal(err)
	}
	private, err := kr.identityKey(c.PrincipalID())
	if err != nil {
		t.Fatal(err)
	}
	reopened := &Client{kr: kr, identityPriv: private, identityPub: c.identityPub}
	reopened.principalID.Store(c.PrincipalID())
	return reopened
}
func TestOwnerTextSpoolExactRetryAndImmutableID(t *testing.T) {
	project, clients := ownerTextMessageFixture(t)
	sender, responder := clients[0], clients[1]
	prepared, err := sender.PrepareOwnerTextProjectMessage(project, responder.PrincipalID(), "ASK", []byte("retry exact bytes"), nil)
	if err != nil {
		t.Fatal(err)
	}
	restarted := reopenOwnerTextClient(t, sender)
	loaded, err := restarted.LoadPreparedOwnerTextProjectMessage(project, prepared.ID)
	if err != nil || !bytes.Equal(loaded.Wire, prepared.Wire) || !bytes.Equal(loaded.LocalEvidence, prepared.LocalEvidence) {
		t.Fatalf("retry changed: %v", err)
	}
	if _, err = restarted.PrepareOwnerTextProjectMessageWithID(project, responder.PrincipalID(), "ASK", prepared.ID, []byte("changed"), nil); err == nil {
		t.Fatal("reserved ID reencrypted")
	}
	if _, err = restarted.LoadPreparedOwnerTextProjectMessage(uuid.NewString(), prepared.ID); err == nil {
		t.Fatal("cross-project retry accepted")
	}
	record, err := restarted.kr.loadOwnerTextProjectMessageBinding(sender.PrincipalID(), sender.identityPriv, prepared.ID)
	if err != nil {
		t.Fatal(err)
	}
	changed := bytes.Clone(prepared.Wire)
	changed[len(changed)-2] ^= 1
	if err = restarted.kr.storeOwnerTextProjectMessage(sender.PrincipalID(), sender.identityPriv, record.Reservation, changed, ownerTextProjectLocalEvidence(sender.identityPriv, changed)); err == nil {
		t.Fatal("changed replay stored")
	}
	if err = restarted.kr.storeOwnerTextProjectMessage(sender.PrincipalID(), sender.identityPriv, record.Reservation, prepared.Wire, prepared.LocalEvidence); err != nil {
		t.Fatal(err)
	}
	dir := restarted.kr.ownerTextProjectMessageDir(sender.PrincipalID())
	if filepath.Base(dir) != "owner-text-project-messages" {
		t.Fatal("wrong spool directory")
	}
	if _, err = os.Stat(filepath.Join(sender.kr.projectMessageDir(sender.PrincipalID()), prepared.ID+".json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("owner message leaked into sharing spool")
	}
	raw, err := readPrivatePairFile(filepath.Join(dir, prepared.ID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("retry exact bytes")) {
		t.Fatal("plaintext persisted")
	}
}
func TestOwnerTextSpoolAmbiguousPreparationAndReopen(t *testing.T) {
	for _, state := range []string{"reserved", "prepared"} {
		t.Run(state, func(t *testing.T) {
			project, clients := ownerTextMessageFixture(t)
			sender, responder := clients[0], clients[1]
			id := ownerTextID(t)
			injected := errors.New("injected spool sync failure")
			sender.kr.pendingPairSyncDir = func(dir string) error {
				if dir == sender.kr.ownerTextProjectMessageDir(sender.PrincipalID()) {
					record, err := sender.kr.readOwnerTextProjectMessageRecord(sender.PrincipalID(), sender.identityPriv, id)
					if err == nil && record.State == state {
						return injected
					}
				}
				return syncPairDir(dir)
			}
			result, err := sender.PrepareOwnerTextProjectMessageWithID(project, responder.PrincipalID(), "ASK", id, []byte("uncertain"), nil)
			if !errors.Is(err, injected) || result.ID != id || len(result.Wire) != 0 {
				t.Fatalf("ambiguous preparation: %+v %v", result, err)
			}
			restarted := reopenOwnerTextClient(t, sender)
			if _, err = restarted.PrepareOwnerTextProjectMessageWithID(project, responder.PrincipalID(), "ASK", id, []byte("uncertain"), nil); err == nil {
				t.Fatal("ambiguous ID reencrypted")
			}
			loaded, err := restarted.LoadPreparedOwnerTextProjectMessage(project, id)
			if state == "reserved" {
				if err == nil {
					t.Fatal("reservation returned retry wire")
				}
				if err = restarted.AbandonOwnerTextProjectMessage(project, id); err != nil {
					t.Fatal(err)
				}
				if _, err = restarted.LoadPreparedOwnerTextProjectMessage(project, id); !errors.Is(err, ErrOwnerTextProjectMessageAbandoned) {
					t.Fatal(err)
				}
			} else {
				if err != nil || len(loaded.Wire) == 0 || len(loaded.LocalEvidence) != sha256.Size {
					t.Fatalf("prepared recovery: %v", err)
				}
				if _, err = responder.DecryptOwnerTextProjectMessage(project, loaded.Wire, nil, nil); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
func TestOwnerTextSpoolAdmissionTombstoneAndReplyAfterRestart(t *testing.T) {
	project, clients := ownerTextMessageFixture(t)
	sender, responder := clients[0], clients[1]
	ask, err := sender.PrepareOwnerTextProjectMessage(project, responder.PrincipalID(), "ASK", []byte("question"), nil)
	if err != nil {
		t.Fatal(err)
	}
	receipt := ownerTextTestReceipt(ask)
	wrong := receipt
	wrong.RequestDigest = make([]byte, 32)
	if err = sender.kr.retireOwnerTextProjectMessage(sender.PrincipalID(), sender.identityPriv, project, ask.ID, wrong); err == nil {
		t.Fatal("wrong digest retired wire")
	}
	if err = sender.kr.retireOwnerTextProjectMessage(sender.PrincipalID(), sender.identityPriv, uuid.NewString(), ask.ID, receipt); err == nil {
		t.Fatal("wrong project retired wire")
	}
	injected := errors.New("retirement sync failed")
	sender.kr.pendingPairSyncDir = func(dir string) error {
		if dir == sender.kr.ownerTextProjectMessageDir(sender.PrincipalID()) {
			record, err := sender.kr.readOwnerTextProjectMessageRecord(sender.PrincipalID(), sender.identityPriv, ask.ID)
			if err == nil && record.State == "admitted" {
				return injected
			}
		}
		return syncPairDir(dir)
	}
	if err = sender.kr.retireOwnerTextProjectMessage(sender.PrincipalID(), sender.identityPriv, project, ask.ID, receipt); !errors.Is(err, injected) {
		t.Fatalf("retirement: %v", err)
	}
	restarted := reopenOwnerTextClient(t, sender)
	if err = restarted.kr.retireOwnerTextProjectMessage(sender.PrincipalID(), sender.identityPriv, project, ask.ID, receipt); err != nil {
		t.Fatal(err)
	}
	if _, err = restarted.LoadPreparedOwnerTextProjectMessage(project, ask.ID); !errors.Is(err, ErrOwnerTextProjectMessageAdmitted) {
		t.Fatalf("admitted retry: %v", err)
	}
	wrong = receipt
	wrong.AdmissionSeq++
	if err = restarted.kr.retireOwnerTextProjectMessage(sender.PrincipalID(), sender.identityPriv, project, ask.ID, wrong); err == nil {
		t.Fatal("conflicting admission accepted")
	}
	record, err := restarted.kr.loadOwnerTextProjectMessageBinding(sender.PrincipalID(), sender.identityPriv, ask.ID)
	if err != nil || record.State != "admitted" || len(record.Wire) != 0 || !bytes.Equal(record.LocalEvidence, ask.LocalEvidence) {
		t.Fatalf("tombstone: %+v %v", record, err)
	}
	reply, err := responder.PrepareOwnerTextProjectMessage(project, sender.PrincipalID(), "REPLY", []byte("answer"), ask.Wire)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := restarted.DecryptOwnerTextProjectMessage(project, reply.Wire, nil, nil)
	if err != nil || string(opened.Plaintext) != "answer" {
		t.Fatalf("tombstone reply: %v", err)
	}
	if err = restarted.AbandonOwnerTextProjectMessage(project, ask.ID); !errors.Is(err, ErrOwnerTextProjectMessageAdmitted) {
		t.Fatal(err)
	}
	if _, err = restarted.PrepareOwnerTextProjectMessageWithID(project, responder.PrincipalID(), "ASK", ask.ID, nil, nil); err == nil {
		t.Fatal("admitted ID reused")
	}
}
func TestOwnerTextSpoolRejectsForgedOrTamperedState(t *testing.T) {
	for _, kind := range []string{"mac", "canonical", "header", "wire", "evidence", "state", "cross-domain", "permissions", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			project, clients := ownerTextMessageFixture(t)
			sender, responder := clients[0], clients[1]
			prepared, err := sender.PrepareOwnerTextProjectMessage(project, responder.PrincipalID(), "ASK", []byte("message"), nil)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(sender.kr.ownerTextProjectMessageDir(sender.PrincipalID()), prepared.ID+".json")
			record, err := sender.kr.loadOwnerTextProjectMessageBinding(sender.PrincipalID(), sender.identityPriv, prepared.ID)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "header":
				record.Reservation.Header.RecipientPrincipalID = uuid.NewString()
			case "wire":
				record.Wire[0] ^= 1
			case "evidence":
				record.LocalEvidence[0] ^= 1
			case "state":
				record.State = "admitted"
			}
			raw := encodeOwnerTextProjectMessageRecord(record, sender.identityPriv)
			switch kind {
			case "mac":
				record.MAC[0] ^= 1
				raw, _ = json.Marshal(record)
			case "canonical":
				raw = append(raw, ' ')
			case "cross-domain":
				record.MAC = nil
				body, _ := json.Marshal(record)
				record.MAC = projectMessageMAC(sender.identityPriv, body)
				raw, _ = json.Marshal(record)
			}
			if err = os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if kind == "permissions" {
				if err = os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "symlink" {
				target := filepath.Join(t.TempDir(), "record")
				if err = os.WriteFile(target, raw, 0600); err != nil {
					t.Fatal(err)
				}
				if err = os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err = os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			}
			if _, err = sender.LoadPreparedOwnerTextProjectMessage(project, prepared.ID); err == nil {
				t.Fatal("tampered state accepted")
			}
		})
	}
}
func TestOwnerTextSpoolAbandonmentGCAndBudgets(t *testing.T) {
	project, clients := ownerTextMessageFixture(t)
	sender, responder := clients[0], clients[1]
	pending, err := sender.PrepareOwnerTextProjectMessage(project, responder.PrincipalID(), "ASK", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	abandoned, err := sender.PrepareOwnerTextProjectMessage(project, responder.PrincipalID(), "ASK", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = sender.AbandonOwnerTextProjectMessage(uuid.NewString(), abandoned.ID); err == nil {
		t.Fatal("wrong project abandoned message")
	}
	if err = sender.AbandonOwnerTextProjectMessage(project, abandoned.ID); err != nil {
		t.Fatal(err)
	}
	if err = sender.AbandonOwnerTextProjectMessage(project, abandoned.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = sender.LoadPreparedOwnerTextProjectMessage(project, abandoned.ID); !errors.Is(err, ErrOwnerTextProjectMessageAbandoned) {
		t.Fatal(err)
	}
	for _, id := range []string{pending.ID, abandoned.ID} {
		record, err := sender.kr.loadOwnerTextProjectMessageBinding(sender.PrincipalID(), sender.identityPriv, id)
		if err != nil {
			t.Fatal(err)
		}
		record.Reservation.ExpiresAt = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)
		if err = sender.kr.writePairFileDurable(filepath.Join(sender.kr.ownerTextProjectMessageDir(sender.PrincipalID()), id+".json"), encodeOwnerTextProjectMessageRecord(record, sender.identityPriv)); err != nil {
			t.Fatal(err)
		}
	}
	temp := filepath.Join(sender.kr.ownerTextProjectMessageDir(sender.PrincipalID()), ".pending-orphan")
	if err = os.WriteFile(temp, []byte("interrupted write"), 0600); err != nil {
		t.Fatal(err)
	}
	unlock, err := sender.kr.lockOwnerTextProjectMessages(sender.PrincipalID())
	if err != nil {
		t.Fatal(err)
	}
	usage, err := sender.kr.ownerTextProjectMessageUsage(sender.PrincipalID(), sender.identityPriv)
	unlock()
	if err != nil || usage.pending != 1 || usage.metadataBytes == 0 {
		t.Fatalf("usage: %+v %v", usage, err)
	}
	for _, path := range []string{temp, filepath.Join(sender.kr.ownerTextProjectMessageDir(sender.PrincipalID()), abandoned.ID+".json")} {
		if _, err = os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("GC retained temporary or expired tombstone")
		}
	}
	record, err := sender.kr.loadOwnerTextProjectMessageBinding(sender.PrincipalID(), sender.identityPriv, pending.ID)
	if err != nil || !bytes.Equal(record.Wire, pending.Wire) {
		t.Fatal("GC lost unresolved wire")
	}
	for _, over := range []ownerTextProjectMessageSpoolUsage{{pendingByProject: map[string]int{project: ownerTextProjectMessageSpoolCount + 1}}, {pendingBytes: ownerTextProjectMessageSpoolBytes + 1}, {metadataBytes: ownerTextProjectMessageMetadataBytes + 1}} {
		if checkOwnerTextProjectSpoolBudget(over) == nil {
			t.Fatal("budget exceeded without error")
		}
	}
	if err = checkOwnerTextProjectSpoolBudget(ownerTextProjectMessageSpoolUsage{pendingByProject: map[string]int{project: ownerTextProjectMessageSpoolCount, uuid.NewString(): ownerTextProjectMessageSpoolCount}}); err != nil {
		t.Fatal("pending count must be per project")
	}
	if !strings.Contains(string(encodeOwnerTextProjectMessageRecord(record, sender.identityPriv)), "localEvidence") {
		t.Fatal("evidence not persisted")
	}
}

func TestOwnerTextSpoolRejectsUnsafeDirectoryAndLock(t *testing.T) {
	for _, kind := range []string{"directory permissions", "directory symlink", "lock permissions", "lock symlink"} {
		t.Run(kind, func(t *testing.T) {
			project, clients := ownerTextMessageFixture(t)
			sender := clients[0]
			path := sender.kr.ownerTextProjectMessageDir(sender.PrincipalID())
			switch kind {
			case "directory permissions":
				if err := os.Mkdir(path, 0755); err != nil {
					t.Fatal(err)
				}
			case "directory symlink":
				if err := os.Symlink(t.TempDir(), path); err != nil {
					t.Fatal(err)
				}
			case "lock permissions":
				path = filepath.Join(sender.kr.root, "owner-text-project-messages.lock")
				if err := os.WriteFile(path, nil, 0644); err != nil {
					t.Fatal(err)
				}
			case "lock symlink":
				path = filepath.Join(sender.kr.root, "owner-text-project-messages.lock")
				target := filepath.Join(t.TempDir(), "lock")
				if err := os.WriteFile(target, nil, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := sender.PrepareOwnerTextProjectMessage(project, clients[1].PrincipalID(), "ASK", nil, nil); err == nil {
				t.Fatal("unsafe directory or lock accepted")
			}
		})
	}
}
func TestOwnerTextSpoolConcurrentIDReservation(t *testing.T) {
	project, clients := ownerTextMessageFixture(t)
	sender, responder := clients[0], clients[1]
	restarted := reopenOwnerTextClient(t, sender)
	id := ownerTextID(t)
	results := make(chan error, 2)
	for _, client := range []*Client{sender, restarted} {
		go func(c *Client) {
			_, err := c.PrepareOwnerTextProjectMessageWithID(project, responder.PrincipalID(), "ASK", id, []byte("one reservation"), nil)
			results <- err
		}(client)
	}
	successes := 0
	for i := 0; i < 2; i++ {
		if err := <-results; err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("successful preparations: %d", successes)
	}
	prepared, err := sender.LoadPreparedOwnerTextProjectMessage(project, id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = responder.DecryptOwnerTextProjectMessage(project, prepared.Wire, nil, nil); err != nil {
		t.Fatal(err)
	}
}
