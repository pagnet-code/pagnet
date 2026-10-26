package sdk

import (
	"bytes"
	"context"
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

func projectTestReceipt(prepared PreparedSharingProjectMessage) SharingProjectMessageReceipt {
	digest := sha256.Sum256(prepared.Wire)
	return SharingProjectMessageReceipt{MessageID: prepared.ID, AdmissionSeq: 1, RequestDigest: digest[:], Status: "pending", CreatedAt: time.Now().UTC()}
}
func TestSharingProjectMessageSequentialAdmissionCapacity(t *testing.T) {
	f := newProjectTransportFixture(t)
	alice, bob := f.clients[0], f.clients[1]
	for i := 0; i < projectMessageSpoolCount+1; i++ {
		prepared, err := alice.PrepareSharingProjectMessage(f.project, bob.PrincipalID(), "ASK", []byte("send"), nil)
		if err != nil {
			t.Fatalf("prepare %d: %v", i, err)
		}
		if _, err = alice.SendPreparedSharingProjectMessage(context.Background(), f.project, prepared.ID); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	unlock, err := alice.kr.lockProjectMessages(alice.PrincipalID())
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	usage, err := alice.kr.projectMessageUsage(alice.PrincipalID(), alice.identityPriv)
	if err != nil || usage.pending != 0 || usage.pendingBytes != 0 || f.posts != 257 {
		t.Fatalf("capacity not released: %+v, %v, posts %d", usage, err, f.posts)
	}
}

func TestSharingProjectMessageRetirementBindingsAndFault(t *testing.T) {
	project, clients := projectMessageFixture(t)
	alice, bob := clients[0], clients[1]
	prepared, err := alice.PrepareSharingProjectMessage(project, bob.PrincipalID(), "ASK", []byte("retain until confirmed"), nil)
	if err != nil {
		t.Fatal(err)
	}
	receipt := projectTestReceipt(prepared)
	wrong := receipt
	wrong.RequestDigest = make([]byte, 32)
	if err = alice.kr.retireProjectMessage(alice.PrincipalID(), alice.identityPriv, project, prepared.ID, wrong); err == nil {
		t.Fatal("wrong receipt retired wire")
	}
	if err = alice.kr.retireProjectMessage(alice.PrincipalID(), alice.identityPriv, uuid.NewString(), prepared.ID, receipt); err == nil {
		t.Fatal("wrong project retired wire")
	}
	retry, err := alice.LoadPreparedSharingProjectMessage(project, prepared.ID)
	if err != nil || !bytes.Equal(retry.Wire, prepared.Wire) {
		t.Fatal("rejected receipt changed wire")
	}
	injected := errors.New("retirement sync failed")
	alice.kr.pendingPairSyncDir = func(dir string) error {
		if dir == alice.kr.projectMessageDir(alice.PrincipalID()) {
			record, err := alice.kr.readProjectMessageRecord(alice.PrincipalID(), alice.identityPriv, prepared.ID)
			if err == nil && record.State == "admitted" {
				return injected
			}
		}
		return syncPairDir(dir)
	}
	if err = alice.kr.retireProjectMessage(alice.PrincipalID(), alice.identityPriv, project, prepared.ID, receipt); !errors.Is(err, injected) {
		t.Fatalf("ignored retirement sync failure: %v", err)
	}
	alice.kr.pendingPairSyncDir = nil
	reopened, err := newKeyring(filepath.Dir(alice.kr.root))
	if err != nil {
		t.Fatal(err)
	}
	if err = reopened.retireProjectMessage(alice.PrincipalID(), alice.identityPriv, project, prepared.ID, receipt); err != nil {
		t.Fatalf("idempotent retirement recovery: %v", err)
	}
	if _, err = alice.LoadPreparedSharingProjectMessage(project, prepared.ID); !errors.Is(err, ErrSharingProjectMessageAdmitted) {
		t.Fatalf("admitted message remained retryable: %v", err)
	}
	record, err := reopened.loadProjectMessageBinding(alice.PrincipalID(), alice.identityPriv, prepared.ID)
	if err != nil || len(record.Wire) != 0 || record.State != "admitted" {
		t.Fatalf("bad tombstone: %+v %v", record, err)
	}
	wrong = receipt
	wrong.AdmissionSeq++
	if err = reopened.retireProjectMessage(alice.PrincipalID(), alice.identityPriv, project, prepared.ID, wrong); err == nil {
		t.Fatal("conflicting admission replaced tombstone")
	}
}

func TestSharingProjectMessageReplyAfterRetirementRestart(t *testing.T) {
	project, clients := projectMessageFixture(t)
	alice, bob := clients[0], clients[1]
	ask, err := alice.PrepareSharingProjectMessage(project, bob.PrincipalID(), "ASK", []byte("question"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = alice.kr.retireProjectMessage(alice.PrincipalID(), alice.identityPriv, project, ask.ID, projectTestReceipt(ask)); err != nil {
		t.Fatal(err)
	}
	reply, err := bob.PrepareSharingProjectMessage(project, alice.PrincipalID(), "REPLY", []byte("answer"), ask.Wire)
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := newKeyring(filepath.Dir(alice.kr.root))
	if err != nil {
		t.Fatal(err)
	}
	private, err := reopened.identityKey(alice.PrincipalID())
	if err != nil {
		t.Fatal(err)
	}
	restarted := &Client{kr: reopened, identityPriv: private, identityPub: alice.identityPub}
	restarted.principalID.Store(alice.PrincipalID())
	for _, predecessor := range [][]byte{nil, ask.Wire} {
		result, err := restarted.DecryptSharingProjectMessage(project, reply.Wire, predecessor)
		if err != nil || string(result.Plaintext) != "answer" {
			t.Fatalf("tombstone predecessor failed: %v", err)
		}
	}
	var altered sharingProjectMessageWire
	_ = json.Unmarshal(ask.Wire, &altered)
	altered.CreatedAt = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)
	raw, _ := json.Marshal(altered)
	if _, err = restarted.DecryptSharingProjectMessage(project, reply.Wire, raw); err == nil {
		t.Fatal("tombstone accepted changed predecessor bytes")
	}
}

func TestSharingProjectMessageExpiredTombstoneGCAndPendingSurvival(t *testing.T) {
	project, clients := projectMessageFixture(t)
	alice, bob := clients[0], clients[1]
	admitted, err := alice.PrepareSharingProjectMessage(project, bob.PrincipalID(), "ASK", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := alice.PrepareSharingProjectMessage(project, bob.PrincipalID(), "ASK", []byte("unresolved"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = alice.kr.retireProjectMessage(alice.PrincipalID(), alice.identityPriv, project, admitted.ID, projectTestReceipt(admitted)); err != nil {
		t.Fatal(err)
	}
	abandoned, err := alice.PrepareSharingProjectMessage(project, bob.PrincipalID(), "ASK", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = alice.AbandonSharingProjectMessage(project, abandoned.ID); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{admitted.ID, pending.ID, abandoned.ID} {
		record, err := alice.kr.loadProjectMessageBinding(alice.PrincipalID(), alice.identityPriv, id)
		if err != nil {
			t.Fatal(err)
		}
		record.Reservation.ExpiresAt = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)
		path := filepath.Join(alice.kr.projectMessageDir(alice.PrincipalID()), id+".json")
		if err = alice.kr.writePairFileDurable(path, encodeProjectMessageRecord(record, alice.identityPriv)); err != nil {
			t.Fatal(err)
		}
	}
	temp := filepath.Join(alice.kr.projectMessageDir(alice.PrincipalID()), ".pending-orphan")
	if err = os.WriteFile(temp, bytes.Repeat([]byte{1}, 1000), 0o600); err != nil {
		t.Fatal(err)
	}
	unlock, err := alice.kr.lockProjectMessages(alice.PrincipalID())
	if err != nil {
		t.Fatal(err)
	}
	usage, err := alice.kr.projectMessageUsage(alice.PrincipalID(), alice.identityPriv)
	unlock()
	if err != nil || usage.pending != 1 {
		t.Fatalf("GC usage: %+v %v", usage, err)
	}
	if _, err = os.Stat(filepath.Join(alice.kr.projectMessageDir(alice.PrincipalID()), admitted.ID+".json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("expired admitted tombstone survived GC")
	}
	if _, err = os.Stat(filepath.Join(alice.kr.projectMessageDir(alice.PrincipalID()), abandoned.ID+".json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("expired abandoned tombstone survived GC")
	}
	if _, err = os.Stat(temp); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("orphan atomic-write file survived GC")
	}
	info, err := os.Stat(filepath.Join(alice.kr.projectMessageDir(alice.PrincipalID()), pending.ID+".json"))
	if err != nil || int(info.Size()) != usage.pendingBytes {
		t.Fatalf("serialized pending bytes not charged: %v", err)
	}
	record, err := alice.kr.loadProjectMessageBinding(alice.PrincipalID(), alice.identityPriv, pending.ID)
	if err != nil || !bytes.Equal(record.Wire, pending.Wire) {
		t.Fatalf("expiry deleted unresolved wire: %v", err)
	}
}

func TestSharingProjectMessageMetadataBackpressure(t *testing.T) {
	project, clients := projectMessageFixture(t)
	alice, bob := clients[0], clients[1]
	prepared, err := alice.PrepareSharingProjectMessage(project, bob.PrincipalID(), "ASK", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = alice.kr.retireProjectMessage(alice.PrincipalID(), alice.identityPriv, project, prepared.ID, projectTestReceipt(prepared)); err != nil {
		t.Fatal(err)
	}
	record, err := alice.kr.loadProjectMessageBinding(alice.PrincipalID(), alice.identityPriv, prepared.ID)
	if err != nil {
		t.Fatal(err)
	}
	// Populate valid MACed live metadata directly to avoid thousands of needless
	// HPKE operations; this exercises the actual directory quota and reservation.
	perRecord := projectRecordMetadataBytes(record)
	for total := perRecord; total+perRecord <= projectMessageMetadataBytes; total += perRecord {
		id, _ := uuid.NewV7()
		record.Reservation.Header.ID = id.String()
		record.Reservation.Header.ThreadID = id.String()
		if err = os.WriteFile(filepath.Join(alice.kr.projectMessageDir(alice.PrincipalID()), id.String()+".json"), encodeProjectMessageRecord(record, alice.identityPriv), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	result, err := alice.PrepareSharingProjectMessage(project, bob.PrincipalID(), "ASK", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "metadata limit") {
		t.Fatalf("no metadata backpressure: %v", err)
	}
	if _, err = os.Stat(filepath.Join(alice.kr.projectMessageDir(alice.PrincipalID()), result.ID+".json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("metadata overflow created reservation")
	}
	if _, err = alice.kr.loadProjectMessageBinding(alice.PrincipalID(), alice.identityPriv, prepared.ID); err != nil {
		t.Fatalf("live predecessor evidence evicted: %v", err)
	}
}

func TestSharingProjectMessageHistoricalReceiptWithoutActiveDescriptor(t *testing.T) {
	for _, state := range []string{"expired", "revoked"} {
		t.Run(state, func(t *testing.T) {
			f := newProjectTransportFixture(t)
			alice, bob := f.clients[0], f.clients[1]
			prepared, err := alice.PrepareSharingProjectMessage(f.project, bob.PrincipalID(), "ASK", nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			f.wire = prepared.Wire
			f.status.State = state
			// Historical sender authority comes from the local authenticated record;
			// descriptor absence must not prevent recovery after expiry or revocation.
			path := filepath.Join(alice.kr.root, alice.PrincipalID(), "sharing-projects", f.project+".json")
			if err = os.Remove(path); err != nil {
				t.Fatal(err)
			}
			f.endpoint = "endpoint-reconnected"
			alice.endpointID.Store(f.endpoint)
			alice.connGeneration.Add(1)
			receipt, err := alice.SharingProjectMessageReceipt(context.Background(), f.project, prepared.ID)
			if err != nil || receipt.MessageID != prepared.ID || f.receipts != 1 || f.posts != 0 || f.proofs != 0 {
				t.Fatalf("historical receipt failed: %+v %v", receipt, err)
			}
			if _, err = alice.LoadPreparedSharingProjectMessage(f.project, prepared.ID); !errors.Is(err, ErrSharingProjectMessageAdmitted) {
				t.Fatalf("historical admission retained retry wire: %v", err)
			}
		})
	}
}

func TestSharingProjectMessageExplicitAbandonment(t *testing.T) {
	for _, reserved := range []bool{false, true} {
		t.Run(map[bool]string{false: "uncertain prepared", true: "unresolved reservation"}[reserved], func(t *testing.T) {
			project, clients := projectMessageFixture(t)
			alice, bob := clients[0], clients[1]
			prepared, err := alice.PrepareSharingProjectMessage(project, bob.PrincipalID(), "ASK", []byte("keep until explicit abandon"), nil)
			if err != nil {
				t.Fatal(err)
			}
			record, err := alice.kr.loadProjectMessageBinding(alice.PrincipalID(), alice.identityPriv, prepared.ID)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(alice.kr.projectMessageDir(alice.PrincipalID()), prepared.ID+".json")
			if reserved {
				record.State = "reserved"
				record.Wire = nil
				record.WireDigest = ""
				if err = alice.kr.writePairFileDurable(path, encodeProjectMessageRecord(record, alice.identityPriv)); err != nil {
					t.Fatal(err)
				}
			}
			// Maintenance preserves uncertain ciphertext and incomplete reservations,
			// including in active projects; only this explicit API can forfeit retries.
			unlock, err := alice.kr.lockProjectMessages(alice.PrincipalID())
			if err != nil {
				t.Fatal(err)
			}
			usage, err := alice.kr.projectMessageUsage(alice.PrincipalID(), alice.identityPriv)
			unlock()
			if err != nil || usage.pending != 1 {
				t.Fatalf("implicit abandonment: %+v %v", usage, err)
			}
			if !reserved {
				retry, err := alice.LoadPreparedSharingProjectMessage(project, prepared.ID)
				if err != nil || !bytes.Equal(retry.Wire, prepared.Wire) {
					t.Fatal("wire changed before explicit abandonment")
				}
			}
			if err = alice.AbandonSharingProjectMessage(project, prepared.ID); err != nil {
				t.Fatal(err)
			}
			if err = alice.AbandonSharingProjectMessage(project, prepared.ID); err != nil {
				t.Fatalf("abandonment not idempotent: %v", err)
			}
			if _, err = alice.LoadPreparedSharingProjectMessage(project, prepared.ID); !errors.Is(err, ErrSharingProjectMessageAbandoned) {
				t.Fatalf("abandoned message retryable: %v", err)
			}
			if err = alice.kr.reserveProjectMessage(alice.PrincipalID(), alice.identityPriv, record.Reservation); err == nil {
				t.Fatal("abandoned ID re-reserved")
			}
			if err = alice.kr.storeProjectMessage(alice.PrincipalID(), alice.identityPriv, record.Reservation, prepared.Wire); !errors.Is(err, ErrSharingProjectMessageAbandoned) {
				t.Fatalf("abandoned ID reencrypted: %v", err)
			}
			tombstone, err := alice.kr.readProjectMessageRecord(alice.PrincipalID(), alice.identityPriv, prepared.ID)
			if err != nil || tombstone.State != "abandoned" || len(tombstone.Wire) != 0 || tombstone.WireDigest != record.WireDigest {
				t.Fatalf("abandoned evidence lost: %+v %v", tombstone, err)
			}
			unlock, err = alice.kr.lockProjectMessages(alice.PrincipalID())
			if err != nil {
				t.Fatal(err)
			}
			usage, err = alice.kr.projectMessageUsage(alice.PrincipalID(), alice.identityPriv)
			unlock()
			if err != nil || usage.pending != 0 || usage.pendingBytes != 0 {
				t.Fatalf("abandonment did not release pending capacity: %+v %v", usage, err)
			}
		})
	}
}

func TestSharingProjectMessagePendingCountPartitionedByProject(t *testing.T) {
	project, clients := projectMessageFixture(t)
	alice, bob := clients[0], clients[1]
	prepared, err := alice.PrepareSharingProjectMessage(project, bob.PrincipalID(), "ASK", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	record, err := alice.kr.loadProjectMessageBinding(alice.PrincipalID(), alice.identityPriv, prepared.ID)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i < projectMessageSpoolCount; i++ {
		id, _ := uuid.NewV7()
		record.Reservation.Header.ID = id.String()
		record.Reservation.Header.ThreadID = id.String()
		record.State = "reserved"
		record.Wire = nil
		record.WireDigest = ""
		if err = os.WriteFile(filepath.Join(alice.kr.projectMessageDir(alice.PrincipalID()), id.String()+".json"), encodeProjectMessageRecord(record, alice.identityPriv), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = alice.PrepareSharingProjectMessage(project, bob.PrincipalID(), "ASK", nil, nil); err == nil || !strings.Contains(err.Error(), "SharingProjectMessageReceipt") {
		t.Fatalf("missing actionable project count limit: %v", err)
	}
	d, _, err := alice.projectMessageDescriptor(project)
	if err != nil {
		t.Fatal(err)
	}
	d.ProjectID = uuid.NewString()
	raw, _ := json.Marshal(d)
	if err = alice.kr.pinSharingProjectDescriptor(alice.PrincipalID(), d.ProjectID, raw); err != nil {
		t.Fatal(err)
	}
	if _, err = alice.PrepareSharingProjectMessage(d.ProjectID, bob.PrincipalID(), "ASK", nil, nil); err != nil {
		t.Fatalf("old project pending count blocked new project: %v", err)
	}
}

func TestSharingProjectMessageWrongServerReceiptPreservesRetry(t *testing.T) {
	f := newProjectTransportFixture(t)
	alice, bob := f.clients[0], f.clients[1]
	prepared, err := alice.PrepareSharingProjectMessage(f.project, bob.PrincipalID(), "ASK", []byte("uncertain"), nil)
	if err != nil {
		t.Fatal(err)
	}
	f.badDigest = true
	if _, err = alice.SendPreparedSharingProjectMessage(context.Background(), f.project, prepared.ID); err == nil {
		t.Fatal("accepted wrong server admission digest")
	}
	if _, err = alice.SharingProjectMessageReceipt(context.Background(), f.project, prepared.ID); err == nil {
		t.Fatal("accepted wrong historical receipt digest")
	}
	retry, err := alice.LoadPreparedSharingProjectMessage(f.project, prepared.ID)
	if err != nil || !bytes.Equal(retry.Wire, prepared.Wire) {
		t.Fatal("wrong receipt discarded uncertain wire")
	}
	f.badDigest = false
	if _, err = alice.SharingProjectMessageReceipt(context.Background(), f.project, prepared.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = alice.LoadPreparedSharingProjectMessage(f.project, prepared.ID); !errors.Is(err, ErrSharingProjectMessageAdmitted) {
		t.Fatalf("confirmed receipt did not retire wire: %v", err)
	}
}
