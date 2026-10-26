package sdk

import (
	"bytes"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
)

func projectMessageFixture(t *testing.T) (string, []*Client) {
	t.Helper()
	project, network := uuid.NewString(), uuid.NewString()
	policy := sha256.Sum256([]byte("policy"))
	d := sharingProjectDescriptor{Version: 2, Suite: "X25519-HKDF-SHA256-AES-256-GCM", ProjectID: project, NetworkID: network, PolicyHash: hex.EncodeToString(policy[:]), IssuerTenantID: uuid.NewString(), IssuerUserID: uuid.NewString(), RecipientTenantID: uuid.NewString(), RecipientUserID: uuid.NewString(), Permissions: []string{"discover", "communicate"}, Limits: SharingPairLimits{4096, 1, 1, 4096, 1, 1}, ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)}
	clients := make([]*Client, 3)
	// Deterministic principal ordering keeps the canonical roster sorted.
	principals := []string{"10000000-0000-4000-8000-000000000001", "20000000-0000-4000-8000-000000000002", "30000000-0000-4000-8000-000000000003"}
	for i := range clients {
		private, err := newIdentityKey()
		if err != nil {
			t.Fatal(err)
		}
		key, _ := ecdh.X25519().NewPrivateKey(private)
		kr, err := newKeyring(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if err = kr.PersistIdentity(principals[i], "", private); err != nil {
			t.Fatal(err)
		}
		clients[i] = &Client{kr: kr, identityPriv: private, identityPub: key.PublicKey().Bytes()}
		clients[i].principalID.Store(principals[i])
		d.Roster = append(d.Roster, sharingProjectPrincipal{principals[i], base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())})
	}
	raw, _ := json.Marshal(d)
	for _, c := range clients {
		if err := c.kr.pinSharingProjectDescriptor(c.PrincipalID(), project, raw); err != nil {
			t.Fatal(err)
		}
	}
	return project, clients
}

func TestSharingProjectMessagesRoundTripAndReply(t *testing.T) {
	project, clients := projectMessageFixture(t)
	alice, bob := clients[0], clients[1]
	ask, err := alice.PrepareSharingProjectMessage(project, bob.PrincipalID(), "ASK", []byte("question"), nil)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := bob.DecryptSharingProjectMessage(project, ask.Wire, nil)
	if err != nil || string(opened.Plaintext) != "question" || opened.Header.ThreadID != ask.ID || opened.Header.CorrelationID != nil {
		t.Fatalf("ask: %+v %v", opened, err)
	}
	reply, err := bob.PrepareSharingProjectMessage(project, alice.PrincipalID(), "REPLY", []byte("answer"), ask.Wire)
	if err != nil {
		t.Fatal(err)
	}
	opened, err = alice.DecryptSharingProjectMessage(project, reply.Wire, ask.Wire)
	if err != nil || string(opened.Plaintext) != "answer" || opened.Header.CorrelationID == nil || *opened.Header.CorrelationID != ask.ID {
		t.Fatalf("reply: %+v %v", opened, err)
	}
	followup, err := alice.PrepareSharingProjectMessage(project, bob.PrincipalID(), "REPLY", []byte("thanks"), reply.Wire)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = bob.DecryptSharingProjectMessage(project, followup.Wire, reply.Wire); err != nil {
		t.Fatal(err)
	}
}

func TestSharingProjectMessagesRejectTampering(t *testing.T) {
	project, clients := projectMessageFixture(t)
	alice, bob, charlie := clients[0], clients[1], clients[2]
	ask, err := alice.PrepareSharingProjectMessage(project, bob.PrincipalID(), "ASK", []byte("secret"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = charlie.DecryptSharingProjectMessage(project, ask.Wire, nil); err == nil {
		t.Fatal("wrong recipient decrypted")
	}
	mutations := []struct {
		name   string
		mutate func(*sharingProjectMessageWire)
	}{
		{"sender", func(w *sharingProjectMessageWire) { w.SenderPrincipalID = charlie.PrincipalID() }},
		{"recipient", func(w *sharingProjectMessageWire) { w.RecipientPrincipalID = charlie.PrincipalID() }},
		{"id", func(w *sharingProjectMessageWire) { id, _ := uuid.NewV7(); w.ID = id.String(); w.ThreadID = w.ID }},
		{"createdAt", func(w *sharingProjectMessageWire) {
			w.CreatedAt = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)
		}},
		{"policy", func(w *sharingProjectMessageWire) { w.PolicyHash = string(bytes.Repeat([]byte{'0'}, 64)) }},
		{"descriptor", func(w *sharingProjectMessageWire) { w.DescriptorHash = string(bytes.Repeat([]byte{'0'}, 64)) }},
		{"padding", func(w *sharingProjectMessageWire) { w.Envelope.Enc += "=" }},
	}
	for _, tc := range mutations {
		t.Run(tc.name, func(t *testing.T) {
			var w sharingProjectMessageWire
			_ = json.Unmarshal(ask.Wire, &w)
			tc.mutate(&w)
			raw, _ := json.Marshal(w)
			if _, err := bob.DecryptSharingProjectMessage(project, raw, nil); err == nil {
				t.Fatal("tampered wire accepted")
			}
			if _, err := bob.PrepareSharingProjectMessage(project, alice.PrincipalID(), "REPLY", []byte("reply"), raw); err == nil {
				t.Fatal("untrusted predecessor authorized reply")
			}
		})
	}
	if _, err = bob.DecryptSharingProjectMessage(project, append(ask.Wire, ' '), nil); err == nil {
		t.Fatal("accepted noncanonical wire")
	}
	reply, err := bob.PrepareSharingProjectMessage(project, alice.PrincipalID(), "REPLY", []byte("answer"), ask.Wire)
	if err != nil {
		t.Fatal(err)
	}
	another, err := alice.PrepareSharingProjectMessage(project, bob.PrincipalID(), "ASK", []byte("another"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = alice.DecryptSharingProjectMessage(project, reply.Wire, another.Wire); err == nil {
		t.Fatal("reply accepted unrelated predecessor")
	}
	if _, err = charlie.PrepareSharingProjectMessage(project, alice.PrincipalID(), "REPLY", nil, ask.Wire); err == nil {
		t.Fatal("third party replied to bilateral thread")
	}
}

func TestSharingProjectMessagePreparedRestartAndCorruption(t *testing.T) {
	project, clients := projectMessageFixture(t)
	alice, bob := clients[0], clients[1]
	prepared, err := alice.PrepareSharingProjectMessage(project, bob.PrincipalID(), "ASK", []byte("retry exact bytes"), nil)
	if err != nil {
		t.Fatal(err)
	}
	kr, err := newKeyring(filepath.Dir(alice.kr.root))
	if err != nil {
		t.Fatal(err)
	}
	private, err := kr.identityKey(alice.PrincipalID())
	if err != nil {
		t.Fatal(err)
	}
	restarted := &Client{kr: kr, identityPriv: private, identityPub: alice.identityPub}
	restarted.principalID.Store(alice.PrincipalID())
	retry, err := restarted.LoadPreparedSharingProjectMessage(project, prepared.ID)
	if err != nil || !bytes.Equal(retry.Wire, prepared.Wire) {
		t.Fatalf("retry changed wire: %v", err)
	}
	path := filepath.Join(kr.projectMessageDir(alice.PrincipalID()), prepared.ID+".json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var record projectMessageRecord
	if err = json.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	if err = kr.reserveProjectMessage(alice.PrincipalID(), private, record.Reservation); err == nil {
		t.Fatal("reserved ID allowed encryption again")
	}
	changed := append([]byte(nil), prepared.Wire...)
	changed[len(changed)-2] ^= 1
	if err = kr.storeProjectMessage(alice.PrincipalID(), private, record.Reservation, changed); err == nil {
		t.Fatal("overwrote immutable wire")
	}
	record.Wire = changed
	raw, _ = json.Marshal(record)
	if err = os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = restarted.LoadPreparedSharingProjectMessage(project, prepared.ID); err == nil {
		t.Fatal("accepted corrupt spool MAC")
	}
}

func TestSharingProjectMessageReservationFailureClosesAndCommitRecovers(t *testing.T) {
	for _, commit := range []bool{false, true} {
		t.Run(map[bool]string{false: "reservation", true: "wire commit"}[commit], func(t *testing.T) {
			project, clients := projectMessageFixture(t)
			alice, bob := clients[0], clients[1]
			var captured []byte
			alice.kr.pendingPairSyncDir = func(dir string) error {
				if dir != alice.kr.projectMessageDir(alice.PrincipalID()) {
					return nil
				}
				entries, _ := os.ReadDir(dir)
				for _, entry := range entries {
					raw, _ := os.ReadFile(filepath.Join(dir, entry.Name()))
					var record projectMessageRecord
					if json.Unmarshal(raw, &record) == nil && ((len(record.Wire) > 0) == commit) {
						captured = append([]byte(nil), record.Wire...)
						return errors.New("injected sync failure")
					}
				}
				return nil
			}
			result, err := alice.PrepareSharingProjectMessage(project, bob.PrincipalID(), "ASK", []byte("crash"), nil)
			if err == nil || result.ID == "" || len(result.Wire) != 0 {
				t.Fatalf("unexpected prepare result: %+v %v", result, err)
			}
			alice.kr.pendingPairSyncDir = nil
			loaded, err := alice.LoadPreparedSharingProjectMessage(project, result.ID)
			if !commit {
				if err == nil {
					t.Fatal("incomplete reservation became retry wire")
				}
			} else if err != nil || !bytes.Equal(loaded.Wire, captured) {
				t.Fatalf("committed wire did not recover: %v", err)
			}
		})
	}
}
