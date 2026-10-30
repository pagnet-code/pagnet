package sdk

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/e2ee"
)

func ownerTextMessageFixture(t *testing.T) (string, []*Client) {
	t.Helper()
	project, clients := projectMessageFixture(t)
	d := ownerTextProjectDescriptor{Version: 1, Suite: "X25519-HKDF-SHA256-AES-256-GCM", Domain: ownerTextProjectProofDomain, ProjectID: project, NetworkID: uuid.NewString(), OwnerTenantID: uuid.NewString(), OwnerUserID: uuid.NewString(), PolicyHash: "policy", Permissions: []string{"discover", "communicate"}, Limits: SharingPairLimits{4096, 1, 2, 8192, 1, 2}, ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)}
	for i, role := range []string{"sender", "responder"} {
		d.Roster = append(d.Roster, ownerTextProjectPrincipal{role, clients[i].PrincipalID(), uuid.NewString(), base64.StdEncoding.EncodeToString(clients[i].identityPub)})
	}
	raw, _ := json.Marshal(d)
	for _, c := range clients[:2] {
		if err := c.kr.pinOwnerTextProjectDescriptor(c.PrincipalID(), project, raw); err != nil {
			t.Fatal(err)
		}
	}
	return project, clients
}
func ownerTextID(t *testing.T) string {
	t.Helper()
	id, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	return id.String()
}
func TestOwnerTextMessagesRoundTripAndAuthenticatedReply(t *testing.T) {
	project, clients := ownerTextMessageFixture(t)
	sender, responder := clients[0], clients[1]
	ask, err := sender.PrepareOwnerTextProjectMessageWithID(project, responder.PrincipalID(), "ASK", ownerTextID(t), []byte("question"), nil)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := responder.DecryptOwnerTextProjectMessage(project, ask.Wire, nil, nil)
	if err != nil || string(opened.Plaintext) != "question" || opened.Header.ThreadID != ask.ID || opened.Header.CorrelationID != nil {
		t.Fatalf("ASK: %+v %v", opened, err)
	}
	reply, err := responder.PrepareOwnerTextProjectMessageWithID(project, sender.PrincipalID(), "REPLY", ownerTextID(t), []byte("answer"), ask.Wire)
	if err != nil {
		t.Fatal(err)
	}
	opened, err = sender.DecryptOwnerTextProjectMessage(project, reply.Wire, ask.Wire, ask.LocalEvidence)
	if err != nil || string(opened.Plaintext) != "answer" || *opened.Header.CorrelationID != ask.ID {
		t.Fatalf("REPLY: %+v %v", opened, err)
	}
	if _, err = sender.DecryptOwnerTextProjectMessage(project, reply.Wire, ask.Wire, nil); err == nil {
		t.Fatal("unauthenticated ASK accepted")
	}
	if _, err = sender.DecryptOwnerTextProjectMessage(project, reply.Wire, ask.Wire, reply.LocalEvidence); err == nil {
		t.Fatal("wrong evidence accepted")
	}
	if _, err = sender.PrepareOwnerTextProjectMessageWithID(project, responder.PrincipalID(), "REPLY", ownerTextID(t), nil, reply.Wire); err == nil {
		t.Fatal("REPLY-to-REPLY accepted")
	}
	if _, err = responder.PrepareOwnerTextProjectMessageWithID(project, sender.PrincipalID(), "ASK", ownerTextID(t), nil, nil); err == nil {
		t.Fatal("wrong ASK role accepted")
	}
	if _, err = sender.PrepareOwnerTextProjectMessageWithID(project, responder.PrincipalID(), "REPLY", ownerTextID(t), nil, ask.Wire); err == nil {
		t.Fatal("wrong REPLY role accepted")
	}
	if _, err = sender.PrepareOwnerTextProjectMessageWithID(project, responder.PrincipalID(), "ASK", uuid.NewString(), nil, nil); err == nil {
		t.Fatal("non-v7 ID accepted")
	}
}
func TestOwnerTextMessagesRejectTamperingAndCanonicalBytes(t *testing.T) {
	project, clients := ownerTextMessageFixture(t)
	sender, responder := clients[0], clients[1]
	ask, err := sender.PrepareOwnerTextProjectMessageWithID(project, responder.PrincipalID(), "ASK", ownerTextID(t), []byte("secret"), nil)
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*ownerTextProjectMessageWire){
		"domain":     func(w *ownerTextProjectMessageWire) { w.Domain = sharingProjectMessageInfo },
		"version":    func(w *ownerTextProjectMessageWire) { w.Version = 2 },
		"descriptor": func(w *ownerTextProjectMessageWire) { w.DescriptorHash = strings.Repeat("0", 64) },
		"recipient":  func(w *ownerTextProjectMessageWire) { w.RecipientPrincipalID = sender.PrincipalID() },
		"role": func(w *ownerTextProjectMessageWire) {
			w.SenderPrincipalID, w.RecipientPrincipalID = w.RecipientPrincipalID, w.SenderPrincipalID
		},
		"timestamp":      func(w *ownerTextProjectMessageWire) { w.CreatedAt = time.Now().Format("2006-01-02T15:04:05+00:00") },
		"base64 padding": func(w *ownerTextProjectMessageWire) { w.Envelope.Enc += "=" },
		"ciphertext": func(w *ownerTextProjectMessageWire) {
			ct, _ := base64.RawURLEncoding.DecodeString(w.Envelope.Ciphertext)
			ct[0] ^= 1
			w.Envelope.Ciphertext = base64.RawURLEncoding.EncodeToString(ct)
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			var w ownerTextProjectMessageWire
			_ = json.Unmarshal(ask.Wire, &w)
			mutate(&w)
			raw, _ := json.Marshal(w)
			if _, err := responder.DecryptOwnerTextProjectMessage(project, raw, nil, nil); err == nil {
				t.Fatal("tampering accepted")
			}
			if _, err := responder.PrepareOwnerTextProjectMessageWithID(project, sender.PrincipalID(), "REPLY", ownerTextID(t), nil, raw); err == nil {
				t.Fatal("untrusted ASK accepted")
			}
		})
	}
	for _, raw := range [][]byte{append(bytes.Clone(ask.Wire), ' '), bytes.Replace(ask.Wire, []byte(`"version":1`), []byte(`"version":1,"extra":true`), 1), bytes.Replace(ask.Wire, []byte(`{"version":1,"domain":`), []byte(`{"domain":`), 1)} {
		if _, err := responder.DecryptOwnerTextProjectMessage(project, raw, nil, nil); err == nil {
			t.Fatal("noncanonical bytes accepted")
		}
	}
	var w ownerTextProjectMessageWire
	_ = json.Unmarshal(ask.Wire, &w)
	header, _ := json.Marshal(w.OwnerTextProjectMessageHeader)
	if !bytes.HasPrefix(ask.Wire, append(bytes.Clone(header[:len(header)-1]), []byte(`,"envelope":`)...)) {
		t.Fatal("wire header order differs")
	}
	if !bytes.HasPrefix(header, []byte(`{"version":1,"domain":"pagnet/owner-text-project/message/v1","projectId":`)) {
		t.Fatal("wrong owner header order")
	}
	enc, _ := base64.RawURLEncoding.DecodeString(w.Envelope.Enc)
	ct, _ := base64.RawURLEncoding.DecodeString(w.Envelope.Ciphertext)
	if _, err = e2ee.HPKEUnwrapAuth(responder.identityPriv, sender.identityPub, enc, []byte(sharingProjectMessageInfo), header, ct); err == nil {
		t.Fatal("wrong HPKE info accepted")
	}
	if _, err = e2ee.HPKEUnwrapAuth(responder.identityPriv, sender.identityPub, enc, []byte(ownerTextProjectMessageInfo), ask.Wire, ct); err == nil {
		t.Fatal("wire used as AAD")
	}
	proofEnc, proofCT, err := e2ee.HPKEWrapAuth(responder.identityPub, sender.identityPriv, []byte(ownerTextProjectProofDomain), header, []byte("proof domain"))
	if err != nil {
		t.Fatal(err)
	}
	w.Envelope.Enc = base64.RawURLEncoding.EncodeToString(proofEnc)
	w.Envelope.Ciphertext = base64.RawURLEncoding.EncodeToString(proofCT)
	proofWire, _ := json.Marshal(w)
	if _, err = responder.DecryptOwnerTextProjectMessage(project, proofWire, nil, nil); err == nil {
		t.Fatal("proof domain ciphertext replayed as message")
	}
	if _, err = responder.DecryptSharingProjectMessage(project, ask.Wire, nil); err == nil {
		t.Fatal("owner wire replayed as sharing message")
	}
	sharing, err := sender.PrepareSharingProjectMessage(project, responder.PrincipalID(), "ASK", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = responder.DecryptOwnerTextProjectMessage(project, sharing.Wire, nil, nil); err == nil {
		t.Fatal("sharing wire replayed as owner message")
	}
}
func TestOwnerTextMessagesValidatePinnedDescriptorAndKey(t *testing.T) {
	for _, kind := range []string{"key", "role", "domain", "canonical", "identity", "installation", "expired"} {
		t.Run(kind, func(t *testing.T) {
			project, clients := ownerTextMessageFixture(t)
			sender := clients[0]
			path := filepath.Join(sender.kr.root, sender.PrincipalID(), "owner-text-projects", project+".json")
			raw, err := readPrivatePairFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var d ownerTextProjectDescriptor
			_ = json.Unmarshal(raw, &d)
			switch kind {
			case "key":
				d.Roster[0].PublicKey = d.Roster[1].PublicKey
			case "role":
				d.Roster[0].Role = "responder"
			case "domain":
				d.Domain = sharingProjectProofDomain
			case "installation":
				d.Roster[0].InstallationID = d.Roster[1].InstallationID
			case "expired":
				d.ExpiresAt = time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano)
			case "identity":
				sender.identityPriv = bytes.Repeat([]byte{7}, 32)
			}
			raw, _ = json.Marshal(d)
			if kind == "canonical" {
				raw = append(raw, ' ')
			}
			if err = os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err = sender.PrepareOwnerTextProjectMessageWithID(project, clients[1].PrincipalID(), "ASK", ownerTextID(t), nil, nil); err == nil {
				t.Fatal("invalid pin accepted")
			}
		})
	}
}
