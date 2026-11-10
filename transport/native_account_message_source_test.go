package transport

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/pagnet-code/pagnet/e2ee"
)

func accountContractFixture(t *testing.T) (NativeAccountMessageSource, e2ee.AAD, NativeDispatchProof) {
	t.Helper()
	raw, err := os.ReadFile("testdata/account_message_source_reply_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct{ SourceCanonical, SourceSHA256, ReplyAADCanonical, ReplyAADSHA256 string }
	if err = json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	var s NativeAccountMessageSource
	var a e2ee.AAD
	if err = json.Unmarshal([]byte(v.SourceCanonical), &s); err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal([]byte(v.ReplyAADCanonical), &a); err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]string{{v.SourceCanonical, v.SourceSHA256}, {v.ReplyAADCanonical, v.ReplyAADSHA256}} {
		h := sha256.Sum256([]byte(pair[0]))
		if hex.EncodeToString(h[:]) != pair[1] {
			t.Fatal("vector hash mismatch")
		}
	}
	if string(mustAccountSourceJSON(s)) != v.SourceCanonical || string(a.CanonicalBytes()) != v.ReplyAADCanonical {
		t.Fatal("canonical vector mismatch")
	}
	b := a.BrowserAccountReply
	return s, a, NativeDispatchProof{AccountMessageSource: &s, OwnershipID: b.OwnershipID, OwnershipGeneration: b.OwnershipGeneration, DispatchSequence: b.DispatchSequence, SourceCommandID: b.SourceCommandID, SourceAdmissionID: b.SourceAdmissionID}
}

func TestNativeAccountMessageSourceReplyVector(t *testing.T) {
	s, a, p := accountContractFixture(t)
	if err := s.ValidateReplyAAD(a, p); err != nil {
		t.Fatal(err)
	}
	if ValidNativeSourceUnion(&NativeTaskSource{}, nil, &s) || ValidNativeSourceUnion(nil, &NativeInvocationSource{}, &s) {
		t.Fatal("mixed authority accepted")
	}
	for _, mutate := range []func(*NativeAccountMessageSource){func(s *NativeAccountMessageSource) { s.Descriptor.EpochID = "new" }, func(s *NativeAccountMessageSource) { s.InputAAD.KeyEpochID = "new" }, func(s *NativeAccountMessageSource) { s.Descriptor.Sender.Kind = "principal" }, func(s *NativeAccountMessageSource) { s.SealedDigest = strings.ToUpper(s.SealedDigest) }, func(s *NativeAccountMessageSource) { s.InputAAD.NativeContent = &e2ee.NativeContentBinding{} }, func(s *NativeAccountMessageSource) { s.InputAAD.ObjectType = e2ee.ObjectTypeBrowserAccountReply }} {
		changed := s
		mutate(&changed)
		if changed.Validate() == nil {
			t.Fatal("invalid source accepted")
		}
	}
	original := p
	changed := s
	changed.SealedDigest = strings.Repeat("b", 64)
	p.AccountMessageSource = &changed
	if SameNativeDispatchProof(original, p) {
		t.Fatal("account source omitted from proof identity")
	}
}

func TestNativeAccountReplyRejectsTransplants(t *testing.T) {
	for _, field := range []string{"owner", "connection", "delegate", "message", "binding", "sealed", "epoch", "command", "admission", "ownership", "generation", "sequence", "nativeGeneration", "nativeSession", "observation", "recipient", "objectType", "reply"} {
		t.Run(field, func(t *testing.T) {
			s, a, p := accountContractFixture(t)
			key := [32]byte{1}
			env, err := e2ee.Encrypt([]byte("reply"), key, a)
			if err != nil {
				t.Fatal(err)
			}
			b := a.BrowserAccountReply
			switch field {
			case "owner":
				b.OwnerUserID = "other"
			case "connection":
				b.ConnectionID = "other"
			case "delegate":
				b.Delegate.Kind = "principal"
			case "message":
				b.MessageID = "other"
			case "binding":
				b.BindingDigest = strings.Repeat("b", 64)
			case "sealed":
				b.SealedDigest = strings.Repeat("b", 64)
			case "epoch":
				b.OriginalEpochID = "other"
				a.KeyEpochID = "other"
			case "command":
				b.SourceCommandID = "other"
			case "admission":
				b.SourceAdmissionID = "other"
			case "ownership":
				b.OwnershipID = "other"
			case "generation":
				b.OwnershipGeneration = "other"
			case "sequence":
				b.DispatchSequence++
			case "nativeGeneration":
				a.NativeContent.NativeGeneration = "other"
			case "nativeSession":
				a.NativeContent.NativeSessionID = "other"
			case "observation":
				a.NativeContent.ObservationID = "019a5a00-0000-7000-8000-000000000099"
			case "recipient":
				a.Recipient = "other"
			case "objectType":
				a.ObjectType = e2ee.ObjectTypeMessage
			case "reply":
				b.ReplyID = "other"
				a.ObjectID = "other"
			}
			if _, err = e2ee.Decrypt(env, key, a); err == nil {
				t.Fatal("transplanted ciphertext authenticated")
			}
			if field != "nativeGeneration" && field != "nativeSession" && field != "observation" && field != "reply" && s.ValidateReplyAAD(a, p) == nil {
				t.Fatal("source transplant accepted")
			}
		})
	}
}

func TestNativeAccountContractRejectsNoncanonicalJSON(t *testing.T) {
	s, a, _ := accountContractFixture(t)
	raw, _ := json.Marshal(s)
	for _, changed := range []string{strings.Replace(string(raw), `"v":1`, `"v":1,"v":1`, 1), strings.Replace(string(raw), `"messageId"`, `"MessageId"`, 1), strings.Replace(string(raw), `"v":1`, `"v":1,"unknown":true`, 1)} {
		var out NativeAccountMessageSource
		if json.Unmarshal([]byte(changed), &out) == nil {
			t.Fatal("noncanonical source accepted")
		}
	}
	raw, _ = json.Marshal(a.BrowserAccountReply)
	for _, changed := range []string{strings.Replace(string(raw), `"format":`, `"unknown":true,"format":`, 1), strings.Replace(string(raw), `"format":`, `"format":"x","format":`, 1), strings.Replace(string(raw), `"reply_id":`, `"Reply_id":`, 1)} {
		var out e2ee.BrowserAccountReplyBinding
		if json.Unmarshal([]byte(changed), &out) == nil {
			t.Fatal("noncanonical reply accepted")
		}
	}
}

func TestNativeAccountReplyFragmentsAndBindingRequirements(t *testing.T) {
	s, a, p := accountContractFixture(t)
	ordinal := 0
	a.NativeContent.Ordinal = &ordinal
	id, err := e2ee.NativeContentFragmentID(a.NativeContent.ContentID, ordinal)
	if err != nil {
		t.Fatal(err)
	}
	a.ObjectType = e2ee.ObjectTypeNativeContentFragment
	a.ObjectID = id
	if err = s.ValidateReplyAAD(a, p); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"native", "binding", "inputBinding", "purpose", "epoch", "logicalTurn", "digest", "timestamp", "commandUUID"} {
		_, a, _ := accountContractFixture(t)
		switch field {
		case "native":
			a.NativeContent = nil
		case "binding":
			a.BrowserAccountReply = nil
		case "inputBinding":
			a.BrowserAccountMessage = &e2ee.BrowserAccountMessageBinding{BindingDigest: s.BindingDigest, SenderKind: e2ee.BrowserAccountDelegateSenderKind}
		case "purpose":
			a.NativeContent.Purpose = "native_turn_output"
		case "epoch":
			a.KeyEpochID = "current-epoch"
		case "logicalTurn":
			a.BrowserAccountReply.LogicalTurnID = "pagnet-worker-turn-07"
		case "timestamp":
			a.CreatedAt = "2026-11-10T12:01:30+00:00"
		case "commandUUID":
			a.BrowserAccountReply.SourceCommandID = "command"
			a.NativeContent.SourceCommandID = "command"
		case "digest":
			a.BrowserAccountReply.SealedDigest = strings.ToUpper(a.BrowserAccountReply.SealedDigest)
		}
		if a.ValidateScope() == nil {
			t.Fatal("invalid account reply scope accepted", field)
		}
	}
}
