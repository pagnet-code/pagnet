package transport

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func directMessageV2Fixture(t *testing.T) (DirectChannelMessageV2, DirectChannelMessageV2, DirectChannelDescriptorV2) {
	t.Helper()
	p, c, _, _, _ := directV2TestFixture(t)
	ask := DirectChannelMessageV2{Header: DirectChannelMessageHeaderV2{
		Version: 2, Domain: DirectChannelDomainV2 + "/message", Kind: "ASK",
		ChannelID: c.ChannelID, DescriptorHash: c.DescriptorHash, EpochID: c.EpochID,
		MessageID: directV2TestID(40), RootID: directV2TestID(40), SenderRole: "S",
	}, Nonce: directV2TestBinary(1, 12), Ciphertext: directV2TestBinary(2, 16)}
	hash, err := DirectChannelMessageHashV2(ask)
	if err != nil {
		t.Fatal(err)
	}
	reply := ask
	reply.Header.Kind, reply.Header.SenderRole = "REPLY", "P"
	reply.Header.MessageID, reply.Header.AskID, reply.Header.AskWireHash = directV2TestID(41), ask.Header.MessageID, hash
	return ask, reply, p.Descriptor
}

func TestDirectChannelMessageV2Golden(t *testing.T) {
	ask, reply, d := directMessageV2Fixture(t)
	wantRaw, err := os.ReadFile("testdata/direct_channel_message_v2.golden.json")
	if err != nil {
		t.Fatal(err)
	}
	want := string(wantRaw)
	raw, err := ask.CanonicalBytes()
	if err != nil || string(raw) != want {
		t.Fatalf("golden wire: %s, %v", raw, err)
	}
	hash, err := DirectChannelMessageHashV2(ask)
	if err != nil || hash != "8IpGKgfV0wnEEMQ-j-lbvrgaFOr81ooCuvZgH5Zf3O8" {
		t.Fatalf("golden hash: %s, %v", hash, err)
	}
	for _, w := range []DirectChannelMessageV2{ask, reply} {
		raw, err := w.CanonicalBytes()
		if err != nil {
			t.Fatal(err)
		}
		got, err := DecodeDirectChannelMessageV2(raw)
		if err != nil || got != w {
			t.Fatalf("round trip: %v", err)
		}
		if err := ValidateDirectChannelMessageForDescriptorV2(w, d); err != nil {
			t.Fatal(err)
		}
	}
	if err := ValidateDirectChannelReplyToV2(reply, ask); err != nil {
		t.Fatal(err)
	}
	continuation := ask
	continuation.Header.MessageID = directV2TestID(42)
	continuation.Header.ParentMessageID = reply.Header.MessageID
	continuation.Header.ParentWireHash, _ = DirectChannelMessageHashV2(reply)
	if _, err := continuation.CanonicalBytes(); err != nil {
		t.Fatal(err)
	}
}

func TestDirectChannelMessageV2StrictDecode(t *testing.T) {
	ask, _, _ := directMessageV2Fixture(t)
	raw, _ := ask.CanonicalBytes()
	bad := map[string][]byte{
		"empty":           nil,
		"whitespace":      append([]byte(" "), raw...),
		"trailing":        append(append([]byte{}, raw...), []byte("{}")...),
		"oversize":        bytes.Repeat([]byte(" "), DirectChannelMessageMaxBytesV2+1),
		"unknown":         bytes.Replace(raw, []byte(`"version":2`), []byte(`"unknown":0,"version":2`), 1),
		"duplicate":       bytes.Replace(raw, []byte(`"version":2`), []byte(`"version":2,"version":2`), 1),
		"missing_empty":   bytes.Replace(raw, []byte(`,"askId":""`), nil, 1),
		"null_empty":      bytes.Replace(raw, []byte(`"askId":""`), []byte(`"askId":null`), 1),
		"number_spelling": bytes.Replace(raw, []byte(`"version":2`), []byte(`"version":2.0`), 1),
		"escaped":         bytes.Replace(raw, []byte(`"kind":"ASK"`), []byte(`"kind":"\u0041SK"`), 1),
		"order":           bytes.Replace(raw, []byte(`"version":2,"domain":"pagnet/direct_ask_reply_v2/message"`), []byte(`"domain":"pagnet/direct_ask_reply_v2/message","version":2`), 1),
		"malformed_utf8":  append([]byte{0xff}, raw...),
	}
	for name, b := range bad {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeDirectChannelMessageV2(b); err == nil {
				t.Fatal("accepted noncanonical wire")
			}
		})
	}
}

func TestDirectChannelMessageV2Malformed(t *testing.T) {
	ask, reply, _ := directMessageV2Fixture(t)
	cases := map[string]func(*DirectChannelMessageV2){
		"version":          func(w *DirectChannelMessageV2) { w.Header.Version = 1 },
		"domain":           func(w *DirectChannelMessageV2) { w.Header.Domain += "/x" },
		"kind":             func(w *DirectChannelMessageV2) { w.Header.Kind = "ask" },
		"role":             func(w *DirectChannelMessageV2) { w.Header.SenderRole = "P" },
		"channel":          func(w *DirectChannelMessageV2) { w.Header.ChannelID += "=" },
		"descriptor":       func(w *DirectChannelMessageV2) { w.Header.DescriptorHash = directV2TestBinary(1, 31) },
		"epoch_version":    func(w *DirectChannelMessageV2) { w.Header.EpochID = directV2TestID(1) },
		"epoch_variant":    func(w *DirectChannelMessageV2) { w.Header.EpochID = "01900000-0000-7000-c000-000000000001" },
		"uuid_nil":         func(w *DirectChannelMessageV2) { w.Header.MessageID = "00000000-0000-0000-0000-000000000000" },
		"uuid_upper":       func(w *DirectChannelMessageV2) { w.Header.RootID = "00000000-0000-4000-8000-0000000000AF" },
		"uuid_compact":     func(w *DirectChannelMessageV2) { w.Header.MessageID = strings.ReplaceAll(w.Header.MessageID, "-", "") },
		"initial_root":     func(w *DirectChannelMessageV2) { w.Header.RootID = directV2TestID(50) },
		"parent_only":      func(w *DirectChannelMessageV2) { w.Header.ParentMessageID = directV2TestID(50) },
		"parent_hash_only": func(w *DirectChannelMessageV2) { w.Header.ParentWireHash = directV2TestBinary(1, 32) },
		"continuation_root": func(w *DirectChannelMessageV2) {
			w.Header.ParentMessageID = directV2TestID(50)
			w.Header.ParentWireHash = directV2TestBinary(1, 32)
		},
		"ask_link":           func(w *DirectChannelMessageV2) { w.Header.AskID = directV2TestID(50) },
		"ask_hash":           func(w *DirectChannelMessageV2) { w.Header.AskWireHash = directV2TestBinary(1, 32) },
		"nonce":              func(w *DirectChannelMessageV2) { w.Nonce = directV2TestBinary(1, 11) },
		"nonce_padding":      func(w *DirectChannelMessageV2) { w.Nonce += "=" },
		"ciphertext_short":   func(w *DirectChannelMessageV2) { w.Ciphertext = directV2TestBinary(1, 15) },
		"ciphertext_padding": func(w *DirectChannelMessageV2) { w.Ciphertext += "==" },
		"reply_self":         func(w *DirectChannelMessageV2) { *w = reply; w.Header.MessageID = w.Header.AskID },
		"reply_parent":       func(w *DirectChannelMessageV2) { *w = reply; w.Header.ParentMessageID = directV2TestID(50) },
		"reply_missing_ask":  func(w *DirectChannelMessageV2) { *w = reply; w.Header.AskID = "" },
		"reply_missing_hash": func(w *DirectChannelMessageV2) { *w = reply; w.Header.AskWireHash = "" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			w := ask
			change(&w)
			if _, err := w.CanonicalBytes(); err == nil {
				t.Fatal("accepted malformed message")
			}
			raw, _ := json.Marshal(w)
			if _, err := DecodeDirectChannelMessageV2(raw); err == nil {
				t.Fatal("decoded malformed message")
			}
		})
	}
}

func TestDirectChannelMessageV2BindingsAndCaps(t *testing.T) {
	ask, reply, d := directMessageV2Fixture(t)
	for _, field := range []string{"channel", "descriptor", "epoch"} {
		t.Run(field, func(t *testing.T) {
			w := reply
			switch field {
			case "channel":
				w.Header.ChannelID = directV2TestBinary(5, 32)
			case "descriptor":
				w.Header.DescriptorHash = directV2TestBinary(5, 32)
			case "epoch":
				w.Header.EpochID = "01900000-0000-7000-8000-000000000002"
			}
			if ValidateDirectChannelMessageForDescriptorV2(w, d) == nil || ValidateDirectChannelReplyToV2(w, ask) == nil {
				t.Fatal("accepted binding mismatch")
			}
		})
	}
	for _, field := range []string{"root", "ask", "hash", "nonce", "ciphertext"} {
		t.Run(field, func(t *testing.T) {
			a, r := ask, reply
			switch field {
			case "root":
				r.Header.RootID = directV2TestID(55)
			case "ask":
				r.Header.AskID = directV2TestID(55)
			case "hash":
				r.Header.AskWireHash = directV2TestBinary(5, 32)
			case "nonce":
				a.Nonce = directV2TestBinary(5, 12)
			case "ciphertext":
				a.Ciphertext = directV2TestBinary(5, 16)
			}
			if ValidateDirectChannelReplyToV2(r, a) == nil {
				t.Fatal("accepted reply mismatch")
			}
		})
	}
	if ValidateDirectChannelReplyToV2(ask, reply) == nil {
		t.Fatal("accepted reversed kinds")
	}
	ask.Ciphertext = directV2TestBinary(2, 3000)
	if _, err := ask.CanonicalBytes(); err != nil {
		t.Fatal(err)
	}
	if ValidateDirectChannelMessageForDescriptorV2(ask, d) == nil {
		t.Fatal("accepted descriptor cap overflow")
	}
	ask.Ciphertext = directV2TestBinary(2, 49000)
	if _, err := ask.CanonicalBytes(); err == nil {
		t.Fatal("accepted global cap overflow")
	}
}
