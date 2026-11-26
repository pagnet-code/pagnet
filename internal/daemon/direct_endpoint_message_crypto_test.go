//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/transport"
)

func TestDirectTargetMessageCrypto(t *testing.T) {
	f := newReconcileMaterialFixture(t, "P")
	var vector struct{ Ask, Reply, Continuation []byte }
	raw, err := os.ReadFile("../directchannelcrypto/testdata/sdk-message-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	ask, err := transport.DecodeDirectChannelMessageV2(vector.Ask)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := transport.DecodeDirectChannelMessageV2(vector.Reply)
	if err != nil {
		t.Fatal(err)
	}
	e := publishedEnrollment(f.enrollment, f.vector.Publication)
	now := func() time.Time { return f.now }
	plaintext, err := openDirectTargetMessageAsk(context.Background(), f.subscription, f.binding, e, f.vector.Publication, f.journal.registry, now, f.operation, ask.Header.MessageID, ask.Header.RootID, vector.Ask)
	defer clear(plaintext)
	if err != nil || string(plaintext) != "question" {
		t.Fatalf("open ASK mismatch: %v", err)
	}
	// Recover the retained exact publication and root without private-key access.
	f.private = nil
	wire, err := sealDirectTargetMessageReply(context.Background(), f.subscription, f.binding, e, f.vector.Publication, f.journal.registry, now, f.operation, reply.Header.MessageID, ask.Header.RootID, vector.Ask, []byte("answer"))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := transport.DecodeDirectChannelMessageV2(wire)
	if err != nil || sealed.Header != reply.Header || transport.ValidateDirectChannelMessageForDescriptorV2(sealed, f.binding.Descriptor) != nil {
		t.Fatalf("sealed reply binding mismatch: %v", err)
	}
	tampered := ask
	ciphertext, err := base64.RawURLEncoding.DecodeString(tampered.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext[0] ^= 1
	tampered.Ciphertext = base64.RawURLEncoding.EncodeToString(ciphertext)
	tamperedWire, err := tampered.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	for name, invalid := range map[string][]byte{"tampered ask": tamperedWire, "continuation": vector.Continuation} {
		t.Run(name, func(t *testing.T) {
			out, err := sealDirectTargetMessageReply(context.Background(), f.subscription, f.binding, e, f.vector.Publication, f.journal.registry, now, f.operation, reply.Header.MessageID, ask.Header.RootID, invalid, []byte("answer"))
			if err == nil || out != nil {
				t.Fatal("sealed reply to unauthenticated or unsupported ASK")
			}
		})
	}
}

func TestDirectTargetMessageCryptoBinding(t *testing.T) {
	for _, action := range []string{"open ask", "seal reply"} {
		for _, mismatch := range []string{"publication", "publication evidence", "descriptor", "credential", "role"} {
			t.Run(action+"/"+mismatch, func(t *testing.T) {
				f := newReconcileMaterialFixture(t, "P")
				e := publishedEnrollment(f.enrollment, f.vector.Publication)
				publication := bytes.Clone(f.vector.Publication)
				switch mismatch {
				case "publication":
					publication[len(publication)-1] ^= 1
				case "publication evidence":
					e.PublicationHash = nil
				case "descriptor":
					f.binding.DescriptorHash[0] ^= 1
				case "credential":
					f.subscription.binding.metadata.CredentialID += "x"
				case "role":
					f.subscription.binding.metadata.Role = "S"
				}
				var out []byte
				var err error
				if action == "open ask" {
					out, err = openDirectTargetMessageAsk(context.Background(), f.subscription, f.binding, e, publication, f.journal.registry, func() time.Time { return f.now }, f.operation, "", "", nil)
				} else {
					out, err = sealDirectTargetMessageReply(context.Background(), f.subscription, f.binding, e, publication, f.journal.registry, func() time.Time { return f.now }, f.operation, "", "", nil, []byte("reply"))
				}
				if err == nil || out != nil {
					t.Fatalf("mismatched binding returned output or no error: %v", err)
				}
				// Evidence must fail before opening or generating epoch material.
				binding, bindingErr := enrollmentBinding(f.subscription, f.binding.Protocol, f.binding.DescriptorBytes, f.binding.LocalFingerprint, f.binding.PeerFingerprint)
				if bindingErr == nil {
					row, reserveErr := f.journal.reserve(f.subscription, binding)
					defer clear(row.Root)
					if reserveErr != nil || row.State == "material" {
						t.Fatalf("binding failure retained material: %v", reserveErr)
					}
				}
			})
		}
	}
}
