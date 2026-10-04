package fabric

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

func controlFixture(t *testing.T) ControlFrame {
	f := forwardFixture(t)
	return ControlFrame{ProtocolVersion: "1", SourceDomain: f.SourceDomain, SourceStoreID: f.SourceStoreID, SourceKeyRevision: f.SourceKeyRevision, DestinationDomain: f.DestinationDomain, DestinationStoreID: f.DestinationStoreID, SourcePeerBindingDigest: f.SourcePeerBindingDigest, DestinationPeerBindingDigest: f.DestinationPeerBindingDigest, Principal: f.Principal, InvocationID: f.InvocationID, ReceiptDigest: f.OriginalEnvelopeDigest, AttemptID: "original-attempt", Action: "pull", PayloadDigest: f.ForwardedEnvelopeDigest, ReplayID: "fresh-control", IssuedAt: f.IssuedAt, ExpiresAt: "2026-10-04T22:00:30Z", BindingProfile: ForwardBindingProfile}
}
func TestControlFrameBindsCurrentCallerReceiptAndExactOperation(t *testing.T) {
	f := controlFixture(t)
	raw, err := f.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(testBytes(3))
	signature := ed25519.Sign(key, raw)
	for name, change := range map[string]func(*ControlFrame){
		"principal": func(f *ControlFrame) { f.Principal.Ref += "other" },
		"issuer":    func(f *ControlFrame) { f.Principal.Issuer += "other" },
		"receipt":   func(f *ControlFrame) { f.ReceiptDigest[0] ^= 1 },
		"attempt":   func(f *ControlFrame) { f.AttemptID += "other" },
		"payload":   func(f *ControlFrame) { f.PayloadDigest[0] ^= 1 },
		"replay":    func(f *ControlFrame) { f.ReplayID += "other" },
		"operation": func(f *ControlFrame) { f.Action = "cancel" },
		"pair":      func(f *ControlFrame) { f.DestinationPeerBindingDigest[0] ^= 1 },
	} {
		t.Run(name, func(t *testing.T) {
			copy := f
			change(&copy)
			altered, e := copy.SigningBytes()
			if e == nil && ed25519.Verify(key.Public().(ed25519.PublicKey), altered, signature) {
				t.Fatal("control signature accepted changed facts")
			}
		})
	}
	forward, err := forwardFixture(t).SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(raw, forward) || ed25519.Verify(key.Public().(ed25519.PublicKey), forward, signature) {
		t.Fatal("control authorizes original invocation")
	}
}
func TestControlFrameRejectsUnboundedOrUnsupportedControl(t *testing.T) {
	for name, change := range map[string]func(*ControlFrame){
		"protocol":      func(f *ControlFrame) { f.ProtocolVersion = "2" },
		"execute":       func(f *ControlFrame) { f.Action = "invoke" },
		"no-attempt":    func(f *ControlFrame) { f.AttemptID = "" },
		"expiry":        func(f *ControlFrame) { f.ExpiresAt = "2026-10-04T22:00:31Z" },
		"zero-duration": func(f *ControlFrame) { f.ExpiresAt = f.IssuedAt },
		"same-domain":   func(f *ControlFrame) { f.DestinationDomain = f.SourceDomain },
	} {
		t.Run(name, func(t *testing.T) {
			f := controlFixture(t)
			change(&f)
			if _, err := f.SigningBytes(); err == nil {
				t.Fatal("invalid control accepted")
			}
		})
	}
	for _, action := range []string{"status", "cancel"} {
		f := controlFixture(t)
		f.Action = action
		f.AttemptID = ""
		if _, err := f.SigningBytes(); err != nil {
			t.Fatal(err)
		}
	}
}
