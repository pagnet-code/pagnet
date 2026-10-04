package fabric

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func forwardFixture(t *testing.T) ForwardFrame {
	t.Helper()
	source, e := DomainNamespace(testBytes(0))
	if e != nil {
		t.Fatal(e)
	}
	destination, e := DomainNamespace(testBytes(1))
	if e != nil {
		t.Fatal(e)
	}
	ref, e := NewEndpointRef(testBytes(1))
	if e != nil {
		t.Fatal(e)
	}
	h := sha256.Sum256([]byte("actual-frame-fixture"))
	return ForwardFrame{SourceDomain: source, SourceStoreID: hex.EncodeToString(h[:]), SourceKeyRevision: 1, DestinationDomain: destination, DestinationStoreID: hex.EncodeToString(h[:]), SourcePeerBindingDigest: h, DestinationPeerBindingDigest: h, Principal: Principal{Ref: "spiffe://source/用户", Kind: "actor.agent", Issuer: source}, Operation: OperationInvoke, InvocationID: "original-invocation", ReplayID: "retained-replay", OriginalEnvelopeDigest: h, ForwardedEnvelopeDigest: h, OriginalProvenance: Provenance{Origin: "spiffe://source/用户"}, ForwardedProvenance: Provenance{Origin: "spiffe://source/用户", Hops: 1, ExtensionChain: []string{"acme.security"}}, Target: &ref, ExpectedRevision: "revision-1", IssuedAt: "2026-10-04T22:00:00Z", ExpiresAt: "2026-10-04T22:05:00Z", Deadline: "2026-10-04T22:10:00Z", BindingProfile: ForwardBindingProfile}
}

func TestForwardFrameCommitsExactTrustIdentityAndLineage(t *testing.T) {
	f := forwardFixture(t)
	raw, err := f.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	private := ed25519.NewKeyFromSeed(testBytes(3))
	signature := ed25519.Sign(private, raw)
	for name, mutate := range map[string]func(*ForwardFrame){
		"sourceStore":        func(f *ForwardFrame) { f.SourceStoreID = strings.Repeat("a", 64) },
		"destinationStore":   func(f *ForwardFrame) { f.DestinationStoreID = strings.Repeat("b", 64) },
		"sourceRevision":     func(f *ForwardFrame) { f.SourceKeyRevision++ },
		"sourceBinding":      func(f *ForwardFrame) { f.SourcePeerBindingDigest[0] ^= 1 },
		"destinationBinding": func(f *ForwardFrame) { f.DestinationPeerBindingDigest[0] ^= 1 },
		"principalRef":       func(f *ForwardFrame) { f.Principal.Ref += "x" },
		"principalKind":      func(f *ForwardFrame) { f.Principal.Kind = "actor.human" },
		"principalIssuer":    func(f *ForwardFrame) { f.Principal.Issuer += "x" },
		"invocation":         func(f *ForwardFrame) { f.InvocationID += "x" },
		"replay":             func(f *ForwardFrame) { f.ReplayID += "x" },
		"originalDigest":     func(f *ForwardFrame) { f.OriginalEnvelopeDigest[0] ^= 1 },
		"forwardedDigest":    func(f *ForwardFrame) { f.ForwardedEnvelopeDigest[0] ^= 1 },
		"originalLineage":    func(f *ForwardFrame) { f.OriginalProvenance.ParentID = "different-parent" },
		"forwardedLineage":   func(f *ForwardFrame) { f.ForwardedProvenance.ExtensionChain = []string{"another.extension"} },
		"target":             func(f *ForwardFrame) { r, _ := NewEndpointRef(testBytes(1)); f.Target = &r },
		"revision":           func(f *ForwardFrame) { f.ExpectedRevision = "revision-2" },
		"expiry":             func(f *ForwardFrame) { f.ExpiresAt = "2026-10-04T22:04:00Z" },
		"deadline":           func(f *ForwardFrame) { f.Deadline = "2026-10-04T22:09:00Z" },
	} {
		t.Run(name, func(t *testing.T) {
			b, _ := json.Marshal(f)
			var changed ForwardFrame
			if e := DecodeJSON(b, &changed); e != nil {
				t.Fatal(e)
			}
			mutate(&changed)
			other, e := changed.SigningBytes()
			if e != nil {
				t.Fatal(e)
			}
			if bytes.Equal(raw, other) || ed25519.Verify(private.Public().(ed25519.PublicKey), other, signature) {
				t.Fatal("forward proof omitted field")
			}
		})
	}
	// Existing caller/admission signatures cannot cross this purpose boundary.
	if bytes.HasPrefix(raw, []byte(callerSigningPurpose)) || bytes.HasPrefix(raw, []byte(admissionSigningPurpose)) {
		t.Fatal("ordinary caller proof reused")
	}
}

func TestForwardFrameRejectsAmbiguousTargetsAndValidity(t *testing.T) {
	f := forwardFixture(t)
	for name, mutate := range map[string]func(*ForwardFrame){
		"sameDomain":       func(f *ForwardFrame) { f.DestinationDomain = f.SourceDomain },
		"storeID":          func(f *ForwardFrame) { f.SourceStoreID = "database-row-id" },
		"zeroPeer":         func(f *ForwardFrame) { f.DestinationPeerBindingDigest = [32]byte{} },
		"noTarget":         func(f *ForwardFrame) { f.Target = nil },
		"wrongTarget":      func(f *ForwardFrame) { r, _ := NewEndpointRef(testBytes(0)); f.Target = &r },
		"readTarget":       func(f *ForwardFrame) { f.Operation = OperationDescribe },
		"unknownOperation": func(f *ForwardFrame) { f.Operation = "smart-invoke" },
		"missingExpiry":    func(f *ForwardFrame) { f.ExpiresAt = "" },
		"unbounded":        func(f *ForwardFrame) { f.ExpiresAt = "2027-10-04T22:05:00Z" },
		"deadlineExtended": func(f *ForwardFrame) { f.Deadline = "2026-10-04T22:04:00Z" },
		"backward":         func(f *ForwardFrame) { f.ExpiresAt = f.IssuedAt },
		"nonCanonicalTime": func(f *ForwardFrame) { f.IssuedAt = "2026-10-04T23:00:00+01:00" },
		"lineageHops":      func(f *ForwardFrame) { f.ForwardedProvenance.Hops = 65 },
		"bindingProfile":   func(f *ForwardFrame) { f.BindingProfile = "ordinary-encryption" },
	} {
		t.Run(name, func(t *testing.T) {
			b, _ := json.Marshal(f)
			var changed ForwardFrame
			_ = json.Unmarshal(b, &changed)
			mutate(&changed)
			if _, e := changed.SigningBytes(); e == nil {
				t.Fatal("invalid forward contract accepted")
			}
		})
	}
	for _, operation := range []Operation{OperationDiscover, OperationDescribe} {
		read := f
		read.Operation = operation
		read.Target = nil
		read.ExpectedRevision = ""
		if _, e := read.SigningBytes(); e != nil {
			t.Fatal("bounded read cannot be forwarded", e)
		}
	}
}

func TestForwardFrameLargeBoundedLineageUsesDigestNotHugeSigningField(t *testing.T) {
	f := forwardFixture(t)
	f.ForwardedProvenance.ExtensionChain = nil
	for range 64 {
		f.ForwardedProvenance.Ancestry = append(f.ForwardedProvenance.Ancestry, strings.Repeat("a", 256))
		f.ForwardedProvenance.ExtensionChain = append(f.ForwardedProvenance.ExtensionChain, strings.Repeat("b", 256))
		f.ForwardedProvenance.TriggerLineage = append(f.ForwardedProvenance.TriggerLineage, strings.Repeat("c", 256))
	}
	raw, e := f.SigningBytes()
	if e != nil {
		t.Fatal(e)
	}
	if len(raw) > 4096 {
		t.Fatal("full lineage expanded signing hot path")
	}
}
