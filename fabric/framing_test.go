package fabric

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"math"
	"strings"
	"testing"
)

type testSigningFrame interface{ SigningBytes() ([]byte, error) }

func signingFixtures() []testSigningFrame {
	r, _ := ParseEndpointRef(goldenEndpoint)
	var key [32]byte
	copy(key[:], testBytes(0))
	h := sha256.Sum256([]byte(`{"input":"original"}`))
	return []testSigningFrame{
		GenesisFrame{Namespace: goldenDomain, GenesisPublicKey: key, PayloadDigest: h},
		RegistryFrame{IssuerNamespace: goldenDomain, IssuerKeyRevision: math.MaxUint64, AudienceDomain: goldenDomain, ActionKind: "endpoint.publish", ExactTargetRef: r, NewRevision: "revision-1", Sequence: 1, PayloadDigest: h},
		CallerProofFrame{SourceDomain: goldenDomain, CallerRef: "spiffe://domain/用户", IssuerKeyRevision: 1, AudienceDomain: goldenDomain, Operation: "invoke", OriginalEnvelopeID: "env-1", ReplayID: "replay-1", OriginalEnvelopeDigest: h, Deadline: "2026-10-04T00:00:00.123Z"},
		DispatchAdmissionFrame{SourceDomain: goldenDomain, CallerRef: "spiffe://domain/用户", AudienceDomain: goldenDomain, InvocationID: "inv-1", AttemptID: "offer-1", ReplayID: "replay-1", FinalizedDispatchDigest: h}}
}
func parseTestFrame(i int, b []byte) (testSigningFrame, error) {
	switch i {
	case 0:
		return ParseGenesisFrame(b)
	case 1:
		return ParseRegistryFrame(b)
	case 2:
		return ParseCallerProofFrame(b)
	default:
		return ParseDispatchAdmissionFrame(b)
	}
}
func TestSigningIndependentGoldenAndRoundTrip(t *testing.T) {
	// Python struct.pack('>I')/struct.pack('>Q') independent full-wire SHA256 vectors.
	goldens := []string{"ac63ed2b4562eb02397e1fecf75565aa3a3d0815323f3d2ec37246f0a72f7c37", "1c469546cd00a4af4a06f279d52bc6f674208523c133f20cf4fb4c1b0f2ba40d", "afa96bd29e49483f2e1a01fc3028d2268d31be2ae0362441443d37c377cbe851", "ead03b1bad4c4ad04aca5e7460fa9a4bb088b2b18c64a51be48640c857996dcf"}
	for i, f := range signingFixtures() {
		raw, e := f.SigningBytes()
		if e != nil {
			t.Fatal(e)
		}
		digest := sha256.Sum256(raw)
		if hex.EncodeToString(digest[:]) != goldens[i] {
			t.Fatalf("profile %d golden mismatch", i)
		}
		out, e := parseTestFrame(i, raw)
		if e != nil {
			t.Fatal(e)
		}
		back, e := out.SigningBytes()
		if e != nil || !bytes.Equal(back, raw) {
			t.Fatal("round trip")
		}
		raw[len(raw)-1] ^= 1
		back2, _ := out.SigningBytes()
		if !bytes.Equal(back2, back) {
			t.Fatal("decoder aliases input")
		}
		for j := range 4 {
			if j != i {
				if _, e := parseTestFrame(j, back); e == nil {
					t.Fatal("cross-purpose parsed")
				}
			}
		}
	}
}
func TestCallerProofCannotAuthorizeFinalizedAdmission(t *testing.T) {
	fs := signingFixtures()
	caller := fs[2].(CallerProofFrame)
	admission := fs[3].(DispatchAdmissionFrame)
	original, _ := caller.SigningBytes()
	private := ed25519.NewKeyFromSeed(testBytes(0))
	sig := ed25519.Sign(private, original)
	public := private.Public().(ed25519.PublicKey)
	if !ed25519.Verify(public, original, sig) {
		t.Fatal("original proof failed")
	}
	final, _ := admission.SigningBytes()
	if ed25519.Verify(public, final, sig) {
		t.Fatal("original proof reused for finalized view")
	}
	admission.FinalizedDispatchDigest = sha256.Sum256([]byte("transformed target/input"))
	changed, _ := admission.SigningBytes()
	if bytes.Equal(changed, final) {
		t.Fatal("final digest unbound")
	}
	stillOriginal, _ := caller.SigningBytes()
	if !bytes.Equal(stillOriginal, original) {
		t.Fatal("original mutated")
	}
	for _, change := range []func(*CallerProofFrame){func(f *CallerProofFrame) { f.CallerRef += "x" }, func(f *CallerProofFrame) { f.ReplayID += "x" }, func(f *CallerProofFrame) { f.Operation = "describe" }, func(f *CallerProofFrame) { f.IssuerKeyRevision++ }, func(f *CallerProofFrame) { f.Deadline = "2026-10-04T00:00:01Z" }, func(f *CallerProofFrame) { f.OriginalEnvelopeDigest[0] ^= 1 }, func(f *CallerProofFrame) { d, _ := DomainNamespace(testBytes(1)); f.AudienceDomain = d }} {
		copy := caller
		change(&copy)
		wire, e := copy.SigningBytes()
		if e != nil || ed25519.Verify(public, wire, sig) {
			t.Fatal("signed field not bound")
		}
	}
}
func TestSigningRejectsMalformedLengthsAndTrailing(t *testing.T) {
	for i, f := range signingFixtures() {
		raw, _ := f.SigningBytes()
		for n := 0; n < len(raw); n++ {
			if _, e := parseTestFrame(i, raw[:n]); e == nil {
				t.Fatalf("profile %d truncated at %d", i, n)
			}
		}
		if _, e := parseTestFrame(i, append(bytes.Clone(raw), 0)); e == nil {
			t.Fatal("trailing byte")
		}
		start := bytes.IndexByte(raw, 0) + 1
		bad := bytes.Clone(raw)
		binary.BigEndian.PutUint32(bad[start:start+4], math.MaxUint32)
		if _, e := parseTestFrame(i, bad); e == nil {
			t.Fatal("oversized declared length")
		}
		if _, e := parseTestFrame(i, make([]byte, MaxSigningFrameBytes+1)); e == nil {
			t.Fatal("oversized wire")
		}
	}
}
func TestSigningSemanticBounds(t *testing.T) {
	fs := signingFixtures()
	c := fs[2].(CallerProofFrame)
	for _, deadline := range []string{"2026-10-04T00:00:00+00:00", "2026-10-04T00:00:00.100Z", "2026-10-04", "2026-10-04T00:00:00z"} {
		bad := c
		bad.Deadline = deadline
		if _, e := bad.SigningBytes(); e == nil {
			t.Errorf("deadline %q", deadline)
		}
	}
	for _, caller := range []string{"", string([]byte{255}), strings.Repeat("a", MaxSigningTextBytes+1)} {
		bad := c
		bad.CallerRef = caller
		if _, e := bad.SigningBytes(); e == nil {
			t.Fatal("invalid caller")
		}
	}
	c.CallerRef = strings.Repeat("a", MaxSigningTextBytes)
	c.Deadline = ""
	if _, e := c.SigningBytes(); e != nil {
		t.Fatal("bounded optional fields", e)
	}
	c.IssuerKeyRevision = 0
	if _, e := c.SigningBytes(); e == nil {
		t.Fatal("zero key revision")
	}
	r := fs[1].(RegistryFrame)
	r.Sequence = 0
	if _, e := r.SigningBytes(); e == nil {
		t.Fatal("zero sequence")
	}
	r = fs[1].(RegistryFrame)
	r.ExactTargetRef = EndpointRef{}
	if _, e := r.SigningBytes(); e == nil {
		t.Fatal("zero target")
	}
	g := fs[0].(GenesisFrame)
	g.GenesisPublicKey[0] ^= 1
	if _, e := g.SigningBytes(); e == nil {
		t.Fatal("foreign genesis namespace")
	}
	fields := make([][]byte, 17)
	for i := range fields {
		fields[i] = make([]byte, 4096)
	}
	if _, e := encodeSigningFields(genesisSigningPurpose, fields...); e == nil {
		t.Fatal("total bound")
	}
}
func TestSigningRejectsFieldShape(t *testing.T) {
	profiles := []struct {
		purpose string
		count   int
	}{{genesisSigningPurpose, 3}, {registrySigningPurpose, 10}, {callerSigningPurpose, 9}, {admissionSigningPurpose, 8}}
	for i, p := range profiles {
		raw, _ := signingFixtures()[i].SigningBytes()
		fields, e := decodeSigningFields(raw, p.purpose, p.count)
		if e != nil {
			t.Fatal(e)
		}
		for j := range fields {
			copyFields := append([][]byte(nil), fields...)
			copyFields[j] = nil
			bad, e := encodeSigningFields(p.purpose, copyFields...)
			if e != nil {
				t.Fatal(e)
			}
			optional := i == 1 && j == 5 || i == 2 && j == 8 || i == 3 && j == 7
			if _, e := parseTestFrame(i, bad); (e == nil) != optional {
				t.Fatalf("profile %d field %d optional=%v err=%v", i, j, optional, e)
			}
		}
	}
}
func TestSigningCounterAndDigestLengths(t *testing.T) {
	profiles := []struct {
		purpose           string
		count             int
		counters, digests []int
	}{
		{genesisSigningPurpose, 3, nil, []int{1, 2}},
		{registrySigningPurpose, 10, []int{1, 7}, []int{8, 9}},
		{callerSigningPurpose, 9, []int{2}, []int{7}},
		{admissionSigningPurpose, 8, nil, []int{6}},
	}
	for i, p := range profiles {
		raw, _ := signingFixtures()[i].SigningBytes()
		fields, _ := decodeSigningFields(raw, p.purpose, p.count)
		for _, index := range p.counters {
			for _, n := range []int{7, 9} {
				modified := append([][]byte(nil), fields...)
				modified[index] = make([]byte, n)
				wire, _ := encodeSigningFields(p.purpose, modified...)
				if _, e := parseTestFrame(i, wire); e == nil {
					t.Fatalf("profile %d accepts counter length %d", i, n)
				}
			}
			modified := append([][]byte(nil), fields...)
			modified[index] = make([]byte, 8)
			wire, _ := encodeSigningFields(p.purpose, modified...)
			if _, e := parseTestFrame(i, wire); e == nil {
				t.Fatal("zero counter accepted")
			}
		}
		for _, index := range p.digests {
			for _, n := range []int{31, 33} {
				modified := append([][]byte(nil), fields...)
				modified[index] = make([]byte, n)
				wire, _ := encodeSigningFields(p.purpose, modified...)
				if _, e := parseTestFrame(i, wire); e == nil {
					t.Fatalf("profile %d accepts digest/key length %d", i, n)
				}
			}
		}
	}
}

func FuzzSigningFrames(f *testing.F) {
	for i, x := range signingFixtures() {
		b, _ := x.SigningBytes()
		f.Add(uint8(i), b)
	}
	f.Add(uint8(0), []byte{})
	f.Fuzz(func(t *testing.T, profile uint8, raw []byte) {
		x, e := parseTestFrame(int(profile%4), raw)
		if e != nil {
			return
		}
		back, e := x.SigningBytes()
		if e != nil || !bytes.Equal(back, raw) {
			t.Fatal("noncanonical accepted")
		}
	})
}
