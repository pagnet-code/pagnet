package nativecontent

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/transport"
)

func contentFixture(t *testing.T, plain []byte) Transfer {
	t.Helper()
	a := e2ee.AAD{ProtocolVersion: transport.ProtocolVersion, TenantID: "00000000-0000-0000-0000-000000000001", NetworkID: "00000000-0000-0000-0000-000000000002", ObjectType: e2ee.ObjectTypeRuntimeInteraction, ObjectID: "00000000-0000-0000-0000-000000000003", Sender: "00000000-0000-0000-0000-000000000004", CreatedAt: "2026-10-02T01:00:00Z", KeyEpochID: "test-epoch"}
	binding := e2ee.NativeContentBinding{ContentID: "00000000-0000-0000-0000-000000000005", ObservationID: "00000000-0000-0000-0000-000000000006", OriginID: "00000000-0000-0000-0000-000000000007", InstanceID: a.Sender, NativeGeneration: "actual-native-generation", NativeSessionID: "actual-native-session", SubjectType: a.ObjectType, SubjectID: a.ObjectID, Purpose: "interaction_answer"}
	result, err := Build(plain, [32]byte{1}, a, binding, "text/plain; charset=utf-8")
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestNativeContentExactAssemblyAcrossUTF8FragmentBoundary(t *testing.T) {
	plain := []byte(strings.Repeat("a", transport.NativeContentFragmentPlaintextBytes-1) + "€" + strings.Repeat("b", 100))
	transfer := contentFixture(t, plain)
	if len(transfer.Fragments) != 2 {
		t.Fatal("expected multi-fragment source")
	}
	opened, mime, err := Open(transfer.Reference, transfer.Fragments, [32]byte{1})
	if err != nil || !bytes.Equal(opened, plain) || mime != "text/plain; charset=utf-8" {
		t.Fatal("exact original source lost", err)
	}
	// Public commitment contains only ciphertext; private source hashes live
	// exclusively inside the encrypted manifest.
	raw, _ := json.Marshal(transfer.Reference)
	if bytes.Contains(raw, []byte(digest(plain))) || bytes.Contains(raw, []byte(digest(plain[:transport.NativeContentFragmentPlaintextBytes]))) {
		t.Fatal("private plaintext commitment exposed")
	}
}

func TestNativeContentRejectsPartialMixedScopeAndReorderedSource(t *testing.T) {
	plain := []byte(strings.Repeat("abc", 30000))
	for _, scenario := range []string{"missing", "duplicate", "reordered", "wrong_origin", "wrong_epoch", "wrong_ordinal", "ciphertext", "wrong_total", "wrong_digest", "wrong_purpose"} {
		t.Run(scenario, func(t *testing.T) {
			transfer := contentFixture(t, plain)
			switch scenario {
			case "missing":
				transfer.Fragments = transfer.Fragments[:1]
			case "duplicate":
				transfer.Fragments[1] = transfer.Fragments[0]
			case "reordered":
				transfer.Fragments[0], transfer.Fragments[1] = transfer.Fragments[1], transfer.Fragments[0]
			case "wrong_origin":
				copy := *transfer.Fragments[0].AAD.NativeContent
				copy.OriginID = "00000000-0000-0000-0000-000000000008"
				transfer.Fragments[0].AAD.NativeContent = &copy
			case "wrong_epoch":
				transfer.Fragments[0].Envelope.KeyEpochID = "other-epoch"
			case "wrong_ordinal":
				copy := *transfer.Fragments[0].AAD.NativeContent
				index := 1
				copy.Ordinal = &index
				transfer.Fragments[0].AAD.NativeContent = &copy
			case "ciphertext":
				transfer.Fragments[0].Envelope.Ciphertext = strings.Repeat("A", len(transfer.Fragments[0].Envelope.Ciphertext))
			case "wrong_total":
				transfer.Reference.CiphertextBytes++
			case "wrong_digest":
				transfer.Reference.CiphertextDigest = strings.Repeat("0", 64)
			case "wrong_purpose":
				transfer.Reference.Purpose = "interaction_detail"
			}
			opened, _, err := Open(transfer.Reference, transfer.Fragments, [32]byte{1})
			if err == nil || opened != nil {
				t.Fatal("incomplete or mixed content accepted")
			}
		})
	}
}

func TestNativeContentEnforcesRecordBoundsAndCompleteUTF8(t *testing.T) {
	good := contentFixture(t, []byte("complete answer"))
	if _, err := Build(make([]byte, transport.NativeContentMaxPlaintextBytes+1), [32]byte{1}, good.Reference.ManifestAAD, *good.Reference.ManifestAAD.NativeContent, "application/octet-stream"); err == nil {
		t.Fatal("oversize source admitted")
	}
	invalidBytes := []byte{0xff, 0xfe}
	for _, mime := range []string{"text/plain", "text/plain; charset=utf-8", "application/json"} {
		if _, err := Build(invalidBytes, [32]byte{1}, good.Reference.ManifestAAD, *good.Reference.ManifestAAD.NativeContent, mime); err == nil {
			t.Fatal("invalid UTF8 producer admitted", mime)
		}
	}
	binary, err := Build(invalidBytes, [32]byte{1}, good.Reference.ManifestAAD, *good.Reference.ManifestAAD.NativeContent, "application/octet-stream")
	if err != nil {
		t.Fatal("binary producer rejected", err)
	}
	opened, _, err := Open(binary.Reference, binary.Fragments, [32]byte{1})
	if err != nil || !bytes.Equal(opened, invalidBytes) {
		t.Fatal("binary content did not round-trip", err)
	}
	// Construct a cryptographically coherent malicious text declaration. The
	// consumer still rejects complete invalid UTF8 even if a producer bypassed Build.
	manifestRaw, err := e2ee.Decrypt(binary.Reference.ManifestEnvelope, [32]byte{1}, binary.Reference.ManifestAAD)
	if err != nil {
		t.Fatal(err)
	}
	var manifest transport.NativeContentManifest
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.MimeType = "text/plain"
	replacementRaw, _ := json.Marshal(manifest)
	before, _ := ciphertextLength(binary.Reference.ManifestEnvelope, transport.NativeContentMaxManifestPlaintextBytes+16)
	binary.Reference.ManifestEnvelope, err = e2ee.Encrypt(replacementRaw, [32]byte{1}, binary.Reference.ManifestAAD)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := ciphertextLength(binary.Reference.ManifestEnvelope, transport.NativeContentMaxManifestPlaintextBytes+16)
	binary.Reference.CiphertextBytes += after - before
	binary.Reference.CiphertextDigest, err = CiphertextCommitment(binary.Reference, binary.Fragments)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Open(binary.Reference, binary.Fragments, [32]byte{1}); err == nil {
		t.Fatal("invalid complete UTF8 consumer accepted")
	}
	clear(manifestRaw)
	clear(replacementRaw)
	good.Fragments[0].Envelope.Ciphertext = strings.Repeat("A", (transport.NativeContentFragmentPlaintextBytes+100)*2)
	if err := ValidateFragment(good.Reference, good.Fragments[0]); err == nil {
		t.Fatal("oversize fragment admitted")
	}
}

func TestNativeContentMaximumSourceFitsEveryEncodedFrame(t *testing.T) {
	// Valid worst-case text stays exact. The JSON/base64/AAD wrapper is charged,
	// not just plaintext; each transfer frame fits the128KiB native frame budget.
	plain := bytes.Repeat([]byte("<"), transport.NativeContentMaxPlaintextBytes)
	initial := contentFixture(t, []byte("seed"))
	aad := initial.Reference.ManifestAAD
	binding := *aad.NativeContent
	binding.NativeGeneration = strings.Repeat("<", 256)
	binding.NativeSessionID = strings.Repeat("<", 512)
	transfer, err := Build(plain, [32]byte{1}, aad, binding, strings.Repeat("<", 128))
	if err != nil {
		t.Fatal(err)
	}
	if len(transfer.Fragments) != e2ee.NativeContentMaxFragments {
		t.Fatal("maximum source fragment count incorrect")
	}
	interaction := transport.InteractionEventPayload{InteractionID: binding.SubjectID, InstanceID: binding.InstanceID, SessionID: binding.NativeSessionID, NativeGeneration: binding.NativeGeneration, Runtime: "codex", Kind: "permission", Resolved: true, Decision: "resolved", DetailContent: &transfer.Reference}
	interactionRaw, err := json.Marshal(interaction)
	if err != nil {
		t.Fatal(err)
	}
	observation := transport.NativeObservationPayload{ObservationID: binding.ObservationID, OriginID: binding.OriginID, MessageType: transport.MsgInteractionResolved, Digest: strings.Repeat("0", 64), ObservedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Hour), Payload: interactionRaw}
	frames := []any{transfer.Reference, observation}
	for _, fragment := range transfer.Fragments {
		frames = append(frames, fragment)
	}
	for _, payload := range frames {
		envelope, err := transport.NewEnvelope(transport.MsgNativeContentFragment, payload)
		if err != nil {
			t.Fatal(err)
		}
		correlation := "00000000-0000-0000-0000-000000000008"
		envelope.CorrelationID = &correlation
		envelope.CausationID = &correlation
		encoded, err := json.Marshal(envelope)
		if err != nil {
			t.Fatal(err)
		}
		if len(encoded) > 128<<10 {
			t.Fatal("encoded native content frame exceeds budget", len(encoded))
		}
	}
	opened, _, err := Open(transfer.Reference, transfer.Fragments, [32]byte{1})
	if err != nil || !bytes.Equal(opened, plain) {
		t.Fatal("maximum accepted original source lost", err)
	}
}

func TestNativeContentCommittedCrossLanguageVectors(t *testing.T) {
	type vector struct {
		Name                  string
		ApprovalProof         string `json:"approvalProof"`
		ApprovalProofOptionID string `json:"approvalProofOptionId"`
		EpochKeyHex           string
		Plaintext             string
		PlaintextDigest       string
		Reference             transport.NativeContentReference
		Fragments             []transport.NativeContentFragment
		ManifestAADCanonical  string
		FragmentAADCanonical  []string
		FragmentIDs           []string
	}
	raw, err := os.ReadFile("testdata/native_content_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []vector
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			bytesKey, err := hex.DecodeString(v.EpochKeyHex)
			if err != nil || len(bytesKey) != 32 {
				t.Fatal("invalid vector key")
			}
			var key [32]byte
			copy(key[:], bytesKey)
			if string(v.Reference.ManifestAAD.CanonicalBytes()) != v.ManifestAADCanonical {
				t.Fatal("manifest canonical AAD changed")
			}
			for index, fragment := range v.Fragments {
				if string(fragment.AAD.CanonicalBytes()) != v.FragmentAADCanonical[index] || fragment.AAD.ObjectID != v.FragmentIDs[index] {
					t.Fatal("fragment canonical AAD or ID changed")
				}
				expected, err := e2ee.NativeContentFragmentID(v.Reference.ContentID, index)
				if err != nil || expected != v.FragmentIDs[index] {
					t.Fatal("fragment ID derivation changed")
				}
			}
			opened, _, err := Open(v.Reference, v.Fragments, key)
			if err != nil || string(opened) != v.Plaintext || digest(opened) != v.PlaintextDigest {
				t.Fatal("committed vector cannot authenticate whole original content", err)
			}
			if v.ApprovalProof != "" {
				var detail transport.OwnerInteractionDetail
				if err := json.Unmarshal(opened, &detail); err != nil {
					t.Fatal(err)
				}
				secret, err := base64.StdEncoding.DecodeString(detail.Inspection.Secret)
				if err != nil {
					t.Fatal(err)
				}
				proof, err := e2ee.ApprovalProof(secret, v.Reference.ManifestAAD, detail.Inspection.InstanceID, detail.Inspection.SessionID, detail.Inspection.NativeInteractionID, v.ApprovalProofOptionID)
				if err != nil || base64.StdEncoding.EncodeToString(proof) != v.ApprovalProof {
					t.Fatal("committed whole-manifest inspection proof changed", err)
				}
			}
		})
	}
}

func TestNativeContentStreamingCommitmentRequiresExactEndAndPropagatesStorageError(t *testing.T) {
	transfer := contentFixture(t, bytes.Repeat([]byte("x"), transport.NativeContentFragmentPlaintextBytes+1))
	next := func(fragments []transport.NativeContentFragment, failure error) func() (transport.NativeContentFragment, bool, error) {
		index := 0
		return func() (transport.NativeContentFragment, bool, error) {
			if index >= len(fragments) {
				return transport.NativeContentFragment{}, false, failure
			}
			fragment := fragments[index]
			index++
			return fragment, true, nil
		}
	}
	commitment, err := CiphertextCommitmentStream(transfer.Reference, next(transfer.Fragments, nil))
	if err != nil || commitment != transfer.Reference.CiphertextDigest {
		t.Fatal("stream commitment differs", err)
	}
	if _, err := CiphertextCommitmentStream(transfer.Reference, next(transfer.Fragments[:1], nil)); err == nil {
		t.Fatal("missing stream fragment accepted")
	}
	extra := append(append([]transport.NativeContentFragment(nil), transfer.Fragments...), transfer.Fragments[0])
	if _, err := CiphertextCommitmentStream(transfer.Reference, next(extra, nil)); err == nil {
		t.Fatal("extra stream fragment accepted")
	}
	failure := errors.New("stored fragment cursor failed")
	if _, err := CiphertextCommitmentStream(transfer.Reference, next(transfer.Fragments, failure)); !errors.Is(err, failure) {
		t.Fatal("storage error hidden", err)
	}
}
