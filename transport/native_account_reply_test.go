package transport

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/e2ee"
)

func accountReplyWireFixture(t *testing.T) (NativeContentReference, NativeContentFragment, NativeObservationPayload) {
	t.Helper()
	_, a, _ := accountContractFixture(t)
	n := a.NativeContent
	envelope, err := e2ee.Encrypt([]byte("private answer"), [32]byte{}, a)
	if err != nil {
		t.Fatal(err)
	}
	r := NativeContentReference{Format: NativeContentFormat, ContentID: n.ContentID, ObservationID: n.ObservationID, OriginID: n.OriginID, InstanceID: n.InstanceID, NativeGeneration: n.NativeGeneration, NativeSessionID: n.NativeSessionID, SubjectType: n.SubjectType, SubjectID: n.SubjectID, Purpose: n.Purpose, FragmentCount: n.FragmentCount, CiphertextBytes: 100, CiphertextDigest: strings.Repeat("a", 64), ManifestEnvelope: envelope, ManifestAAD: a}
	ordinal := 0
	fragmentAAD := a
	binding := *n
	binding.Ordinal = &ordinal
	fragmentAAD.NativeContent = &binding
	fragmentAAD.ObjectType = e2ee.ObjectTypeNativeContentFragment
	fragmentAAD.ObjectID, _ = e2ee.NativeContentFragmentID(r.ContentID, ordinal)
	fragmentEnvelope, err := e2ee.Encrypt([]byte("private answer"), [32]byte{}, fragmentAAD)
	if err != nil {
		t.Fatal(err)
	}
	f := NativeContentFragment{ContentID: r.ContentID, Ordinal: 0, Envelope: fragmentEnvelope, AAD: fragmentAAD}
	payload, err := MarshalNativeJSON(NativeTurnSourcePayload{OutputContent: &r, InstanceID: r.InstanceID, Runtime: "codex", NativeGeneration: r.NativeGeneration, SessionID: r.NativeSessionID, SourceSequence: 1, LogicalTurnID: n.LogicalTurnID, NativeTurnSequence: 7, SourceCommandID: n.SourceCommandID, SourceAdmissionID: n.SourceAdmissionID, InputKind: "account_message"})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	observed, _ := time.Parse(time.RFC3339Nano, a.CreatedAt)
	return r, f, NativeObservationPayload{ObservationID: r.ObservationID, OriginID: r.OriginID, MessageType: MsgRuntimeTurnCompleted, Digest: hex.EncodeToString(digest[:]), ObservedAt: observed, ExpiresAt: observed.Add(time.Hour), Payload: payload}
}
func replyWire(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := MarshalNativeJSON(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestNativeAccountReplyWireRoundTrip(t *testing.T) {
	r, f, o := accountReplyWireFixture(t)
	if _, err := DecodeNativeAccountReplyBegin(replyWire(t, r)); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeNativeAccountReplyFragment(replyWire(t, f), r); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeNativeAccountReplyCommit(replyWire(t, o), r); err != nil {
		t.Fatal(err)
	}
	staged := NativeAccountReplyStagedPayload{ContentID: r.ContentID, CiphertextDigest: r.CiphertextDigest, MissingOrdinals: []int{}}
	if _, err := DecodeNativeAccountReplyStaged(replyWire(t, staged), r); err != nil {
		t.Fatal(err)
	}
	b := r.ManifestAAD.BrowserAccountReply
	receipt := NativeAccountReplyReceiptPayload{OriginID: r.OriginID, ObservationID: r.ObservationID, ObservationDigest: o.Digest, MessageID: b.MessageID, ReplyID: b.ReplyID, ContentID: r.ContentID, CiphertextDigest: r.CiphertextDigest, Disposition: "committed"}
	if _, err := DecodeNativeAccountReplyReceipt(replyWire(t, receipt), r, o.Digest); err != nil {
		t.Fatal(err)
	}
	for _, code := range []string{"invalid_payload", "unauthorized", "conflict", "incomplete", "retry_later", "unavailable"} {
		rejected := NativeAccountReplyRejectedPayload{OriginID: r.OriginID, ObservationID: r.ObservationID, ContentID: r.ContentID, CiphertextDigest: r.CiphertextDigest, ErrorCode: code, Retryable: true}
		if _, err := DecodeNativeAccountReplyRejected(replyWire(t, rejected), r); err != nil {
			t.Fatal(err)
		}
	}
	for _, kind := range []string{MsgAccountReplyBegin, MsgAccountReplyFragment, MsgAccountReplyCommit} {
		var value any = r
		if kind == MsgAccountReplyFragment {
			value = f
		}
		if kind == MsgAccountReplyCommit {
			value = o
		}
		raw, err := marshalNativeEnvelopePayload(kind, json.RawMessage(replyWire(t, value)))
		if err != nil || !bytes.Equal(raw, replyWire(t, value)) {
			t.Fatal("canonical envelope payload", kind, err)
		}
	}
}

func TestNativeAccountReplyStrictWire(t *testing.T) {
	r, _, _ := accountReplyWireFixture(t)
	valid := replyWire(t, NativeAccountReplyRejectedPayload{OriginID: r.OriginID, ObservationID: r.ObservationID, ContentID: r.ContentID, CiphertextDigest: r.CiphertextDigest, ErrorCode: "conflict", Retryable: false})
	malformed := map[string][]byte{
		"duplicate":         bytes.Replace(valid, []byte(`"retryable":false`), []byte(`"retryable":false,"retryable":true`), 1),
		"case alias":        bytes.Replace(valid, []byte(`"retryable"`), []byte(`"Retryable"`), 1),
		"missing retryable": bytes.Replace(valid, []byte(`,"retryable":false`), nil, 1),
		"null":              bytes.Replace(valid, []byte(`"retryable":false`), []byte(`"retryable":null`), 1),
		"unknown":           bytes.Replace(valid, []byte(`"retryable":false`), []byte(`"retryable":false,"publicError":"private answer"`), 1),
		"unknown code":      bytes.Replace(valid, []byte(`"conflict"`), []byte(`"private answer"`), 1),
		"trailing":          append(append([]byte{}, valid...), []byte(` {}`)...),
		"oversize":          append(append([]byte{}, valid...), bytes.Repeat([]byte(" "), NativeAccountReplyMaxWireBytes)...),
		"invalid utf8":      append(append([]byte{}, valid...), 0xff),
		"wrong identity":    bytes.Replace(valid, []byte(r.OriginID), []byte("other"), 1),
	}
	for name, raw := range malformed {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeNativeAccountReplyRejected(raw, r); err == nil {
				t.Fatal("accepted malformed rejection")
			}
		})
	}
	staged := replyWire(t, NativeAccountReplyStagedPayload{ContentID: r.ContentID, CiphertextDigest: r.CiphertextDigest, MissingOrdinals: []int{}})
	for _, raw := range [][]byte{bytes.Replace(staged, []byte(`,"moreMissing":false`), nil, 1), bytes.Replace(staged, []byte(`[]`), []byte(`null`), 1), bytes.Replace(staged, []byte(`false`), []byte(`true`), 1)} {
		if _, err := DecodeNativeAccountReplyStaged(raw, r); err == nil {
			t.Fatal("accepted ambiguous staging completion")
		}
	}
}

func TestNativeAccountReplyBoundsAndCorrelation(t *testing.T) {
	r, f, o := accountReplyWireFixture(t)
	for _, count := range []int{0, e2ee.NativeContentMaxFragments + 1} {
		bad := r
		bad.FragmentCount = count
		if _, err := DecodeNativeAccountReplyBegin(replyWire(t, bad)); err == nil {
			t.Fatal("fragment count accepted", count)
		}
	}
	f.Ordinal = r.FragmentCount
	if _, err := DecodeNativeAccountReplyFragment(replyWire(t, f), r); err == nil {
		t.Fatal("ordinal accepted")
	}
	o.Digest = strings.Repeat("0", 64)
	if _, err := DecodeNativeAccountReplyCommit(replyWire(t, o), r); err == nil {
		t.Fatal("changed digest accepted")
	}
	r.FragmentCount = 32
	r.ManifestAAD.NativeContent.FragmentCount = 32
	for _, ordinals := range [][]int{{-1}, {32}, {1, 1}, {2, 1}, make([]int, 17)} {
		p := NativeAccountReplyStagedPayload{ContentID: r.ContentID, CiphertextDigest: r.CiphertextDigest, MissingOrdinals: ordinals}
		if _, err := DecodeNativeAccountReplyStaged(replyWire(t, p), r); err == nil {
			t.Fatal("invalid missing ordinals accepted", ordinals)
		}
	}
	p := NativeAccountReplyStagedPayload{ContentID: r.ContentID, CiphertextDigest: r.CiphertextDigest, MoreMissing: true, MissingOrdinals: make([]int, 16)}
	for i := range p.MissingOrdinals {
		p.MissingOrdinals[i] = i
	}
	if _, err := DecodeNativeAccountReplyStaged(replyWire(t, p), r); err != nil {
		t.Fatal(err)
	}
}

func TestNativeAccountReplyStagingIsNeverReceipt(t *testing.T) {
	r, _, o := accountReplyWireFixture(t)
	staged := replyWire(t, NativeAccountReplyStagedPayload{ContentID: r.ContentID, CiphertextDigest: r.CiphertextDigest, MissingOrdinals: []int{}})
	generic := replyWire(t, NativeObservationReceiptPayload{OriginID: r.OriginID, ObservationID: r.ObservationID, Digest: o.Digest, Disposition: "accepted"})
	for _, raw := range [][]byte{staged, generic} {
		if _, err := DecodeNativeAccountReplyReceipt(raw, r, o.Digest); err == nil {
			t.Fatal("non-delivery response accepted as committed receipt")
		}
	}
	// Structural admission does not authenticate an encrypted reference.
	r.ManifestEnvelope.Ciphertext = "not authenticated"
	if _, err := DecodeNativeAccountReplyBegin(replyWire(t, r)); err != nil {
		t.Fatal("wire parser unexpectedly claims ciphertext validation", err)
	}
}

func TestNativeAccountReplyReceiptCorrelation(t *testing.T) {
	r, _, o := accountReplyWireFixture(t)
	b := r.ManifestAAD.BrowserAccountReply
	receipt := NativeAccountReplyReceiptPayload{OriginID: r.OriginID, ObservationID: r.ObservationID, ObservationDigest: o.Digest, MessageID: b.MessageID, ReplyID: b.ReplyID, ContentID: r.ContentID, CiphertextDigest: r.CiphertextDigest, Disposition: "committed"}
	for _, mutate := range []func(*NativeAccountReplyReceiptPayload){
		func(p *NativeAccountReplyReceiptPayload) { p.OriginID = "other" }, func(p *NativeAccountReplyReceiptPayload) { p.ObservationID = "other" }, func(p *NativeAccountReplyReceiptPayload) { p.ObservationDigest = strings.Repeat("b", 64) }, func(p *NativeAccountReplyReceiptPayload) { p.MessageID = "other" }, func(p *NativeAccountReplyReceiptPayload) { p.ReplyID = "other" }, func(p *NativeAccountReplyReceiptPayload) { p.ContentID = "other" }, func(p *NativeAccountReplyReceiptPayload) { p.CiphertextDigest = strings.Repeat("b", 64) }, func(p *NativeAccountReplyReceiptPayload) { p.Disposition = "staged" },
	} {
		changed := receipt
		mutate(&changed)
		if _, err := DecodeNativeAccountReplyReceipt(replyWire(t, changed), r, o.Digest); err == nil {
			t.Fatal("receipt identity change accepted")
		}
	}
	raw := replyWire(t, o)
	if _, err := DecodeNativeAccountReplyCommit(append([]byte(" "), raw...), r); err == nil {
		t.Fatal("noncanonical observation accepted")
	}
	o.Payload = bytes.Replace(o.Payload, []byte(`"inputKind":"account_message"`), []byte(`"inputKind":"account_message","plaintext":"private answer"`), 1)
	sum := sha256.Sum256(o.Payload)
	o.Digest = hex.EncodeToString(sum[:])
	if _, err := DecodeNativeAccountReplyCommit(replyWire(t, o), r); err == nil {
		t.Fatal("plaintext extension accepted")
	}
}
