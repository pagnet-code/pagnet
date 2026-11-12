package transport

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"unicode/utf8"

	"github.com/pagnet-code/pagnet/e2ee"
)

const NativeAccountReplyProtocol = "native-account-reply-v1"
const NativeAccountReplyMaxWireBytes = 128 << 10
const (
	MsgAccountReplyBegin    = "host.account_reply_begin"
	MsgAccountReplyFragment = "host.account_reply_fragment"
	MsgAccountReplyCommit   = "host.account_reply_commit"
	MsgAccountReplyStaged   = "account_reply_staged"
	MsgAccountReplyReceipt  = "account_reply_receipt"
	MsgAccountReplyRejected = "account_reply_rejected"
)

// Begin, fragment and commit carry the existing canonical encrypted content and
// observation records directly. Retries preserve their original bytes and IDs.
type NativeAccountReplyBeginPayload = NativeContentReference
type NativeAccountReplyFragmentPayload = NativeContentFragment
type NativeAccountReplyCommitPayload = NativeObservationPayload

// Staging proves storage progress only, never durable reply delivery.
type NativeAccountReplyStagedPayload struct {
	ContentID        string `json:"contentId"`
	CiphertextDigest string `json:"ciphertextDigest"`
	MissingOrdinals  []int  `json:"missingOrdinals"`
	MoreMissing      bool   `json:"moreMissing"`
}

// Only this dedicated committed receipt acknowledges durable account delivery.
// Generic observation receipts and staging responses cannot replace it.
type NativeAccountReplyReceiptPayload struct {
	OriginID          string `json:"originId"`
	ObservationID     string `json:"observationId"`
	ObservationDigest string `json:"observationDigest"`
	MessageID         string `json:"messageId"`
	ReplyID           string `json:"replyId"`
	ContentID         string `json:"contentId"`
	CiphertextDigest  string `json:"ciphertextDigest"`
	Disposition       string `json:"disposition"`
}

// ErrorCode is an enumerated public code, never native or plaintext error text.
type NativeAccountReplyRejectedPayload struct {
	OriginID         string `json:"originId"`
	ObservationID    string `json:"observationId"`
	ContentID        string `json:"contentId"`
	CiphertextDigest string `json:"ciphertextDigest"`
	ErrorCode        string `json:"errorCode"`
	Retryable        bool   `json:"retryable"`
}

var errNativeAccountReply = errors.New("transport: invalid native account reply payload")

func decodeNativeAccountReply(raw []byte, target any) error {
	if len(raw) == 0 || len(raw) > NativeAccountReplyMaxWireBytes || !utf8.Valid(raw) || DecodeOwnerTextConsolePayload(raw, target) != nil {
		return errNativeAccountReply
	}
	return nil
}

func accountReplyDigest(value string) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == 32 && hex.EncodeToString(raw) == value
}

// ValidateNativeAccountReplyReference checks bounded wire metadata only. It
// grants no authority: receivers must additionally run nativecontent's reference
// and fragment validators and verify the independently retained original source.
func ValidateNativeAccountReplyReference(r NativeContentReference) error {
	if r.Format != NativeContentFormat || r.Purpose != e2ee.ObjectTypeBrowserAccountReply || !accountReplyDigest(r.CiphertextDigest) || r.FragmentCount < 1 || r.FragmentCount > e2ee.NativeContentMaxFragments || r.CiphertextBytes < 16 || r.CiphertextBytes > NativeContentMaxCiphertextBytes {
		return errNativeAccountReply
	}
	for _, id := range []string{r.ContentID, r.ObservationID, r.OriginID, r.InstanceID, r.SubjectID} {
		if id == "" || len(id) > 256 {
			return errNativeAccountReply
		}
	}
	if r.NativeGeneration == "" || len(r.NativeGeneration) > 256 || r.NativeSessionID == "" || len(r.NativeSessionID) > 512 || r.SubjectType != e2ee.ObjectTypeBrowserAccountReply {
		return errNativeAccountReply
	}
	n := r.ManifestAAD.NativeContent
	reply := r.ManifestAAD.BrowserAccountReply
	if n == nil || reply == nil || n.Ordinal != nil || n.ContentID != r.ContentID || n.ObservationID != r.ObservationID || n.OriginID != r.OriginID || n.InstanceID != r.InstanceID || n.NativeGeneration != r.NativeGeneration || n.NativeSessionID != r.NativeSessionID || n.SubjectType != r.SubjectType || n.SubjectID != r.SubjectID || n.Purpose != r.Purpose || n.FragmentCount != r.FragmentCount {
		return errNativeAccountReply
	}
	return nil
}
func DecodeNativeAccountReplyBegin(raw []byte) (NativeContentReference, error) {
	var r NativeContentReference
	if decodeNativeAccountReply(raw, &r) != nil || ValidateNativeAccountReplyReference(r) != nil {
		return NativeContentReference{}, errNativeAccountReply
	}
	return r, nil
}

// DecodeNativeAccountReplyFragment checks wire shape and retained upload identity;
// it does not authenticate ciphertext or its AAD.
func DecodeNativeAccountReplyFragment(raw []byte, r NativeContentReference) (NativeContentFragment, error) {
	var f NativeContentFragment
	if decodeNativeAccountReply(raw, &f) != nil || ValidateNativeAccountReplyReference(r) != nil || f.ContentID != r.ContentID || f.Ordinal < 0 || f.Ordinal >= r.FragmentCount {
		return NativeContentFragment{}, errNativeAccountReply
	}
	return f, nil
}

// DecodeNativeAccountReplyCommit preserves the canonical observation and binds
// its attachment to the retained begin. This is not an authorization or receipt.
func DecodeNativeAccountReplyCommit(raw []byte, r NativeContentReference) (NativeObservationPayload, error) {
	var o NativeObservationPayload
	if decodeNativeAccountReply(raw, &o) != nil || ValidateNativeAccountReplyReference(r) != nil || o.OriginID != r.OriginID || o.ObservationID != r.ObservationID || o.MessageType != MsgRuntimeTurnCompleted || o.DeleteRequestID != "" || o.ObservedAt.IsZero() || !o.ExpiresAt.After(o.ObservedAt) {
		return NativeObservationPayload{}, errNativeAccountReply
	}
	observationJSON, err := MarshalNativeJSON(o)
	if err != nil || !bytes.Equal(raw, observationJSON) {
		return NativeObservationPayload{}, errNativeAccountReply
	}
	sum := sha256.Sum256(o.Payload)
	if o.Digest != hex.EncodeToString(sum[:]) {
		return NativeObservationPayload{}, errNativeAccountReply
	}
	var p NativeTurnSourcePayload
	if decodeNativeAccountReply(o.Payload, &p) != nil {
		return NativeObservationPayload{}, errNativeAccountReply
	}
	canonical, err := MarshalNativeJSON(p)
	ref, errRef := MarshalNativeJSON(r)
	attached, errAttached := MarshalNativeJSON(p.OutputContent)
	n := r.ManifestAAD.NativeContent
	if err != nil || errRef != nil || errAttached != nil || !bytes.Equal(canonical, o.Payload) || !bytes.Equal(ref, attached) || p.PlanContent != nil || p.InstanceID != r.InstanceID || p.NativeGeneration != r.NativeGeneration || p.SessionID != r.NativeSessionID || p.LogicalTurnID != n.LogicalTurnID || p.SourceCommandID != n.SourceCommandID || p.SourceAdmissionID != n.SourceAdmissionID || p.InputKind != "account_message" || p.Runtime == "" || len(p.Runtime) > 128 || p.Kind != "" || p.RetryAt != "" || p.Model != "" {
		return NativeObservationPayload{}, errNativeAccountReply
	}
	return o, nil
}
func DecodeNativeAccountReplyStaged(raw []byte, r NativeContentReference) (NativeAccountReplyStagedPayload, error) {
	var p NativeAccountReplyStagedPayload
	if decodeNativeAccountReply(raw, &p) != nil || ValidateNativeAccountReplyReference(r) != nil || p.ContentID != r.ContentID || p.CiphertextDigest != r.CiphertextDigest || p.MissingOrdinals == nil || len(p.MissingOrdinals) > NativeContentMaxFragmentPage || p.MoreMissing && len(p.MissingOrdinals) != NativeContentMaxFragmentPage {
		return NativeAccountReplyStagedPayload{}, errNativeAccountReply
	}
	previous := -1
	for _, ordinal := range p.MissingOrdinals {
		if ordinal <= previous || ordinal >= r.FragmentCount {
			return NativeAccountReplyStagedPayload{}, errNativeAccountReply
		}
		previous = ordinal
	}
	if p.MoreMissing && previous >= r.FragmentCount-1 {
		return NativeAccountReplyStagedPayload{}, errNativeAccountReply
	}
	return p, nil
}
func DecodeNativeAccountReplyReceipt(raw []byte, r NativeContentReference, observationDigest string) (NativeAccountReplyReceiptPayload, error) {
	var p NativeAccountReplyReceiptPayload
	if decodeNativeAccountReply(raw, &p) != nil || ValidateNativeAccountReplyReference(r) != nil || r.ManifestAAD.BrowserAccountReply == nil || !accountReplyDigest(observationDigest) || p.OriginID != r.OriginID || p.ObservationID != r.ObservationID || p.ObservationDigest != observationDigest || p.ContentID != r.ContentID || p.CiphertextDigest != r.CiphertextDigest || p.MessageID != r.ManifestAAD.BrowserAccountReply.MessageID || p.ReplyID != r.ManifestAAD.BrowserAccountReply.ReplyID || p.Disposition != "committed" {
		return NativeAccountReplyReceiptPayload{}, errNativeAccountReply
	}
	return p, nil
}
func DecodeNativeAccountReplyRejected(raw []byte, r NativeContentReference) (NativeAccountReplyRejectedPayload, error) {
	var p NativeAccountReplyRejectedPayload
	if decodeNativeAccountReply(raw, &p) != nil || ValidateNativeAccountReplyReference(r) != nil || p.OriginID != r.OriginID || p.ObservationID != r.ObservationID || p.ContentID != r.ContentID || p.CiphertextDigest != r.CiphertextDigest {
		return NativeAccountReplyRejectedPayload{}, errNativeAccountReply
	}
	switch p.ErrorCode {
	case "invalid_payload", "unauthorized", "conflict", "incomplete", "retry_later", "unavailable":
		return p, nil
	}
	return NativeAccountReplyRejectedPayload{}, errNativeAccountReply
}
