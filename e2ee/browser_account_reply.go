package e2ee

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"strconv"
	"strings"
	"time"
)

const BrowserAccountReplyBindingFormat = "pagnet.browser-account-reply-aad.v1"
const ObjectTypeBrowserAccountReply = "browser_account_reply"

// BrowserAccountDelegate identifies a logical browser delegate, never a principal.
type BrowserAccountDelegate struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

// BrowserAccountReplyBinding authenticates the original input and dispatch.
// Declaration order is the v1 cross-language canonical contract.
type BrowserAccountReplyBinding struct {
	Format              string                 `json:"format"`
	ReplyID             string                 `json:"reply_id"`
	MessageID           string                 `json:"message_id"`
	BindingDigest       string                 `json:"binding_digest"`
	SealedDigest        string                 `json:"sealed_digest"`
	OwnerUserID         string                 `json:"owner_user_id"`
	ConnectionID        string                 `json:"connection_id"`
	Delegate            BrowserAccountDelegate `json:"delegate"`
	SourceCommandID     string                 `json:"source_command_id"`
	SourceAdmissionID   string                 `json:"source_admission_id"`
	OwnershipID         string                 `json:"ownership_id"`
	OwnershipGeneration string                 `json:"ownership_generation"`
	DispatchSequence    int64                  `json:"dispatch_sequence"`
	LogicalTurnID       string                 `json:"logical_turn_id"`
	OriginalEpochID     string                 `json:"original_epoch_id"`
}

// Authenticated wire v1 requires canonical nested bytes, including field order.
// Reject aliases, duplicate keys and alternative encodings before authentication.
func (b *BrowserAccountReplyBinding) UnmarshalJSON(raw []byte) error {
	type binding BrowserAccountReplyBinding
	var parsed binding
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&parsed); err != nil {
		return err
	}
	canonical, err := canonicalJSON(parsed)
	if err != nil || !bytes.Equal(raw, canonical) {
		return errors.New("noncanonical account reply binding")
	}
	*b = BrowserAccountReplyBinding(parsed)
	return nil
}

func (a AAD) validateBrowserAccountReplyBinding() error {
	b := a.BrowserAccountReply
	if b == nil {
		if a.ObjectType == ObjectTypeBrowserAccountReply {
			return errors.New("missing account reply binding")
		}
		return nil
	}
	invalid := errors.New("invalid account reply AAD")
	for _, s := range []string{b.ReplyID, b.MessageID, b.OwnerUserID, b.ConnectionID, b.Delegate.ID, b.SourceCommandID, b.SourceAdmissionID, b.OwnershipID, b.OwnershipGeneration, b.OriginalEpochID} {
		if s == "" || len(s) > 256 {
			return invalid
		}
	}
	for _, s := range []string{b.BindingDigest, b.SealedDigest} {
		raw, e := hex.DecodeString(s)
		if e != nil || len(raw) != 32 || hex.EncodeToString(raw) != s {
			return invalid
		}
	}
	created, createdErr := time.Parse(time.RFC3339Nano, a.CreatedAt)
	if createdErr != nil || created.UTC().Format(time.RFC3339Nano) != a.CreatedAt {
		return invalid
	}
	for _, id := range []string{b.SourceCommandID, b.SourceAdmissionID} {
		parsed, err := uuid.Parse(id)
		if err != nil || parsed.String() != id {
			return invalid
		}
	}
	turn, turnErr := strconv.ParseInt(strings.TrimPrefix(b.LogicalTurnID, "pagnet-worker-turn-"), 10, 64)
	if b.Format != BrowserAccountReplyBindingFormat || b.Delegate.Kind != BrowserAccountDelegateSenderKind || b.DispatchSequence <= 0 || turnErr != nil || turn <= 0 || b.LogicalTurnID != fmt.Sprintf("pagnet-worker-turn-%d", turn) || a.ProtocolVersion != 2 || a.TenantID == "" || a.NetworkID == "" || a.Sender == "" || a.CreatedAt == "" || a.Recipient != b.Delegate.ID || a.KeyEpochID != b.OriginalEpochID || a.ProtectedContext != nil || a.BrowserAccountMessage != nil || a.NativeContent == nil {
		return invalid
	}
	n := a.NativeContent
	if n.Purpose != ObjectTypeBrowserAccountReply || n.SubjectType != ObjectTypeBrowserAccountReply || n.SubjectID != b.MessageID || n.SourceCommandID != b.SourceCommandID || n.SourceAdmissionID != b.SourceAdmissionID || n.LogicalTurnID != b.LogicalTurnID {
		return invalid
	}
	if n.Ordinal == nil && (a.ObjectType != ObjectTypeBrowserAccountReply || a.ObjectID != b.ReplyID) {
		return invalid
	}
	return nil
}
