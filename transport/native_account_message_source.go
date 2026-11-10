package transport

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/pagnet-code/pagnet/accountmessage"
	"github.com/pagnet-code/pagnet/e2ee"
)

// NativeAccountMessageSource preserves original account authority without
// representing the browser delegate as a principal or task.
type NativeAccountMessageSource struct {
	V             int                       `json:"v"`
	MessageID     string                    `json:"messageId"`
	BindingDigest string                    `json:"bindingDigest"`
	SealedDigest  string                    `json:"sealedDigest"`
	Descriptor    accountmessage.Descriptor `json:"descriptor"`
	InputAAD      e2ee.AAD                  `json:"inputAAD"`
}

func (s *NativeAccountMessageSource) UnmarshalJSON(raw []byte) error {
	type source NativeAccountMessageSource
	var parsed source
	if err := DecodeOwnerTextConsolePayload(raw, &parsed); err != nil {
		return err
	}
	*s = NativeAccountMessageSource(parsed)
	return s.Validate()
}

func (s NativeAccountMessageSource) Validate() error {
	d := s.Descriptor
	sealed, err := hex.DecodeString(s.SealedDigest)
	expected := e2ee.AAD{ProtocolVersion: 2, TenantID: d.TenantID, NetworkID: d.NetworkID, ObjectType: e2ee.ObjectTypeMessage, ObjectID: d.MessageID, Sender: d.Sender.ID, Recipient: d.TargetPrincipalID, CreatedAt: d.CreatedAt, KeyEpochID: d.EpochID, BrowserAccountMessage: &e2ee.BrowserAccountMessageBinding{BindingDigest: s.BindingDigest, SenderKind: d.Sender.Kind}}
	if s.V != 1 || d.Validate() != nil || s.MessageID != d.MessageID || s.BindingDigest != d.BindingDigest() || err != nil || len(sealed) != 32 || hex.EncodeToString(sealed) != s.SealedDigest || s.InputAAD.ValidateScope() != nil || !bytes.Equal(s.InputAAD.CanonicalBytes(), expected.CanonicalBytes()) {
		return errors.New("invalid original account message source descriptor")
	}
	return nil
}

// ValidNativeSourceUnion preserves sourceless control commands while rejecting
// mixed original authorities. Legacy task inputs can remain sourceless;
// invocation and account classifications require their own original source.
func ValidNativeSourceUnion(task *NativeTaskSource, invocation *NativeInvocationSource, account *NativeAccountMessageSource) bool {
	n := 0
	if task != nil {
		n++
	}
	if invocation != nil {
		n++
		if invocation.Validate() != nil {
			return false
		}
	}
	if account != nil {
		n++
		if account.Validate() != nil {
			return false
		}
	}
	return n <= 1
}

// ValidateReplyAAD ties a reply to this frozen input and its original dispatch.
func (s NativeAccountMessageSource) ValidateReplyAAD(a e2ee.AAD, p NativeDispatchProof) error {
	b := a.BrowserAccountReply
	if s.Validate() != nil || a.ValidateScope() != nil || b == nil || p.AccountMessageSource == nil || !ValidNativeSourceUnion(p.TaskSource, p.InvocationSource, p.AccountMessageSource) || !bytes.Equal(mustAccountSourceJSON(s), mustAccountSourceJSON(*p.AccountMessageSource)) {
		return errors.New("invalid account reply source")
	}
	d := s.Descriptor
	if a.TenantID != d.TenantID || a.NetworkID != d.NetworkID || a.Sender != d.TargetInstanceID || b.MessageID != s.MessageID || b.BindingDigest != s.BindingDigest || b.SealedDigest != s.SealedDigest || b.OwnerUserID != d.OwnerUserID || b.ConnectionID != d.ConnectionID || b.Delegate.Kind != d.Sender.Kind || b.Delegate.ID != d.Sender.ID || b.OriginalEpochID != d.EpochID || b.SourceCommandID != p.SourceCommandID || b.SourceAdmissionID != p.SourceAdmissionID || b.OwnershipID != p.OwnershipID || b.OwnershipGeneration != p.OwnershipGeneration || b.DispatchSequence != p.DispatchSequence {
		return errors.New("account reply source mismatch")
	}
	return nil
}
func mustAccountSourceJSON(s NativeAccountMessageSource) []byte { b, _ := json.Marshal(s); return b }
