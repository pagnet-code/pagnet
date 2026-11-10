package e2ee

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
)

const BrowserAccountDelegateSenderKind = "browser_account_delegate"

// BrowserAccountMessageBinding commits to the complete canonical preparation
// descriptor. Sender is the account delegate's logical ID, never a principal.
type BrowserAccountMessageBinding struct {
	BindingDigest string `json:"binding_digest"`
	SenderKind    string `json:"sender_kind"`
}

func (b *BrowserAccountMessageBinding) UnmarshalJSON(raw []byte) error {
	type binding BrowserAccountMessageBinding
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	var parsed binding
	if err := d.Decode(&parsed); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("invalid account message binding")
	}
	*b = BrowserAccountMessageBinding(parsed)
	return nil
}

func (a AAD) validateBrowserAccountMessageBinding() error {
	b := a.BrowserAccountMessage
	if b == nil {
		return nil
	}
	digest, err := hex.DecodeString(b.BindingDigest)
	if err != nil || len(digest) != 32 || hex.EncodeToString(digest) != b.BindingDigest || b.SenderKind != BrowserAccountDelegateSenderKind || a.ProtocolVersion != 2 || a.ObjectType != ObjectTypeMessage || a.TenantID == "" || a.NetworkID == "" || a.ObjectID == "" || a.Sender == "" || a.Recipient == "" || a.CreatedAt == "" || a.KeyEpochID == "" || a.ProtectedContext != nil || a.NativeContent != nil {
		return errors.New("invalid account message AAD")
	}
	return nil
}
