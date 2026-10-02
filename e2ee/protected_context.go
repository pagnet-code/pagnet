package e2ee

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"regexp"
)

const OwnerContextKind = "account_host"

var contextIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// ProtectedContext is a real private content authority, not a network alias.
// No network membership or service credential confers authority over it.
type ProtectedContext struct {
	Kind        string `json:"kind"`
	ID          string `json:"id"`
	TenantID    string `json:"tenant_id"`
	OwnerUserID string `json:"owner_user_id"`
	HostID      string `json:"host_id"`
}

// A protected authority has a closed schema. Unknown fields cannot silently
// change a caller's intended scope while being omitted from authenticated AAD.
func (c *ProtectedContext) UnmarshalJSON(raw []byte) error {
	type descriptor ProtectedContext
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var parsed descriptor
	if err := decoder.Decode(&parsed); err != nil {
		return err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errors.New("invalid protected content context")
	}
	*c = ProtectedContext(parsed)
	return c.Validate()
}
func (c ProtectedContext) Validate() error {
	if c.Kind != OwnerContextKind || !contextIDPattern.MatchString(c.ID) || !contextIDPattern.MatchString(c.TenantID) || !contextIDPattern.MatchString(c.OwnerUserID) || !contextIDPattern.MatchString(c.HostID) {
		return errors.New("invalid protected content context")
	}
	return nil
}
func (a AAD) ValidateScope() error {
	if err := a.validateNativeContentBinding(); err != nil {
		return err
	}
	if a.ProtectedContext == nil {
		if a.NetworkID == "" {
			return errors.New("missing protected content scope")
		}
		return nil
	}
	if a.NetworkID != "" || a.ProtectedContext.Validate() != nil || a.TenantID != a.ProtectedContext.TenantID {
		return errors.New("contradictory protected content scope")
	}
	return nil
}

const HPKEInfoOwnerCEK = "pagnet.owner-context.cek.v1"

func OwnerBrowserSessionAAD(c ProtectedContext, session, object string) []byte {
	b, _ := canonicalJSON(struct {
		Purpose string           `json:"purpose"`
		Context ProtectedContext `json:"context"`
		Session string           `json:"session_id"`
		Object  string           `json:"object_id"`
	}{HPKEInfoOwnerCEK, c, session, object})
	return b
}

// ApprovalProof authenticates inspected content and the exact chosen native
// option. Its secret is delivered only inside the encrypted inspection object.
func ApprovalProof(secret []byte, aad AAD, instance, session, native, option string) ([]byte, error) {
	if len(secret) != 32 || aad.ProtectedContext == nil || aad.ValidateScope() != nil || instance == "" || session == "" || native == "" || option == "" {
		return nil, errors.New("invalid inspected approval binding")
	}
	b, err := canonicalJSON(struct {
		Purpose  string `json:"purpose"`
		AAD      string `json:"aad"`
		Instance string `json:"instance_id"`
		Session  string `json:"session_id"`
		Native   string `json:"native_interaction_id"`
		Option   string `json:"option_id"`
	}{"pagnet.owner-approval.v1", base64.StdEncoding.EncodeToString(aad.CanonicalBytes()), instance, session, native, option})
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(b)
	return mac.Sum(nil), nil
}
