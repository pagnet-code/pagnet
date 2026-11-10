package accountmessage

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/pagnet-code/pagnet/e2ee"
)

const MaxTextBytes = 16384
const MaxFrameBytes = 128 << 10

type Sender struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

// Descriptor's declaration order is the v1 cross-language canonical contract.
type Descriptor struct {
	V                        int    `json:"v"`
	MessageID                string `json:"messageId"`
	TenantID                 string `json:"tenantId"`
	OwnerUserID              string `json:"ownerUserId"`
	ConnectionID             string `json:"connectionId"`
	Sender                   Sender `json:"sender"`
	NetworkID                string `json:"networkId"`
	TargetPrincipalID        string `json:"targetPrincipalId"`
	HostID                   string `json:"hostId"`
	TargetDefinitionID       string `json:"targetDefinitionId"`
	TargetInstanceID         string `json:"targetInstanceId"`
	ConsentID                string `json:"consentId"`
	ResourceID               string `json:"resourceId"`
	IdentityIncarnationID    string `json:"identityIncarnationId"`
	DesiredRevision          string `json:"desiredRevision"`
	RunnerID                 string `json:"runnerId"`
	RunnerConnectedAt        string `json:"runnerConnectedAt"`
	ServerInstanceID         string `json:"serverInstanceId"`
	HostConnectionGeneration string `json:"hostConnectionGeneration"`
	KeyHolderID              string `json:"keyHolderId"`
	EpochID                  string `json:"epochId"`
	OfferID                  string `json:"offerId"`
	ReadinessGeneration      string `json:"readinessGeneration"`
	OfferDigest              string `json:"offerDigest"`
	SubscriptionID           string `json:"subscriptionId"`
	SubscriptionVersion      string `json:"subscriptionVersion"`
	CreatedAt                string `json:"createdAt"`
	ExpiresAt                string `json:"expiresAt"`
}

func canonical(v any) []byte {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if e.Encode(v) != nil {
		panic("account message canonical encoding")
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n"))
}
func digest(v any) string { s := sha256.Sum256(canonical(v)); return hex.EncodeToString(s[:]) }
func validDigest(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == s
}
func decode(raw []byte, target any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if e := d.Decode(target); e != nil {
		return e
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("invalid account message JSON")
	}
	return nil
}
func (d Descriptor) CanonicalJSON() []byte { return canonical(d) }
func (d Descriptor) BindingDigest() string { return digest(d) }
func (d Descriptor) Validate() error {
	invalid := errors.New("invalid account message descriptor")
	if d.V != 1 || d.Sender.Kind != e2ee.BrowserAccountDelegateSenderKind || !validDigest(d.OfferDigest) {
		return invalid
	}
	for _, s := range []string{d.MessageID, d.TenantID, d.OwnerUserID, d.ConnectionID, d.Sender.ID, d.NetworkID, d.TargetPrincipalID, d.HostID, d.TargetDefinitionID, d.TargetInstanceID, d.ConsentID, d.ResourceID, d.IdentityIncarnationID, d.RunnerID, d.ServerInstanceID, d.KeyHolderID, d.EpochID, d.OfferID, d.SubscriptionID} {
		if len(s) < 1 || len(s) > 128 || !utf8.ValidString(s) {
			return invalid
		}
	}
	for _, s := range []string{d.DesiredRevision, d.HostConnectionGeneration, d.ReadinessGeneration} {
		n, e := strconv.ParseInt(s, 10, 64)
		if e != nil || n <= 0 || strconv.FormatInt(n, 10) != s {
			return invalid
		}
	}
	n, e := strconv.ParseUint(d.SubscriptionVersion, 10, 64)
	if e != nil || n == 0 || strconv.FormatUint(n, 10) != d.SubscriptionVersion {
		return invalid
	}
	for _, s := range []string{d.RunnerConnectedAt, d.CreatedAt, d.ExpiresAt} {
		t, e := time.Parse(time.RFC3339Nano, s)
		if e != nil || t.UTC().Format(time.RFC3339Nano) != s {
			return invalid
		}
	}
	created, _ := time.Parse(time.RFC3339Nano, d.CreatedAt)
	expires, _ := time.Parse(time.RFC3339Nano, d.ExpiresAt)
	if !expires.After(created) || expires.Sub(created) > time.Minute {
		return invalid
	}
	return nil
}
func (d Descriptor) AAD(binding string) e2ee.AAD {
	return e2ee.AAD{ProtocolVersion: 2, TenantID: d.TenantID, NetworkID: d.NetworkID, ObjectType: e2ee.ObjectTypeMessage, ObjectID: d.MessageID, Sender: d.Sender.ID, Recipient: d.TargetPrincipalID, CreatedAt: d.CreatedAt, KeyEpochID: d.EpochID, BrowserAccountMessage: &e2ee.BrowserAccountMessageBinding{BindingDigest: binding, SenderKind: d.Sender.Kind}}
}

type SealRequest struct {
	V             int        `json:"v"`
	Descriptor    Descriptor `json:"descriptor"`
	BindingDigest string     `json:"bindingDigest"`
	Text          string     `json:"text"`
}

func (r SealRequest) Validate() error {
	if r.V != 1 || r.Descriptor.Validate() != nil || r.BindingDigest != r.Descriptor.BindingDigest() || len(r.Text) < 1 || len(r.Text) > MaxTextBytes || !utf8.ValidString(r.Text) {
		return errors.New("invalid account message seal")
	}
	return nil
}
func ParseSeal(raw []byte) (SealRequest, error) {
	var r SealRequest
	if len(raw) > MaxFrameBytes || !utf8.Valid(raw) {
		return r, errors.New("invalid account seal frame")
	}
	if e := decode(raw, &r); e != nil {
		return SealRequest{}, errors.New("invalid account seal frame")
	}
	return r, r.Validate()
}

// Descriptor is retained locally for retry comparison. Reply omits it.
type Sealed struct {
	V             int                     `json:"v"`
	MessageID     string                  `json:"messageId"`
	BindingDigest string                  `json:"bindingDigest"`
	SealedDigest  string                  `json:"sealedDigest"`
	Envelope      e2ee.EncryptedPayloadV1 `json:"envelope"`
	Descriptor    Descriptor              `json:"descriptor"`
}

func (s Sealed) Digest() string {
	return digest(struct {
		Descriptor Descriptor              `json:"descriptor"`
		Envelope   e2ee.EncryptedPayloadV1 `json:"envelope"`
	}{s.Descriptor, s.Envelope})
}
func (s Sealed) Validate() error {
	if s.V != 1 || s.Descriptor.Validate() != nil || s.MessageID != s.Descriptor.MessageID || s.BindingDigest != s.Descriptor.BindingDigest() || s.SealedDigest != s.Digest() || s.Envelope.Validate() != nil || s.Envelope.KeyEpochID != s.Descriptor.EpochID {
		return errors.New("invalid sealed account message")
	}
	return nil
}
func (s Sealed) Reply() any {
	return struct {
		V             int                     `json:"v"`
		MessageID     string                  `json:"messageId"`
		BindingDigest string                  `json:"bindingDigest"`
		SealedDigest  string                  `json:"sealedDigest"`
		Envelope      e2ee.EncryptedPayloadV1 `json:"envelope"`
	}{s.V, s.MessageID, s.BindingDigest, s.SealedDigest, s.Envelope}
}
