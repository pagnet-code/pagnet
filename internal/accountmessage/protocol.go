package accountmessage

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"unicode/utf8"

	schema "github.com/pagnet-code/pagnet/accountmessage"
	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/transport"
)

const MaxTextBytes = 16384
const MaxFrameBytes = 128 << 10

type Sender = schema.Sender

type Descriptor schema.Descriptor

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
	if DecodeFrame(raw, target) != nil {
		return errors.New("invalid account message JSON")
	}
	return nil
}

func (d Descriptor) CanonicalJSON() []byte { return schema.Descriptor(d).CanonicalJSON() }
func (d Descriptor) BindingDigest() string { return schema.Descriptor(d).BindingDigest() }
func (d Descriptor) Validate() error       { return schema.Descriptor(d).Validate() }
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

// DecodeFrame rejects invalid UTF-8, unpaired JSON UTF-16 surrogate escapes,
// duplicate/unknown/case-aliased or missing fields, and oversized frames.
func DecodeFrame(raw []byte, target any) error {
	if len(raw) > MaxFrameBytes || !validJSONUnicode(raw) || transport.DecodeOwnerTextConsolePayload(raw, target) != nil {
		return errors.New("invalid account message frame")
	}
	return nil
}
func validJSONUnicode(raw []byte) bool {
	if !utf8.Valid(raw) {
		return false
	}
	inString := false
	for i := 0; i < len(raw); i++ {
		if raw[i] == '"' {
			inString = !inString
			continue
		}
		if !inString || raw[i] != '\\' {
			continue
		}
		i++
		if i >= len(raw) {
			return false
		}
		if raw[i] != 'u' {
			continue
		}
		if i+4 >= len(raw) {
			return false
		}
		n, e := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
		if e != nil {
			return false
		}
		i += 4
		if n >= 0xdc00 && n <= 0xdfff {
			return false
		}
		if n >= 0xd800 && n <= 0xdbff {
			if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
				return false
			}
			low, e := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
			if e != nil || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return true
}
