package transport

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"

	"github.com/pagnet-code/pagnet/domain"
)

var errNativeShareEpochStageReceipt = errors.New("transport: invalid native share epoch stage receipt")

// NativeShareEpochStageReceipt is recipient-host-signed evidence of ciphertext
// staging. It grants no installation, admission or epoch key authority. The
// caller must independently retain the expected context and trusted host key.
type NativeShareEpochStageReceipt struct {
	Version     int       `json:"version"`
	BindingID   domain.ID `json:"bindingId"`
	OperationID domain.ID `json:"operationId"`
	Digest      string    `json:"digest"`
	Signature   []byte    `json:"signature"`
}

// CanonicalBytes preserves the original stage transcript, including its null
// signature field. The detached signature is excluded from the signed bytes.
func (r NativeShareEpochStageReceipt) CanonicalBytes() ([]byte, error) {
	if r.Version != NativeShareEpochVersion || !nativeShareBindingID(r.BindingID) || !nativeShareBindingID(r.OperationID) || !nativeShareBindingHex(r.Digest) {
		return nil, errNativeShareEpochStageReceipt
	}
	r.Signature = nil
	raw, err := json.Marshal(r)
	return append([]byte("pagnet/native-share-epoch/staged/v1/"), raw...), err
}

func (r NativeShareEpochStageReceipt) Verify(expectedBindingID, expectedOperationID domain.ID, trustedRecipientHost ed25519.PublicKey) error {
	raw, err := r.CanonicalBytes()
	if err != nil || r.BindingID != expectedBindingID || r.OperationID != expectedOperationID || len(trustedRecipientHost) != ed25519.PublicKeySize || len(r.Signature) != ed25519.SignatureSize || !ed25519.Verify(trustedRecipientHost, raw, r.Signature) {
		return errNativeShareEpochStageReceipt
	}
	return nil
}

// DecodeNativeShareEpochStageReceipt checks wire shape and values, but callers
// must Verify with independently retained context and a trusted recipient key.
func DecodeNativeShareEpochStageReceipt(raw []byte) (NativeShareEpochStageReceipt, error) {
	var r NativeShareEpochStageReceipt
	if len(raw) > 4<<10 || !strictNativeShareEpochStageReceiptJSON(raw) || json.Unmarshal(raw, &r) != nil {
		return NativeShareEpochStageReceipt{}, errNativeShareEpochStageReceipt
	}
	if _, err := r.CanonicalBytes(); err != nil || len(r.Signature) != ed25519.SignatureSize {
		return NativeShareEpochStageReceipt{}, errNativeShareEpochStageReceipt
	}
	return r, nil
}

func strictNativeShareEpochStageReceiptJSON(raw []byte) bool {
	fields := map[string]bool{"version": true, "bindingId": true, "operationId": true, "digest": true, "signature": true}
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return false
	}
	seen := make(map[string]bool)
	for d.More() {
		token, err = d.Token()
		name, ok := token.(string)
		if err != nil || !ok || !fields[name] || seen[name] {
			return false
		}
		seen[name] = true
		token, err = d.Token()
		if err != nil || token == nil {
			return false
		}
		if _, ok := token.(json.Delim); ok {
			return false
		}
		if name == "signature" {
			value, ok := token.(string)
			if !ok {
				return false
			}
			decoded, err := base64.StdEncoding.Strict().DecodeString(value)
			if err != nil || base64.StdEncoding.EncodeToString(decoded) != value {
				return false
			}
		}
	}
	token, err = d.Token()
	if err != nil || token != json.Delim('}') || len(seen) != len(fields) {
		return false
	}
	_, err = d.Token()
	return err == io.EOF
}
