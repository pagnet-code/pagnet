package transport

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"
	"unicode/utf8"

	"github.com/pagnet-code/pagnet/domain"
)

var errNativeShareEpochStageCommand = errors.New("transport: invalid native share epoch stage command or result")

// NativeShareEpochStageCommand carries proposed staging inputs, never authority.
// Expected and SourceSigningPublicKey must match independently retained values.
type NativeShareEpochStageCommand struct {
	Version                int                      `json:"version"`
	BindingID              domain.ID                `json:"bindingId"`
	Expected               NativeShareEpochMetadata `json:"expected"`
	SourceSigningPublicKey []byte                   `json:"sourceSigningPublicKey"`
	Package                []byte                   `json:"package"`
}

// Digest authenticates every field, including the original package bytes.
func (c NativeShareEpochStageCommand) Digest() (string, error) {
	if c.Version != NativeShareEpochVersion || !nativeShareBindingID(c.BindingID) || len(c.SourceSigningPublicKey) != ed25519.PublicKeySize || len(c.Package) == 0 || len(c.Package) > 16<<10 {
		return "", errNativeShareEpochStageCommand
	}
	if _, err := c.Expected.AAD(); err != nil {
		return "", errNativeShareEpochStageCommand
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return "", errNativeShareEpochStageCommand
	}
	digest := sha256.Sum256(append([]byte("pagnet/native-share-epoch/stage-command/v1/"), raw...))
	return hex.EncodeToString(digest[:]), nil
}

// Verify binds the enclosing command ID and retained context before verifying
// the source's package signature. The carried public key is never a trust root.
func (c NativeShareEpochStageCommand) Verify(commandID, bindingID domain.ID, expected NativeShareEpochMetadata, trustedSource ed25519.PublicKey, now time.Time) error {
	if _, err := c.Digest(); err != nil {
		return err
	}
	if c.Expected.CommandID != commandID || c.BindingID != bindingID || c.Expected != expected || len(trustedSource) != ed25519.PublicKeySize || !bytes.Equal(c.SourceSigningPublicKey, trustedSource) {
		return errNativeShareEpochStageCommand
	}
	if _, err := DecodeNativeShareEpochPackage(c.Package, expected, trustedSource, now); err != nil {
		return errNativeShareEpochStageCommand
	}
	return nil
}

// ParseNativeShareEpochStageCommand checks strict wire shape, bounds and static
// values without verifying signatures, current time or retained authority.
// Callers must Verify before authorizing new work.
func ParseNativeShareEpochStageCommand(raw []byte) (NativeShareEpochStageCommand, error) {
	var c NativeShareEpochStageCommand
	if len(raw) > 32<<10 || !strictNativeShareStageWireJSON(raw, "command") || json.Unmarshal(raw, &c) != nil {
		return NativeShareEpochStageCommand{}, errNativeShareEpochStageCommand
	}
	if _, err := c.Digest(); err != nil {
		return NativeShareEpochStageCommand{}, errNativeShareEpochStageCommand
	}
	return c, nil
}

// DecodeNativeShareEpochStageCommand validates shape, bounds and retained context.
func DecodeNativeShareEpochStageCommand(raw []byte, commandID, bindingID domain.ID, expected NativeShareEpochMetadata, trustedSource ed25519.PublicKey, now time.Time) (NativeShareEpochStageCommand, error) {
	c, err := ParseNativeShareEpochStageCommand(raw)
	if err != nil || c.Verify(commandID, bindingID, expected, trustedSource, now) != nil {
		return NativeShareEpochStageCommand{}, errNativeShareEpochStageCommand
	}
	return c, nil
}

// NativeShareEpochStageResult binds recipient evidence to one exact command.
// It grants no installation, admission or epoch activation authority.
type NativeShareEpochStageResult struct {
	Version       int                          `json:"version"`
	CommandID     domain.ID                    `json:"commandId"`
	CommandDigest string                       `json:"commandDigest"`
	Receipt       NativeShareEpochStageReceipt `json:"receipt"`
	Signature     []byte                       `json:"signature"`
}

// SignatureBytes excludes only the result's detached Signature. The receipt,
// including its existing signature, is preserved verbatim in the transcript.
func (r NativeShareEpochStageResult) SignatureBytes() ([]byte, error) {
	if r.Version != NativeShareEpochVersion || !nativeShareBindingID(r.CommandID) || !nativeShareBindingHex(r.CommandDigest) || len(r.Receipt.Signature) != ed25519.SignatureSize {
		return nil, errNativeShareEpochStageCommand
	}
	if _, err := r.Receipt.CanonicalBytes(); err != nil {
		return nil, errNativeShareEpochStageCommand
	}
	raw, err := json.Marshal(struct {
		Version       int                          `json:"version"`
		CommandID     domain.ID                    `json:"commandId"`
		CommandDigest string                       `json:"commandDigest"`
		Receipt       NativeShareEpochStageReceipt `json:"receipt"`
	}{r.Version, r.CommandID, r.CommandDigest, r.Receipt})
	return append([]byte("pagnet/native-share-epoch/stage-result/v1/"), raw...), err
}

// Verify requires the independently retained, previously verified exact command
// and trusted recipient host. It does not refresh command authorization.
func (r NativeShareEpochStageResult) Verify(commandID domain.ID, command NativeShareEpochStageCommand, trustedRecipientHost ed25519.PublicKey) error {
	digest, err := command.Digest()
	if err != nil || command.Expected.CommandID != commandID || r.CommandID != commandID || r.CommandDigest != digest || r.Receipt.Verify(command.BindingID, command.Expected.OperationID, trustedRecipientHost) != nil {
		return errNativeShareEpochStageCommand
	}
	raw, err := r.SignatureBytes()
	if err != nil || len(r.Signature) != ed25519.SignatureSize || !ed25519.Verify(trustedRecipientHost, raw, r.Signature) {
		return errNativeShareEpochStageCommand
	}
	return nil
}

// ParseNativeShareEpochStageResult checks strict wire shape, bounds and static
// values without signature or retained-context verification. It can parse
// immutable replay evidence after the original command deadline has passed.
func ParseNativeShareEpochStageResult(raw []byte) (NativeShareEpochStageResult, error) {
	var r NativeShareEpochStageResult
	if len(raw) > 8<<10 || !strictNativeShareStageWireJSON(raw, "result") || json.Unmarshal(raw, &r) != nil || len(r.Signature) != ed25519.SignatureSize {
		return NativeShareEpochStageResult{}, errNativeShareEpochStageCommand
	}
	if _, err := r.SignatureBytes(); err != nil {
		return NativeShareEpochStageResult{}, errNativeShareEpochStageCommand
	}
	return r, nil
}

func DecodeNativeShareEpochStageResult(raw []byte, commandID domain.ID, command NativeShareEpochStageCommand, trustedRecipientHost ed25519.PublicKey) (NativeShareEpochStageResult, error) {
	r, err := ParseNativeShareEpochStageResult(raw)
	if err != nil || r.Verify(commandID, command, trustedRecipientHost) != nil {
		return NativeShareEpochStageResult{}, errNativeShareEpochStageCommand
	}
	return r, nil
}

// Every object has exact, unique, case-sensitive, nonnullable fields. Byte
// strings use canonical base64; nested objects receive the same strict checks.
func strictNativeShareStageWireJSON(raw []byte, root string) bool {
	if !utf8.Valid(raw) {
		return false
	}
	schemas := map[string]map[string]string{
		"command":  {"version": "", "bindingId": "", "expected": "metadata", "sourceSigningPublicKey": "bytes", "package": "bytes"},
		"result":   {"version": "", "commandId": "", "commandDigest": "", "receipt": "receipt", "signature": "bytes"},
		"receipt":  {"version": "", "bindingId": "", "operationId": "", "digest": "", "signature": "bytes"},
		"metadata": {"version": "", "operationId": "", "tenantId": "", "networkId": "", "previousEpochId": "", "epochId": "", "epochPossessionVerifier": "", "proposalRevision": "", "grantGeneration": "", "bindingDigest": "", "holderId": "", "holderX25519": "", "commandId": "", "commandConnectionId": "", "authorityConnectionId": "", "deadline": ""},
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	var object func(string) bool
	object = func(schema string) bool {
		token, err := d.Token()
		if err != nil || token != json.Delim('{') {
			return false
		}
		seen := make(map[string]bool)
		for d.More() {
			token, err = d.Token()
			name, ok := token.(string)
			child, allowed := schemas[schema][name]
			if err != nil || !ok || !allowed || seen[name] {
				return false
			}
			seen[name] = true
			if child != "" && child != "bytes" {
				if !object(child) {
					return false
				}
				continue
			}
			token, err = d.Token()
			if err != nil || token == nil {
				return false
			}
			if _, ok := token.(json.Delim); ok {
				return false
			}
			if child == "bytes" {
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
		return err == nil && token == json.Delim('}') && len(seen) == len(schemas[schema])
	}
	if !object(root) {
		return false
	}
	_, err := d.Token()
	return err == io.EOF
}
