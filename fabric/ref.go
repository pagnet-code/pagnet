// Package fabric defines provider-independent agent and service contracts.
package fabric

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"io"
	"strings"
)

const (
	EndpointRefLength     = 118
	OfferRefLength        = 173
	domainNamespaceLength = 54
	referenceIDLength     = 52
	referencePrefix       = "pagnet://"
)

var referenceBase32 = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// EndpointRef is an immutable canonical identity, not proof of trust or access.
// Labels, aliases, database IDs and network locations are not part of this URI.
// Its zero value denotes no reference and cannot be serialized as a valid one.
type EndpointRef struct {
	namespace  string
	endpointID string
	offerID    string
}

func referenceInputError(message string) error { return NewError(CodeInvalidInput, message) }

// DomainNamespace derives the self-certifying namespace from an independent
// domain's 32-byte Ed25519 genesis public key. It does not establish trust.
func DomainNamespace(domainPublicKey []byte) (string, error) {
	if len(domainPublicKey) != 32 {
		return "", referenceInputError("domain genesis public key must be 32 bytes")
	}
	hash := sha256.New()
	hash.Write([]byte("pagnet.fabric.domain.v1\x00"))
	hash.Write(domainPublicKey)
	return "d-" + referenceBase32.EncodeToString(hash.Sum(nil)), nil
}

// NewEndpointRef allocates a random stable endpoint identity. Registry storage
// must still reject identity collisions atomically; this function owns no store.
func NewEndpointRef(domainPublicKey []byte) (EndpointRef, error) {
	return newEndpointRef(domainPublicKey, rand.Reader)
}

func newEndpointRef(domainPublicKey []byte, entropy io.Reader) (EndpointRef, error) {
	namespace, err := DomainNamespace(domainPublicKey)
	if err != nil {
		return EndpointRef{}, err
	}
	var id [32]byte
	if _, err = io.ReadFull(entropy, id[:]); err != nil {
		return EndpointRef{}, referenceInputError("endpoint identity entropy unavailable")
	}
	return EndpointRef{namespace: namespace, endpointID: referenceBase32.EncodeToString(id[:])}, nil
}

func canonicalReferenceID(text string) bool {
	if len(text) != referenceIDLength {
		return false
	}
	for i := range len(text) {
		c := text[i]
		if !(c >= 'a' && c <= 'z' || c >= '2' && c <= '7') {
			return false
		}
	}
	raw, err := referenceBase32.DecodeString(text)
	return err == nil && len(raw) == 32 && referenceBase32.EncodeToString(raw) == text
}

func canonicalDomainNamespace(namespace string) bool {
	return len(namespace) == domainNamespaceLength && strings.HasPrefix(namespace, "d-") && canonicalReferenceID(namespace[2:])
}

// ParseEndpointRef accepts only the two exact canonical forms. It performs no
// URI normalization, percent decoding, case folding or alias resolution.
func ParseEndpointRef(text string) (EndpointRef, error) {
	var ref EndpointRef
	if (len(text) != EndpointRefLength && len(text) != OfferRefLength) || !strings.HasPrefix(text, referencePrefix) {
		return ref, referenceInputError("invalid canonical endpoint reference")
	}
	namespace := text[len(referencePrefix) : len(referencePrefix)+domainNamespaceLength]
	endpointOffset := len(referencePrefix) + domainNamespaceLength
	if !canonicalDomainNamespace(namespace) || text[endpointOffset:endpointOffset+3] != "/e/" {
		return ref, referenceInputError("invalid canonical endpoint reference")
	}
	endpointID := text[endpointOffset+3 : EndpointRefLength]
	if !canonicalReferenceID(endpointID) {
		return ref, referenceInputError("invalid canonical endpoint identity")
	}
	ref = EndpointRef{namespace: namespace, endpointID: endpointID}
	if len(text) == OfferRefLength {
		if text[EndpointRefLength:EndpointRefLength+3] != "#o-" || !canonicalReferenceID(text[EndpointRefLength+3:]) {
			return EndpointRef{}, referenceInputError("invalid canonical offer reference")
		}
		ref.offerID = text[EndpointRefLength+3:]
	}
	return ref, nil
}

// WithOfferID builds an explicitly selected offer reference from exactly 32
// opaque identity bytes. It leaves the receiver and parent endpoint unchanged.
func (r EndpointRef) WithOfferID(id []byte) (EndpointRef, error) {
	if _, err := ParseEndpointRef(r.String()); err != nil {
		return EndpointRef{}, err
	}
	if len(id) != 32 {
		return EndpointRef{}, referenceInputError("offer identity must be 32 bytes")
	}
	r.offerID = referenceBase32.EncodeToString(id)
	return r, nil
}

func (r EndpointRef) String() string {
	if r.namespace == "" || r.endpointID == "" {
		return ""
	}
	ref := referencePrefix + r.namespace + "/e/" + r.endpointID
	if r.offerID != "" {
		ref += "#o-" + r.offerID
	}
	return ref
}
func (r EndpointRef) Domain() string        { return r.namespace }
func (r EndpointRef) IsOffer() bool         { return r.offerID != "" }
func (r EndpointRef) Endpoint() EndpointRef { r.offerID = ""; return r }

func (r EndpointRef) MarshalJSON() ([]byte, error) {
	if _, err := ParseEndpointRef(r.String()); err != nil {
		return nil, err
	}
	return json.Marshal(r.String())
}
func (r *EndpointRef) UnmarshalJSON(raw []byte) error {
	if r == nil {
		return referenceInputError("endpoint reference destination is nil")
	}
	// JSON Unicode escapes can occupy six bytes per accepted ASCII character.
	if len(raw) > 6*OfferRefLength+2 {
		return referenceInputError("endpoint reference JSON exceeds bound")
	}
	raw = bytes.TrimSpace(raw)
	var text string
	if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &text) != nil {
		return referenceInputError("endpoint reference must be a JSON string")
	}
	parsed, err := ParseEndpointRef(text)
	if err != nil {
		return err
	}
	*r = parsed
	return nil
}
