// Package directchannelcrypto implements local direct-channel publication and readiness cryptography.
package directchannelcrypto

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/transport"
)

const domain = transport.DirectChannelDomainV2

// ErrInvalid reports an invalid direct-channel context or wire.
var ErrInvalid = errors.New("sdk: invalid direct channel context or wire")

func privateMatches(private, public []byte) bool {
	key, err := ecdh.X25519().NewPrivateKey(private)
	return err == nil && bytes.Equal(key.PublicKey().Bytes(), public)
}

func binary(s string, size int) ([]byte, error) {
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || (size >= 0 && len(b) != size) || base64.RawURLEncoding.EncodeToString(b) != s {
		return nil, ErrInvalid
	}
	return b, nil
}
func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
func validate(raw []byte, expected transport.DirectChannelDescriptorV2, now time.Time) (transport.DirectChannelDescriptorV2, error) {
	d, err := transport.DecodeDirectChannelDescriptorV2(raw)
	trusted, terr := expected.CanonicalBytes()
	if err != nil || terr != nil || !bytes.Equal(raw, trusted) || transport.ValidateDirectChannelDescriptorV2(d, now) != nil {
		return transport.DirectChannelDescriptorV2{}, ErrInvalid
	}
	return d, nil
}

func channelID(d transport.DirectChannelDescriptorV2) string {
	id, _ := transport.DirectChannelIDV2(d)
	return id
}

// Material is local-only and must never be serialized to N. The derived
// readiness key is suitable for the readiness verifier; the root
// and traffic keys stay local. Fields support adapters inside this module and
// are excluded from JSON; callers must clear owned material and derived keys.
type Material struct {
	Descriptor      transport.DirectChannelDescriptorV2 `json:"-"`
	Hash            [32]byte                            `json:"-"`
	Key             [32]byte                            `json:"-"`
	Role            string                              `json:"-"`
	PublicationHash [32]byte                            `json:"-"` // set only after preparing, accepting, or validating the stored exact publication
}

func materialFor(d transport.DirectChannelDescriptorV2, raw, key []byte, role string) (*Material, error) {
	if len(key) != 32 || (role != "S" && role != "P") {
		return nil, ErrInvalid
	}
	m := &Material{Descriptor: d, Hash: sha256.Sum256(raw), Role: role}
	copy(m.Key[:], key)
	return m, nil
}

// Prepare creates an authenticated epoch-key publication for the source endpoint.
func Prepare(raw []byte, expected transport.DirectChannelDescriptorV2, private []byte, now time.Time) (*Material, []byte, error) {
	d, err := validate(raw, expected, now)
	if err != nil {
		return nil, nil, err
	}
	pub, _ := binary(d.S.PublicKey, 32)
	recipient, _ := binary(d.P.PublicKey, 32)
	if !privateMatches(private, pub) {
		return nil, nil, ErrInvalid
	}
	key := make([]byte, 32)
	defer clear(key)
	if _, err = rand.Read(key); err != nil {
		return nil, nil, err
	}
	hash := sha256.Sum256(raw)
	enc, ct, err := e2ee.HPKEWrapAuth(recipient, private, []byte(domain+"/epoch-wrap"), hash[:], key)
	if err != nil {
		return nil, nil, err
	}
	wire, err := (transport.DirectChannelPublicationV2{Descriptor: d, Enc: b64(enc), Ciphertext: b64(ct)}).CanonicalBytes()
	if err != nil {
		return nil, nil, err
	}
	m, err := materialFor(d, raw, key, "S")
	if err != nil {
		return nil, nil, err
	}
	m.PublicationHash = sha256.Sum256(wire)
	return m, wire, nil
}

// Accept authenticates a publication for the peer endpoint.
func Accept(wire []byte, expected transport.DirectChannelDescriptorV2, private []byte, now time.Time) (*Material, error) {
	p, err := transport.DecodeDirectChannelPublicationV2(wire)
	if err != nil {
		return nil, ErrInvalid
	}
	raw, err := p.Descriptor.CanonicalBytes()
	if err != nil {
		return nil, ErrInvalid
	}
	d, err := validate(raw, expected, now)
	if err != nil {
		return nil, err
	}
	pub, _ := binary(d.P.PublicKey, 32)
	sender, _ := binary(d.S.PublicKey, 32)
	enc, eerr := binary(p.Enc, 32)
	ct, cerr := binary(p.Ciphertext, 48)
	if !privateMatches(private, pub) || eerr != nil || cerr != nil {
		return nil, ErrInvalid
	}
	hash := sha256.Sum256(raw)
	key, err := e2ee.HPKEUnwrapAuth(private, sender, enc, []byte(domain+"/epoch-wrap"), hash[:], ct)
	defer clear(key)
	if err != nil {
		return nil, err
	}
	m, err := materialFor(d, raw, key, "P")
	if err != nil {
		return nil, err
	}
	m.PublicationHash = sha256.Sum256(wire)
	return m, nil
}
func (m *Material) derive(purpose string) ([]byte, error) {
	return hkdf.Key(sha256.New, m.Key[:], m.Hash[:], domain+"/"+purpose, 32)
}

// ReadinessKey returns a caller-owned key that must be cleared after use.
func (m *Material) ReadinessKey() ([]byte, error) { return m.derive("readiness") }

// ReadinessProof uses a credential ID from authenticated local metadata. It
// only proves possession; challenge issuance and replay consumption are external.
func (m *Material) ReadinessProof(raw []byte, credentialID string, now time.Time) ([]byte, error) {
	challenge, err := transport.DecodeDirectChannelReadinessChallengeV2(raw)
	if err != nil || m.PublicationHash == ([32]byte{}) || challenge.Role != m.Role {
		return nil, ErrInvalid
	}
	d := m.Descriptor
	party := d.S
	if m.Role == "P" {
		party = d.P
	}
	issued, _ := time.Parse(time.RFC3339Nano, challenge.IssuedAt)
	expiry, _ := time.Parse(time.RFC3339Nano, challenge.ExpiresAt)
	descriptorExpiry, _ := time.Parse(time.RFC3339Nano, d.ExpiresAt)
	if transport.ValidateDirectChannelDescriptorV2(d, now) != nil || now.Before(issued) || !expiry.After(now) || expiry.After(descriptorExpiry) || credentialID != party.CredentialID || challenge.CredentialID != credentialID || challenge.PrincipalID != party.PrincipalID || challenge.EndpointID != party.EndpointID || challenge.ChannelID != channelID(d) || challenge.ParentGrantID != d.ParentGrantID || challenge.GrantGeneration != d.GrantGeneration || challenge.ChannelGeneration != d.ChannelGeneration || challenge.DirectIntentID != d.DirectIntentID || challenge.DescriptorHash != b64(m.Hash[:]) || challenge.PublicationHash != b64(m.PublicationHash[:]) || challenge.EpochID != d.EpochID {
		return nil, ErrInvalid
	}
	key, err := m.ReadinessKey()
	defer clear(key)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(raw)
	transcriptHash := sha256.Sum256(raw)
	proof := transport.DirectChannelReadinessProofV2{ProtocolVersion: transport.DirectChannelReadinessProtocolV2, ChallengeID: challenge.ChallengeID, TranscriptHash: b64(transcriptHash[:]), Confirmation: b64(mac.Sum(nil))}
	return proof.CanonicalBytes()
}

// Clear erases local epoch key material when its owner is finished with it.
func (m *Material) Clear() { clear(m.Key[:]) }

// Format redacts local material for every formatting verb, including %#v.
func (m Material) Format(s fmt.State, verb rune) {
	_, _ = s.Write([]byte("directchannelcrypto.Material{REDACTED}"))
}
