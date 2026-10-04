package fabric

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"time"
)

const PeerCertificateSigningPurpose = "pagnet.fabric.peer-certificate.v1"

// PeerCertificate binds an independently generated exchange public key to its
// original immutable domain authority. A valid signature is not a trusted pin.
type PeerCertificate struct {
	Namespace           string   `json:"namespace"`
	StoreID             string   `json:"storeId"`
	RootKeyRevision     uint64   `json:"rootKeyRevision,string"`
	RootPublicKey       [32]byte `json:"rootPublicKey"`
	ExchangePublicKey   [32]byte `json:"exchangePublicKey"`
	ExchangeKeyRevision uint64   `json:"exchangeKeyRevision,string"`
	BindingProfile      string   `json:"bindingProfile"`
	IssuedAt            string   `json:"issuedAt"`
	ExpiresAt           string   `json:"expiresAt"`
}
type SignedPeerCertificate struct {
	Certificate PeerCertificate `json:"certificate"`
	Signature   []byte          `json:"signature"`
}

func (c PeerCertificate) SigningBytes() ([]byte, error) {
	namespace, err := DomainNamespace(c.RootPublicKey[:])
	if err != nil || namespace != c.Namespace || len(c.StoreID) != 64 || !forwardStoreID(c.StoreID) || c.RootKeyRevision != 1 || c.ExchangeKeyRevision == 0 || c.BindingProfile != ForwardBindingProfile || c.IssuedAt == "" || c.ExpiresAt == "" || !validSigningDeadline(c.IssuedAt) || !validSigningDeadline(c.ExpiresAt) {
		return nil, referenceInputError("invalid peer certificate fields")
	}
	issued, _ := time.Parse(time.RFC3339Nano, c.IssuedAt)
	expires, _ := time.Parse(time.RFC3339Nano, c.ExpiresAt)
	if !expires.After(issued) || expires.Sub(issued) > 366*24*time.Hour {
		return nil, referenceInputError("peer certificate validity exceeds bounds")
	}
	// Reject low-order X25519 points. This fixed validation scalar is not an
	// identity key and grants no authority; actual private keys stay external.
	var scalar [32]byte
	scalar[0] = 1
	private, _ := ecdh.X25519().NewPrivateKey(scalar[:])
	public, err := ecdh.X25519().NewPublicKey(c.ExchangePublicKey[:])
	if err != nil {
		return nil, referenceInputError("invalid exchange public key")
	}
	if _, err = private.ECDH(public); err != nil {
		return nil, referenceInputError("invalid low-order exchange public key")
	}
	return encodeSigningFields(PeerCertificateSigningPurpose, []byte(c.Namespace), []byte(c.StoreID), signingCounter(c.RootKeyRevision), c.RootPublicKey[:], c.ExchangePublicKey[:], signingCounter(c.ExchangeKeyRevision), []byte(c.BindingProfile), []byte(c.IssuedAt), []byte(c.ExpiresAt))
}
func VerifyPeerCertificate(c SignedPeerCertificate, now time.Time) error {
	raw, err := c.Certificate.SigningBytes()
	if err != nil {
		return err
	}
	issued, _ := time.Parse(time.RFC3339Nano, c.Certificate.IssuedAt)
	expires, _ := time.Parse(time.RFC3339Nano, c.Certificate.ExpiresAt)
	if now.IsZero() || now.Before(issued) || !now.Before(expires) || len(c.Signature) != ed25519.SignatureSize || !ed25519.Verify(c.Certificate.RootPublicKey[:], raw, c.Signature) {
		return NewError(CodeUnauthenticated, "Peer certificate invalid or outside validity")
	}
	return nil
}

// Digest commits canonical signed fields and original signature without
// treating arbitrary JSON reserialization as an authenticated wire message.
func (c SignedPeerCertificate) Digest() ([32]byte, error) {
	raw, err := c.Certificate.SigningBytes()
	if err != nil {
		return [32]byte{}, err
	}
	if len(c.Signature) != ed25519.SignatureSize || !ed25519.Verify(c.Certificate.RootPublicKey[:], raw, c.Signature) {
		return [32]byte{}, NewError(CodeUnauthenticated, "Peer certificate signature invalid")
	}
	signed, err := encodeSigningFields("pagnet.fabric.peer-binding.v1", raw, c.Signature)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(signed), nil
}
