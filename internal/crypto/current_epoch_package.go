package crypto

import (
	"bytes"
	"crypto/ecdh"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode/utf8"
)

// CurrentEpochKeyPackageVersion identifies the grant-scoped, current-only wire
// format. It is deliberately separate from the historical NKA key package.
const CurrentEpochKeyPackageVersion = 1

// CurrentEpochPackageContext must come from independently verified authority
// on both sides of the exchange. Generations must be positive. RecipientID is
// the recipient host identity; RecipientPublicKey is its X25519 public key.
// The caller must hold network authority stable while building the package.
type CurrentEpochPackageContext struct {
	OwnerTenantID               string `json:"owner_tenant_id"`
	NetworkID                   string `json:"network_id"`
	GrantID                     string `json:"grant_id"`
	GrantGeneration             uint64 `json:"grant_generation,string"`
	NetworkTransitionGeneration uint64 `json:"network_transition_generation,string"`
	RecipientID                 string `json:"recipient_id"`
	RecipientPublicKey          []byte `json:"recipient_public_key"`
	EpochID                     string `json:"epoch_id"`
}

// CurrentEpochKeyPackage contains only an HPKE ciphertext and its version.
// Context is never accepted from the package: the opener supplies it separately.
// This primitive neither installs keys nor activates a grant or membership.
type CurrentEpochKeyPackage struct {
	Version    int    `json:"version"`
	Enc        []byte `json:"enc"`
	Ciphertext []byte `json:"ciphertext"`
}

func currentEpochPackageInfo(c CurrentEpochPackageContext) ([]byte, error) {
	for _, id := range []string{c.OwnerTenantID, c.NetworkID, c.GrantID, c.RecipientID, c.EpochID} {
		if id == "" || !utf8.ValidString(id) || strings.TrimSpace(id) != id {
			return nil, errors.New("crypto: current epoch package context incomplete")
		}
	}
	if c.GrantGeneration == 0 || c.NetworkTransitionGeneration == 0 || len(c.RecipientPublicKey) != 32 {
		return nil, errors.New("crypto: current epoch package context invalid")
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	return append([]byte("pagnet/e2ee/current-epoch-keypackage/v1/"), raw...), nil
}

// BuildCurrentEpochKeyPackage exports exactly the requested current epoch,
// without modifying the authority's historical keyring. The authority's tenant
// and network must agree with the independently admitted grant context.
func (n *NKA) BuildCurrentEpochKeyPackage(c CurrentEpochPackageContext) (*CurrentEpochKeyPackage, error) {
	info, err := currentEpochPackageInfo(c)
	if err != nil {
		return nil, err
	}
	if n == nil || n.keyring == nil || n.TenantID != c.OwnerTenantID || n.NetworkID != c.NetworkID || n.keyring.NetworkID != c.NetworkID {
		return nil, errors.New("crypto: current epoch package authority mismatch")
	}
	// Fail closed on ambiguous current authority rather than choosing one of
	// several active epochs by timestamp.
	var current *KeyEpoch
	seen := map[string]bool{}
	for i := range n.keyring.Epochs {
		e := &n.keyring.Epochs[i]
		if e.ID == "" || seen[e.ID] || len(e.Key) != epochKeySize || e.CreatedAt.IsZero() || (e.State != EpochActive && e.State != EpochRotated && e.State != EpochRevoked) {
			return nil, errors.New("crypto: current epoch package authority invalid")
		}
		seen[e.ID] = true
		if e.State == EpochActive {
			if current != nil {
				return nil, errors.New("crypto: current epoch package authority ambiguous")
			}
			current = e
		}
	}
	if current == nil || current.ID != c.EpochID || len(current.Key) != epochKeySize {
		return nil, errors.New("crypto: requested current epoch unavailable")
	}
	raw, err := json.Marshal(&Keyring{NetworkID: c.NetworkID, Epochs: []KeyEpoch{*current}})
	if err != nil {
		return nil, err
	}
	enc, ct, err := WrapKey(c.RecipientPublicKey, info, nil, raw)
	if err != nil {
		return nil, err
	}
	return &CurrentEpochKeyPackage{Version: CurrentEpochKeyPackageVersion, Enc: enc, Ciphertext: ct}, nil
}

// OpenCurrentEpochKeyPackage authenticates a package against independently
// expected context and returns a detached single-epoch keyring. The caller is
// responsible for rechecking current authority before any later installation.
func OpenCurrentEpochKeyPackage(pkg *CurrentEpochKeyPackage, recipientPriv []byte, expected CurrentEpochPackageContext) (*Keyring, error) {
	info, err := currentEpochPackageInfo(expected)
	if err != nil {
		return nil, err
	}
	if pkg == nil || pkg.Version != CurrentEpochKeyPackageVersion || len(pkg.Enc) != 32 {
		return nil, errors.New("crypto: current epoch package format invalid")
	}
	private, err := ecdh.X25519().NewPrivateKey(recipientPriv)
	if err != nil || !bytes.Equal(private.PublicKey().Bytes(), expected.RecipientPublicKey) {
		return nil, errors.New("crypto: current epoch package recipient mismatch")
	}
	raw, err := OpenKey(recipientPriv, pkg.Enc, info, nil, pkg.Ciphertext)
	if err != nil {
		return nil, errors.New("crypto: current epoch package authentication failed")
	}
	var ring Keyring
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&ring) != nil || decoder.Decode(new(any)) != io.EOF || ring.NetworkID != expected.NetworkID || len(ring.Epochs) != 1 {
		return nil, errors.New("crypto: current epoch package payload invalid")
	}
	epoch := ring.Epochs[0]
	if epoch.ID != expected.EpochID || epoch.State != EpochActive || len(epoch.Key) != epochKeySize || epoch.CreatedAt.IsZero() {
		return nil, errors.New("crypto: current epoch package epoch invalid")
	}
	return &ring, nil
}
