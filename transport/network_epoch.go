package transport

import (
	"encoding/json"
	"github.com/pagnet-code/pagnet/e2ee"
)

const NetworkEpochPossessionProtocol = "network-epoch-possession-v1"
const MsgCryptoAttestEpoch = "host.crypto_attest_epoch"
const MsgCryptoProveEpoch = "host.crypto_prove_epoch"

// NetworkEpochManifest publishes an epoch-derived verifier, never its secret.
// The authority signs this immutable public binding once per epoch.
type NetworkEpochManifest struct {
	Protocol         string `json:"protocol"`
	TenantID         string `json:"tenantId"`
	NetworkID        string `json:"networkId"`
	EpochID          string `json:"epochId"`
	VerifierPub      string `json:"verifierPub"`
	AuthorityHostID  string `json:"authorityHostId"`
	AuthorityX25519  string `json:"authorityX25519"`
	AuthorityEd25519 string `json:"authorityEd25519"`
	Signature        string `json:"signature,omitempty"`
}

func (m NetworkEpochManifest) SignatureBytes() []byte {
	m.Signature = ""
	b, _ := json.Marshal(m)
	return b
}

// NetworkEpochProofBinding fences proof to one server-issued nonce and one
// exact connection generation. Changing any field invalidates its signature.
type NetworkEpochProofBinding struct {
	Protocol      string `json:"protocol"`
	TenantID      string `json:"tenantId"`
	NetworkID     string `json:"networkId"`
	EpochID       string `json:"epochId"`
	HolderID      string `json:"holderId"`
	HolderHostID  string `json:"holderHostId"`
	HolderX25519  string `json:"holderX25519"`
	HolderEd25519 string `json:"holderEd25519"`
	RunnerID      string `json:"runnerId"`
	ConnectedAt   string `json:"connectedAt"`
	CommandID     string `json:"commandId"`
	Nonce         string `json:"nonce"`
	ExpiresAt     string `json:"expiresAt"`
}

func (b NetworkEpochProofBinding) SignatureBytes() []byte { p, _ := json.Marshal(b); return p }

// NetworkEpochAttestationSample is selected from authenticated stored history
// by the server. The host authenticates it without returning its plaintext.
type NetworkEpochAttestationSample struct {
	Envelope e2ee.EncryptedPayloadV1 `json:"envelope"`
	AAD      e2ee.AAD                `json:"aad"`
}

const MaxNetworkEpochAttestationSampleBytes = 96 * 1024

type CryptoAttestEpochPayload struct {
	Sample           *NetworkEpochAttestationSample `json:"sample,omitempty"`
	CommandID        string                         `json:"commandId"`
	Protocol         string                         `json:"protocol"`
	TenantID         string                         `json:"tenantId"`
	NetworkID        string                         `json:"networkId"`
	EpochID          string                         `json:"epochId"`
	AuthorityHostID  string                         `json:"authorityHostId"`
	AuthorityX25519  string                         `json:"authorityX25519"`
	AuthorityEd25519 string                         `json:"authorityEd25519"`
}
type CryptoAttestEpochResult struct {
	Manifest       NetworkEpochManifest `json:"manifest"`
	SampleVerified bool                 `json:"sampleVerified,omitempty"`
}
type CryptoProveEpochPayload struct {
	Binding NetworkEpochProofBinding `json:"binding"`
}
type CryptoProveEpochResult struct {
	Signature string `json:"signature"`
}
