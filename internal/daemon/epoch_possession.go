package daemon

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/internal/crypto"
	"github.com/pagnet-code/pagnet/transport"
)

func (d *Daemon) epochManifest(tenantID, networkID, epochID string) (*transport.NetworkEpochManifest, error) {
	if tenantID == "" || networkID == "" || epochID == "" || d.stateID() == "" {
		return nil, errors.New("crypto: incomplete epoch manifest scope")
	}
	kr, err := crypto.LoadKeyring(d.StateDir, networkID)
	if err != nil {
		return nil, err
	}
	identity, err := crypto.LoadHostIdentity(d.StateDir)
	if err != nil {
		return nil, err
	}
	return d.epochManifestFromKeyring(tenantID, networkID, epochID, kr, identity)
}

func (d *Daemon) epochManifestFromKeyring(tenantID, networkID, epochID string, kr *crypto.Keyring, identity *crypto.HostIdentity) (*transport.NetworkEpochManifest, error) {
	if tenantID == "" || networkID == "" || epochID == "" || d.stateID() == "" || kr == nil || kr.NetworkID != networkID {
		return nil, errors.New("crypto: incomplete epoch manifest scope")
	}
	signer, err := crypto.EpochPossessionSigner(kr, epochID)
	if err != nil {
		return nil, err
	}
	defer clear(signer)
	m := &transport.NetworkEpochManifest{Protocol: transport.NetworkEpochPossessionProtocol, TenantID: tenantID, NetworkID: networkID, EpochID: epochID, VerifierPub: base64.StdEncoding.EncodeToString(signer.Public().(ed25519.PublicKey)), AuthorityHostID: d.stateID(), AuthorityX25519: base64.StdEncoding.EncodeToString(identity.X25519Pub), AuthorityEd25519: base64.StdEncoding.EncodeToString(identity.Ed25519Pub)}
	m.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(identity.Ed25519Signer(), m.SignatureBytes()))
	return m, nil
}

// Explicit attestation reads an existing keyring only. Missing local keys
// are an error; attestation must never activate, rotate or repair a keyring.
func (d *Daemon) doCryptoAttestEpoch(p transport.CryptoAttestEpochPayload) (any, error) {
	if p.Protocol != transport.NetworkEpochPossessionProtocol || p.CommandID == "" {
		return nil, errors.New("crypto: unsupported epoch attestation")
	}
	identity, err := crypto.LoadHostIdentity(d.StateDir)
	if err != nil {
		return nil, err
	}
	if p.AuthorityHostID != d.stateID() || p.AuthorityX25519 != base64.StdEncoding.EncodeToString(identity.X25519Pub) || p.AuthorityEd25519 != base64.StdEncoding.EncodeToString(identity.Ed25519Pub) {
		return nil, errors.New("crypto: authority identity mismatch")
	}
	kr, err := crypto.LoadKeyring(d.StateDir, p.NetworkID)
	if err != nil {
		return nil, err
	}
	if p.Sample != nil {
		if err := verifyEpochAttestationSample(kr, p); err != nil {
			return nil, err
		}
	}
	m, err := d.epochManifestFromKeyring(p.TenantID, p.NetworkID, p.EpochID, kr, identity)
	if err != nil {
		return nil, err
	}
	return &transport.CryptoAttestEpochResult{Manifest: *m, SampleVerified: p.Sample != nil}, nil
}

func (d *Daemon) doCryptoProveEpoch(p transport.CryptoProveEpochPayload) (any, error) {
	b := p.Binding
	if b.Protocol != transport.NetworkEpochPossessionProtocol || b.TenantID == "" || b.NetworkID == "" || b.EpochID == "" || b.HolderID == "" || b.RunnerID == "" || b.CommandID == "" || b.HolderHostID != d.stateID() {
		return nil, errors.New("crypto: invalid epoch proof binding")
	}
	nonce, err := base64.StdEncoding.DecodeString(b.Nonce)
	if err != nil || len(nonce) != 32 {
		return nil, errors.New("crypto: invalid epoch proof nonce")
	}
	expiry, err := time.Parse(time.RFC3339Nano, b.ExpiresAt)
	if err != nil || expiry.UTC().Format(time.RFC3339Nano) != b.ExpiresAt || !expiry.After(time.Now()) || expiry.After(time.Now().Add(5*time.Minute)) {
		return nil, errors.New("crypto: expired or invalid epoch proof")
	}
	connected, err := time.Parse(time.RFC3339Nano, b.ConnectedAt)
	if err != nil || connected.UTC().Format(time.RFC3339Nano) != b.ConnectedAt || connected.After(time.Now().Add(time.Minute)) || !connected.Before(expiry) {
		return nil, errors.New("crypto: invalid proof connection generation")
	}
	identity, err := crypto.LoadHostIdentity(d.StateDir)
	if err != nil {
		return nil, err
	}
	if b.HolderX25519 != base64.StdEncoding.EncodeToString(identity.X25519Pub) || b.HolderEd25519 != base64.StdEncoding.EncodeToString(identity.Ed25519Pub) {
		return nil, errors.New("crypto: proof holder identity mismatch")
	}
	kr, err := crypto.LoadKeyring(d.StateDir, b.NetworkID)
	if err != nil {
		return nil, err
	}
	signer, err := crypto.EpochPossessionSigner(kr, b.EpochID)
	if err != nil {
		return nil, err
	}
	defer clear(signer)
	return &transport.CryptoProveEpochResult{Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(signer, b.SignatureBytes()))}, nil
}

func verifyEpochAttestationSample(kr *crypto.Keyring, p transport.CryptoAttestEpochPayload) error {
	fail := errors.New("crypto: existing epoch could not authenticate stored history")
	sample := p.Sample
	if sample == nil || kr == nil || kr.NetworkID != p.NetworkID {
		return fail
	}
	encoded, err := json.Marshal(sample)
	if err != nil || len(encoded) > transport.MaxNetworkEpochAttestationSampleBytes {
		return fail
	}
	aad := sample.AAD
	// Genuine protocol-1 history remains readable; this never admits old new
	// writes. Authentication uses the exact persisted AAD without reconstruction.
	if (aad.ProtocolVersion != 1 && aad.ProtocolVersion != transport.ProtocolVersion) || aad.ValidateScope() != nil || aad.ProtectedContext != nil || aad.TenantID != p.TenantID || aad.NetworkID != p.NetworkID || aad.KeyEpochID != p.EpochID || aad.ObjectType != "message" || aad.ObjectID == "" || aad.Sender == "" || aad.Recipient == "" {
		return fail
	}
	if _, err := time.Parse(time.RFC3339Nano, aad.CreatedAt); err != nil {
		return fail
	}
	if sample.Envelope.KeyEpochID != p.EpochID || sample.Envelope.Validate() != nil {
		return fail
	}
	if base64.StdEncoding.DecodedLen(len(sample.Envelope.Ciphertext)) > 64*1024+16 {
		return fail
	}
	epoch, ok := kr.EpochByID(p.EpochID)
	if !ok || epoch.State != crypto.EpochActive {
		return fail
	}
	key, err := epoch.KeyArray()
	if err != nil {
		return fail
	}
	defer clear(key[:])
	plaintext, err := e2ee.Decrypt(sample.Envelope, key, aad)
	if err != nil {
		return fail
	}
	clear(plaintext)
	return nil
}
