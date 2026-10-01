package daemon

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"time"

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
	signer, err := crypto.EpochPossessionSigner(kr, epochID)
	if err != nil {
		return nil, err
	}
	defer clear(signer)
	identity, err := crypto.LoadHostIdentity(d.StateDir)
	if err != nil {
		return nil, err
	}
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
	m, err := d.epochManifest(p.TenantID, p.NetworkID, p.EpochID)
	if err != nil {
		return nil, err
	}
	return &transport.CryptoAttestEpochResult{Manifest: *m}, nil
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
