package daemon

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/internal/crypto"
	"github.com/pagnet-code/pagnet/transport"
)

func TestEpochPossessionReconnectAndMissingKeys(t *testing.T) {
	d := newCryptoDaemon(t)
	if err := d.state.KVSet("host_id", "authority"); err != nil {
		t.Fatal(err)
	}
	result, err := d.doCryptoActivate(transport.CryptoActivatePayload{CommandID: "activate", TenantID: "tenant", NetworkID: "11111111-1111-4111-8111-111111111111", PossessionProtocol: transport.NetworkEpochPossessionProtocol})
	if err != nil {
		t.Fatal(err)
	}
	m := result.(*transport.CryptoActivateResult).Manifest
	authorityPub, _ := base64.StdEncoding.DecodeString(m.AuthorityEd25519)
	signature, _ := base64.StdEncoding.DecodeString(m.Signature)
	if !ed25519.Verify(authorityPub, m.SignatureBytes(), signature) {
		t.Fatal("authority signature invalid")
	}
	keyPath, err := crypto.KeyringPath(d.StateDir, "11111111-1111-4111-8111-111111111111")
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	attestation := transport.CryptoAttestEpochPayload{Protocol: transport.NetworkEpochPossessionProtocol, CommandID: "attest", TenantID: "tenant", NetworkID: "11111111-1111-4111-8111-111111111111", EpochID: m.EpochID, AuthorityHostID: m.AuthorityHostID, AuthorityX25519: m.AuthorityX25519, AuthorityEd25519: m.AuthorityEd25519}
	a, err := d.doCryptoAttestEpoch(attestation)
	if err != nil {
		t.Fatal(err)
	}
	am := a.(*transport.CryptoAttestEpochResult).Manifest
	if am != *m {
		t.Fatal("attestation changed immutable manifest")
	}
	after, _ := os.ReadFile(keyPath)
	if string(before) != string(after) {
		t.Fatal("attestation mutated keyring")
	}
	verifier, _ := base64.StdEncoding.DecodeString(m.VerifierPub)
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	b := transport.NetworkEpochProofBinding{Protocol: transport.NetworkEpochPossessionProtocol, TenantID: "tenant", NetworkID: "11111111-1111-4111-8111-111111111111", EpochID: m.EpochID, HolderID: "holder", HolderHostID: m.AuthorityHostID, HolderX25519: m.AuthorityX25519, HolderEd25519: m.AuthorityEd25519, RunnerID: "runner", ConnectedAt: time.Now().UTC().Format(time.RFC3339Nano), CommandID: "prove", Nonce: base64.StdEncoding.EncodeToString(nonce), ExpiresAt: time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano)}
	p, err := d.doCryptoProveEpoch(transport.CryptoProveEpochPayload{Binding: b})
	if err != nil {
		t.Fatal(err)
	}
	proof, _ := base64.StdEncoding.DecodeString(p.(*transport.CryptoProveEpochResult).Signature)
	if !ed25519.Verify(verifier, b.SignatureBytes(), proof) {
		t.Fatal("possession proof invalid")
	}
	// Each public scope/connection field is cryptographically bound, not merely
	// checked by routing. A captured proof cannot attest another connection.
	raw, _ := json.Marshal(b)
	var fields map[string]any
	_ = json.Unmarshal(raw, &fields)
	for field := range fields {
		t.Run(field, func(t *testing.T) {
			var changed map[string]any
			_ = json.Unmarshal(raw, &changed)
			changed[field] = "different"
			data, _ := json.Marshal(changed)
			var other transport.NetworkEpochProofBinding
			_ = json.Unmarshal(data, &other)
			if ed25519.Verify(verifier, other.SignatureBytes(), proof) {
				t.Fatal("replay accepted")
			}
		})
	}
	// Restart the crypto manager: proof requires disk keys, not an in-memory
	// enrollment challenge or a second online key holder.
	d.cryptoMu.Lock()
	d.cryptoMgr = nil
	d.cryptoMu.Unlock()
	b.RunnerID = "new-runner"
	b.CommandID = "new-command"
	b.ConnectedAt = time.Now().UTC().Format(time.RFC3339Nano)
	p, err = d.doCryptoProveEpoch(transport.CryptoProveEpochPayload{Binding: b})
	if err != nil {
		t.Fatal(err)
	}
	newProof, _ := base64.StdEncoding.DecodeString(p.(*transport.CryptoProveEpochResult).Signature)
	if !ed25519.Verify(verifier, b.SignatureBytes(), newProof) {
		t.Fatal("restart proof invalid")
	}
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	if _, err := d.doCryptoProveEpoch(transport.CryptoProveEpochPayload{Binding: b}); err == nil {
		t.Fatal("same identity without keyring proved possession")
	}
	if _, err := d.doCryptoAttestEpoch(attestation); err == nil {
		t.Fatal("attestation silently generated missing keys")
	}
	if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
		t.Fatal("missing keyring recreated")
	}
	if err := os.Remove(crypto.HostPath(d.StateDir)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.doCryptoAttestEpoch(attestation); err == nil {
		t.Fatal("missing identity accepted")
	}
	if _, err := os.Stat(crypto.HostPath(d.StateDir)); !os.IsNotExist(err) {
		t.Fatal("attestation recreated missing identity")
	}
}

func TestEpochPossessionRejectInvalidCommands(t *testing.T) {
	d := newCryptoDaemon(t)
	_ = d.state.KVSet("host_id", "host")
	res, err := d.doCryptoActivate(transport.CryptoActivatePayload{TenantID: "tenant", NetworkID: "22222222-2222-4222-8222-222222222222", PossessionProtocol: transport.NetworkEpochPossessionProtocol})
	if err != nil {
		t.Fatal(err)
	}
	m := res.(*transport.CryptoActivateResult).Manifest
	nonce := base64.StdEncoding.EncodeToString(make([]byte, 32))
	b := transport.NetworkEpochProofBinding{Protocol: transport.NetworkEpochPossessionProtocol, TenantID: "tenant", NetworkID: "22222222-2222-4222-8222-222222222222", EpochID: m.EpochID, HolderID: "holder", HolderHostID: "host", HolderX25519: m.AuthorityX25519, HolderEd25519: m.AuthorityEd25519, RunnerID: "runner", ConnectedAt: time.Now().UTC().Format(time.RFC3339Nano), CommandID: "command", Nonce: nonce, ExpiresAt: time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano)}
	cases := map[string]func(*transport.NetworkEpochProofBinding){"expired": func(b *transport.NetworkEpochProofBinding) {
		b.ExpiresAt = time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano)
	}, "unbounded": func(b *transport.NetworkEpochProofBinding) {
		b.ExpiresAt = time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
	}, "wrong_host": func(b *transport.NetworkEpochProofBinding) { b.HolderHostID = "other" }, "wrong_key": func(b *transport.NetworkEpochProofBinding) { b.HolderEd25519 = "other" }, "wrong_epoch": func(b *transport.NetworkEpochProofBinding) { b.EpochID = "missing" }, "nonce": func(b *transport.NetworkEpochProofBinding) { b.Nonce = "short" }, "protocol": func(b *transport.NetworkEpochProofBinding) { b.Protocol = "legacy" }, "generation": func(b *transport.NetworkEpochProofBinding) { b.ConnectedAt = "invalid" }}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			changed := b
			mutate(&changed)
			if _, err := d.doCryptoProveEpoch(transport.CryptoProveEpochPayload{Binding: changed}); err == nil {
				t.Fatal("invalid command accepted")
			}
		})
	}
}
