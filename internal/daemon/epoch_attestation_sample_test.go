package daemon

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/internal/crypto"
	"github.com/pagnet-code/pagnet/transport"
)

func TestEpochAttestationAuthenticatesStoredHistory(t *testing.T) {
	d := newCryptoDaemon(t)
	if err := d.state.KVSet("host_id", "host"); err != nil {
		t.Fatal(err)
	}
	const network = "11111111-1111-4111-8111-111111111111"
	raw, err := d.doCryptoActivate(transport.CryptoActivatePayload{TenantID: "tenant", NetworkID: network, PossessionProtocol: transport.NetworkEpochPossessionProtocol})
	if err != nil {
		t.Fatal(err)
	}
	manifest := raw.(*transport.CryptoActivateResult).Manifest
	kr, err := crypto.LoadKeyring(d.StateDir, network)
	if err != nil {
		t.Fatal(err)
	}
	epoch, err := kr.ActiveEpoch()
	if err != nil {
		t.Fatal(err)
	}
	key, err := epoch.KeyArray()
	if err != nil {
		t.Fatal(err)
	}
	path, err := crypto.KeyringPath(d.StateDir, network)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	p := transport.CryptoAttestEpochPayload{CommandID: "attest", Protocol: transport.NetworkEpochPossessionProtocol, TenantID: "tenant", NetworkID: network, EpochID: epoch.ID, AuthorityHostID: "host", AuthorityX25519: manifest.AuthorityX25519, AuthorityEd25519: manifest.AuthorityEd25519}
	const secret = "PRIVATE_HISTORY_MUST_NEVER_LEAVE_HOST"
	for _, recipient := range []string{"agent", ""} {
		for _, version := range []int{1, transport.ProtocolVersion} {
			aad := e2ee.AAD{ProtocolVersion: version, TenantID: "tenant", NetworkID: network, KeyEpochID: epoch.ID, ObjectType: "message", ObjectID: "object", Sender: "human", Recipient: recipient, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
			envelope, err := e2ee.Encrypt([]byte(secret), key, aad)
			if err != nil {
				t.Fatal(err)
			}
			p.Sample = &transport.NetworkEpochAttestationSample{Envelope: envelope, AAD: aad}
			result, err := d.doCryptoAttestEpoch(p)
			if err != nil {
				t.Fatal(err)
			}
			checked := result.(*transport.CryptoAttestEpochResult)
			if !checked.SampleVerified {
				t.Error("native did not authenticate stored history")
			}
			if checked.Manifest != *manifest {
				t.Fatal("history verification changed immutable manifest")
			}
			encoded, _ := json.Marshal(result)
			if bytes.Contains(encoded, []byte(secret)) {
				t.Fatal("plaintext returned to server")
			}
		}
	}
	originalSample := *p.Sample
	mutations := map[string]func(*transport.NetworkEpochAttestationSample){
		"tenant":          func(s *transport.NetworkEpochAttestationSample) { s.AAD.TenantID = "other" },
		"network":         func(s *transport.NetworkEpochAttestationSample) { s.AAD.NetworkID = "other" },
		"epoch":           func(s *transport.NetworkEpochAttestationSample) { s.AAD.KeyEpochID = "other" },
		"envelope_epoch":  func(s *transport.NetworkEpochAttestationSample) { s.Envelope.KeyEpochID = "other" },
		"object_type":     func(s *transport.NetworkEpochAttestationSample) { s.AAD.ObjectType = "task" },
		"object":          func(s *transport.NetworkEpochAttestationSample) { s.AAD.ObjectID = "changed" },
		"sender":          func(s *transport.NetworkEpochAttestationSample) { s.AAD.Sender = "changed" },
		"recipient":       func(s *transport.NetworkEpochAttestationSample) { s.AAD.Recipient = "changed" },
		"timestamp":       func(s *transport.NetworkEpochAttestationSample) { s.AAD.CreatedAt = "invalid" },
		"future_protocol": func(s *transport.NetworkEpochAttestationSample) { s.AAD.ProtocolVersion = 999 },
		"ciphertext":      func(s *transport.NetworkEpochAttestationSample) { s.Envelope.Ciphertext = "AAAA" },
		"oversized_metadata": func(s *transport.NetworkEpochAttestationSample) {
			s.AAD.Sender = strings.Repeat("x", transport.MaxNetworkEpochAttestationSampleBytes)
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			s := originalSample
			mutate(&s)
			request := p
			request.Sample = &s
			if result, err := d.doCryptoAttestEpoch(request); err == nil || result != nil {
				t.Fatal("invalid history authorized an epoch verifier")
			}
		})
	}
	oversized := originalSample
	oversized.Envelope, err = e2ee.Encrypt(make([]byte, 64*1024+1), key, oversized.AAD)
	if err != nil {
		t.Fatal(err)
	}
	request := p
	request.Sample = &oversized
	if _, err := d.doCryptoAttestEpoch(request); err == nil {
		t.Fatal("oversized content accepted")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("attestation mutated original epoch")
	}
	// Same public identity and epoch label, but a different local key: a
	// server-selected real historical sample rejects trusting this wrong ring.
	kr.Epochs[0].Key = bytes.Repeat([]byte{9}, 32)
	if err := crypto.SaveKeyring(d.StateDir, kr); err != nil {
		t.Fatal(err)
	}
	p.Sample = &originalSample
	if result, err := d.doCryptoAttestEpoch(p); err == nil || result != nil {
		t.Fatal("different keyring attested original history")
	}
	wrongBefore, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.doCryptoAttestEpoch(p); err == nil {
		t.Fatal("failed keyring regenerated")
	}
	wrongAfter, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wrongBefore, wrongAfter) {
		t.Fatal("wrong keyring repaired instead of refused")
	}
}
