package daemon

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/internal/crypto"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

func TestNativeTerminalDirectionalCryptoAndRevocation(t *testing.T) {
	d, err := New(Config{StateDir: privateDaemonStateDir(t)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	network := uuid.NewString()
	raw, err := d.doCryptoActivate(transport.CryptoActivatePayload{TenantID: "tenant", NetworkID: network})
	if err != nil {
		t.Fatal(err)
	}
	epochID := raw.(*transport.CryptoActivateResult).EpochID
	d.cryptoManager().SetNetworkCrypto(network, NetworkCryptoState{TenantID: "tenant", Status: "active", EpochID: epochID})
	p := &NativeWorkerProxy{scope: sessionworker.Scope{InstanceID: uuid.NewString()}, bootstrap: sessionworker.Bootstrap{Native: sessionworker.NativeSpec{NetworkID: network, NetworkTenantID: "tenant"}}}
	origin, _ := json.Marshal(transport.NativeObservationOrigin{ID: uuid.NewString()})
	snapshot := sessionworker.NativeSnapshot{Origin: origin, NativeGeneration: "originalGeneration", NativeSessionID: uuid.NewString(), NativeStartIdentity: "originalBirth"}
	w, err := d.newNativeTerminalWindow(nil, p, uuid.NewString(), snapshot, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer w.close()
	ring, err := crypto.LoadKeyring(d.StateDir, network)
	if err != nil {
		t.Fatal(err)
	}
	epoch, _ := ring.EpochByID(epochID)
	key, err := epoch.KeyArray()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key[:])
	bootstrap, err := e2ee.Decrypt(*w.meta.Envelope, key, *w.meta.AAD)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(bootstrap)
	var secret terminalSessionSecret
	if json.Unmarshal(bootstrap, &secret) != nil || secret.NativeStartIdentity != snapshot.NativeStartIdentity || secret.SourceOriginID == "" || secret.RealEpochID != epochID || secret.OutputKey == secret.InputKey {
		t.Fatal("bootstrap lost original source or directional key separation")
	}
	w.active = true
	original := []byte{0, 0xff, 0x1b, '[', '3', '1', 'm', 0xe2, 0x98, 0x83}
	frame, err := w.output(d, original, uint64(len(original)), false)
	if err != nil {
		t.Fatal(err)
	}
	if frame.Data != "" || frame.Envelope == nil || frame.AAD.KeyEpochID != w.meta.SessionKeyID {
		t.Fatal("network plaintext or real epoch frame leak")
	}
	opened, err := e2ee.Decrypt(*frame.Envelope, w.outputKey, *frame.AAD)
	if err != nil || !bytes.Equal(opened, original) {
		t.Fatal("exact native PTY bytes changed", err)
	}
	clear(opened)
	if _, err = e2ee.Decrypt(*frame.Envelope, w.inputKey, *frame.AAD); err == nil {
		t.Fatal("opposite direction opened output")
	}
	for _, mutate := range []func(*e2ee.AAD){func(a *e2ee.AAD) { a.ObjectID += "different-window" }, func(a *e2ee.AAD) { a.NetworkID = uuid.NewString() }, func(a *e2ee.AAD) { a.ObjectType = e2ee.ObjectTypeRuntimeTerminalInput }} {
		bad := *frame.AAD
		mutate(&bad)
		if _, err := e2ee.Decrypt(*frame.Envelope, w.outputKey, bad); err == nil {
			t.Fatal("mutated frame authority opened")
		}
	}
	for _, bad := range []transport.TerminalInputPayload{{InstanceID: w.meta.InstanceID, SessionID: w.meta.SessionID, Data: "plaintext"}, {InstanceID: w.meta.InstanceID, SessionID: w.meta.SessionID, NativeGeneration: w.meta.NativeGeneration, SessionKeyID: w.meta.SessionKeyID, Seq: 1, Envelope: frame.Envelope, AAD: frame.AAD}} {
		if w.input(d, bad) == nil {
			t.Fatal("plaintext or direction-confused input accepted")
		}
	}
	if err := ring.Revoke(epochID); err != nil {
		t.Fatal(err)
	}
	if err := crypto.SaveKeyring(d.StateDir, ring); err != nil {
		t.Fatal(err)
	}
	if _, err := w.output(d, original, uint64(len(original)), false); err == nil {
		t.Fatal("revoked real epoch still emitted ephemeral output")
	}
	w.close()
	if w.inputKey != ([32]byte{}) || w.outputKey != ([32]byte{}) {
		t.Fatal("detach retained directional keys")
	}
}
