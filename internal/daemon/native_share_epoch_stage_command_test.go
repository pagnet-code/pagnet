//go:build linux || darwin

package daemon

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
)

func nativeEpochCommandWire(t *testing.T, f *nativeEpochStoreFixture) (transport.NativeShareEpochStageCommand, []byte) {
	t.Helper()
	c := transport.NativeShareEpochStageCommand{Version: 1, BindingID: f.auth.Prepared.Prepare.Binding.BindingID, Expected: f.auth.Expected, SourceSigningPublicKey: f.auth.TrustedSource, Package: f.raw}
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	return c, raw
}

func TestNativeShareEpochStageCommandSignsOnlySuccessfulStage(t *testing.T) {
	f := newNativeEpochStoreFixture(t)
	c, wire := nativeEpochCommandWire(t, f)
	calls := 0
	check := f.auth.Reauthorize
	f.auth.Reauthorize = func(a NativeShareEpochStageAuthorization) error { calls++; return check(a) }
	result, err := f.store.StageCommand(c.Expected.CommandID, wire, f.auth)
	if err != nil {
		t.Fatal(err)
	}
	if calls < 2 {
		t.Fatal("independent and store authorization not both checked")
	}
	if err := result.Verify(c.Expected.CommandID, c, f.identity.Ed25519Verifier()); err != nil {
		t.Fatal(err)
	}
	transcript, err := result.SignatureBytes()
	if err != nil || !ed25519.Verify(f.identity.Ed25519Verifier(), transcript, result.Signature) {
		t.Fatal("wrong signed result bytes")
	}
	var record nativeShareEpochStageRecord
	raw := nativeEpochRead(t, filepath.Join(f.directory(), "stage.json"))
	if json.Unmarshal(raw, &record) != nil || !reflect.DeepEqual(record.Receipt, result.Receipt) || !bytes.Equal(record.Package, c.Package) {
		t.Fatal("result differs from staged evidence")
	}
	retry, err := f.store.StageCommand(c.Expected.CommandID, wire, f.auth)
	if err != nil || !reflect.DeepEqual(retry, result) {
		t.Fatal("exact retry changed", err)
	}
	denied := f.auth
	denied.Reauthorize = func(NativeShareEpochStageAuthorization) error { return errors.New("revoked") }
	got, err := f.store.StageCommand(c.Expected.CommandID, wire, denied)
	if err == nil || !reflect.DeepEqual(got, transport.NativeShareEpochStageResult{}) {
		t.Fatal("revocation returned signed evidence")
	}
}

func TestNativeShareEpochStageCommandRejectsBeforeStage(t *testing.T) {
	for _, kind := range []string{"command ID", "binding", "expected", "source", "package", "no authority", "denied", "malformed", "stage denial"} {
		t.Run(kind, func(t *testing.T) {
			f := newNativeEpochStoreFixture(t)
			c, _ := nativeEpochCommandWire(t, f)
			id := c.Expected.CommandID
			auth := f.auth
			other := domain.ID("33333333-3333-4333-8333-333333333333")
			switch kind {
			case "command ID":
				id = other
			case "binding":
				c.BindingID = other
			case "expected":
				c.Expected.CommandConnectionID = "replayed"
			case "source":
				c.SourceSigningPublicKey = make([]byte, 32)
			case "package":
				c.Package = []byte(`{}`)
			case "no authority":
				auth.Reauthorize = nil
			case "denied":
				auth.Reauthorize = func(NativeShareEpochStageAuthorization) error { return errors.New("revoked") }
			case "stage denial":
				calls := 0
				auth.Reauthorize = func(NativeShareEpochStageAuthorization) error {
					calls++
					if calls > 1 {
						return errors.New("revoked during stage")
					}
					return nil
				}
			}
			wire, _ := json.Marshal(c)
			if kind == "malformed" {
				wire = append(wire, []byte(`{}`)...)
			}
			got, err := f.store.StageCommand(id, wire, auth)
			if err == nil || !reflect.DeepEqual(got, transport.NativeShareEpochStageResult{}) {
				t.Fatal("invalid command returned evidence")
			}
			if _, err := os.Stat(filepath.Join(f.directory(), "stage.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("rejected command published stage")
			}
		})
	}
}
