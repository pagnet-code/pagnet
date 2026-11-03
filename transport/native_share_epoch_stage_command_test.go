package transport

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
)

func nativeStageCommandFixture(t *testing.T) (NativeShareEpochStageCommand, NativeShareEpochStageResult, ed25519.PublicKey, time.Time) {
	t.Helper()
	p, source, _, now := nativeShareEpochFixture(t)
	raw, _ := json.Marshal(p)
	receipt, _ := nativeShareStageReceiptFixture(t)
	host := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	receipt.OperationID = p.Metadata.OperationID
	transcript, _ := receipt.CanonicalBytes()
	receipt.Signature = ed25519.Sign(host, transcript)
	c := NativeShareEpochStageCommand{Version: 1, BindingID: receipt.BindingID, Expected: p.Metadata, SourceSigningPublicKey: source, Package: raw}
	digest, err := c.Digest()
	if err != nil {
		t.Fatal(err)
	}
	r := NativeShareEpochStageResult{Version: 1, CommandID: p.Metadata.CommandID, CommandDigest: digest, Receipt: receipt}
	transcript, err = r.SignatureBytes()
	if err != nil {
		t.Fatal(err)
	}
	r.Signature = ed25519.Sign(host, transcript)
	return c, r, host.Public().(ed25519.PublicKey), now
}

func TestNativeShareEpochStageCommandResultExactTranscripts(t *testing.T) {
	c, r, host, now := nativeStageCommandFixture(t)
	raw, _ := json.Marshal(c)
	decoded, err := DecodeNativeShareEpochStageCommand(raw, c.Expected.CommandID, c.BindingID, c.Expected, c.SourceSigningPublicKey, now)
	if err != nil || !reflect.DeepEqual(c, decoded) {
		t.Fatal("command round trip", err)
	}
	expected := `pagnet/native-share-epoch/stage-command/v1/` + string(raw)
	sum := sha256.Sum256([]byte(expected))
	digest, _ := c.Digest()
	if digest != hex.EncodeToString(sum[:]) {
		t.Fatal("command digest transcript changed")
	}
	receiptWire, _ := json.Marshal(r.Receipt)
	expected = `pagnet/native-share-epoch/stage-result/v1/{"version":1,"commandId":"` + string(r.CommandID) + `","commandDigest":"` + digest + `","receipt":` + string(receiptWire) + `}`
	transcript, _ := r.SignatureBytes()
	if string(transcript) != expected || !ed25519.Verify(host, []byte(expected), r.Signature) {
		t.Fatal("result signed bytes differ")
	}
	raw, _ = json.Marshal(r)
	result, err := DecodeNativeShareEpochStageResult(raw, c.Expected.CommandID, c, host)
	if err != nil || !reflect.DeepEqual(r, result) {
		t.Fatal("result round trip", err)
	}
}

func TestNativeShareEpochStageCommandResultContextAndTamper(t *testing.T) {
	c, r, host, now := nativeStageCommandFixture(t)
	other := domain.ID("33333333-3333-4333-8333-333333333333")
	if c.Verify(other, c.BindingID, c.Expected, c.SourceSigningPublicKey, now) == nil {
		t.Fatal("wrong enclosing command accepted")
	}
	if c.Verify(c.Expected.CommandID, other, c.Expected, c.SourceSigningPublicKey, now) == nil {
		t.Fatal("wrong binding accepted")
	}
	changedContext := c.Expected
	changedContext.AuthorityConnectionID = "replayed-authority"
	if c.Verify(c.Expected.CommandID, c.BindingID, changedContext, c.SourceSigningPublicKey, now) == nil {
		t.Fatal("replay context accepted")
	}
	wrong := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32)).Public().(ed25519.PublicKey)
	if c.Verify(c.Expected.CommandID, c.BindingID, c.Expected, wrong, now) == nil {
		t.Fatal("wrong source accepted")
	}
	if c.Verify(c.Expected.CommandID, c.BindingID, c.Expected, c.SourceSigningPublicKey, now.Add(time.Hour)) == nil {
		t.Fatal("expired command accepted")
	}
	for name, mutate := range map[string]func(*NativeShareEpochStageCommand){
		"version":        func(c *NativeShareEpochStageCommand) { c.Version++ },
		"binding":        func(c *NativeShareEpochStageCommand) { c.BindingID = other },
		"expected":       func(c *NativeShareEpochStageCommand) { c.Expected.GrantGeneration++ },
		"source":         func(c *NativeShareEpochStageCommand) { c.SourceSigningPublicKey = wrong },
		"original bytes": func(c *NativeShareEpochStageCommand) { c.Package = append(append([]byte(nil), c.Package...), ' ') },
		"package substitution": func(c *NativeShareEpochStageCommand) {
			var p NativeShareEpochPackage
			_ = json.Unmarshal(c.Package, &p)
			p.Wrapped.Ciphertext[0] ^= 1
			c.Package, _ = json.Marshal(p)
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := c
			mutate(&changed)
			if r.Verify(c.Expected.CommandID, changed, host) == nil {
				t.Fatal("result accepted changed command")
			}
			if name != "original bytes" && name != "binding" && changed.Verify(c.Expected.CommandID, c.BindingID, c.Expected, c.SourceSigningPublicKey, now) == nil {
				t.Fatal("tampered command accepted")
			}
		})
	}
	for name, mutate := range map[string]func(*NativeShareEpochStageResult){
		"version":           func(r *NativeShareEpochStageResult) { r.Version++ },
		"command":           func(r *NativeShareEpochStageResult) { r.CommandID = other },
		"digest":            func(r *NativeShareEpochStageResult) { r.CommandDigest = strings.Repeat("cd", 32) },
		"receipt":           func(r *NativeShareEpochStageResult) { r.Receipt.Digest = strings.Repeat("cd", 32) },
		"receipt signature": func(r *NativeShareEpochStageResult) { r.Receipt.Signature = make([]byte, 64) },
		"signature":         func(r *NativeShareEpochStageResult) { r.Signature = make([]byte, 64) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := r
			mutate(&changed)
			if changed.Verify(c.Expected.CommandID, c, host) == nil {
				t.Fatal("tampered result accepted")
			}
		})
	}
	if r.Verify(other, c, host) == nil || r.Verify(c.Expected.CommandID, c, wrong) == nil || r.Verify(c.Expected.CommandID, c, nil) == nil {
		t.Fatal("wrong result context accepted")
	}
}

func TestNativeShareEpochStageCommandResultStrictJSON(t *testing.T) {
	c, r, host, now := nativeStageCommandFixture(t)
	for _, kind := range []string{"command", "result"} {
		t.Run(kind, func(t *testing.T) {
			var wire []byte
			var decode func([]byte) error
			if kind == "command" {
				wire, _ = json.Marshal(c)
				decode = func(raw []byte) error {
					_, err := DecodeNativeShareEpochStageCommand(raw, c.Expected.CommandID, c.BindingID, c.Expected, c.SourceSigningPublicKey, now)
					return err
				}
			} else {
				wire, _ = json.Marshal(r)
				decode = func(raw []byte) error {
					_, err := DecodeNativeShareEpochStageResult(raw, c.Expected.CommandID, c, host)
					return err
				}
			}
			var fields map[string]json.RawMessage
			_ = json.Unmarshal(wire, &fields)
			for name := range fields {
				for _, bad := range []string{"missing", "null", "case", "duplicate", "object", "array", "type"} {
					t.Run(name+"/"+bad, func(t *testing.T) {
						copyFields := map[string]json.RawMessage{}
						for k, v := range fields {
							copyFields[k] = v
						}
						switch bad {
						case "missing":
							delete(copyFields, name)
						case "null":
							copyFields[name] = json.RawMessage(`null`)
						case "case":
							copyFields[strings.ToUpper(name)] = copyFields[name]
							delete(copyFields, name)
						case "object":
							copyFields[name] = json.RawMessage(`{}`)
						case "array":
							copyFields[name] = json.RawMessage(`[]`)
						case "type":
							copyFields[name] = json.RawMessage(`true`)
						}
						raw, _ := json.Marshal(copyFields)
						if bad == "duplicate" {
							raw = append(raw[:len(raw)-1], []byte(`,"`+name+`":`+string(fields[name])+`}`)...)
						}
						if decode(raw) == nil {
							t.Fatal("malformed JSON accepted")
						}
					})
				}
			}
			for name, raw := range map[string][]byte{"empty": nil, "null": []byte(`null`), "trailing": append(append([]byte(nil), wire...), []byte(`{}`)...), "oversize": append(append([]byte(nil), wire...), bytes.Repeat([]byte(" "), 33<<10)...), "unknown": append(append([]byte(nil), wire[:len(wire)-1]...), []byte(`,"unknown":1}`)...), "nested duplicate": bytes.Replace(wire, []byte(`"version":1`), []byte(`"version":1,"version":1`), -1)} {
				t.Run(name, func(t *testing.T) {
					if decode(raw) == nil {
						t.Fatal("malformed JSON accepted")
					}
				})
			}
		})
	}
}
