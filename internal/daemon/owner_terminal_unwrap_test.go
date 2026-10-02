//go:build unix

package daemon

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/internal/crypto"
	"github.com/pagnet-code/pagnet/transport"
)

func TestOwnerTerminalUnwrapAuthenticatesInstanceContextAndCiphertext(t *testing.T) {
	d, p, ready := preparedOwnerDaemon(t)
	ring, err := crypto.LoadContextKeyring(d.StateDir, p.Context)
	if err != nil {
		t.Fatal(err)
	}
	epoch, _ := ring.ActiveEpoch()
	key, _ := epoch.KeyArray()
	object, err := e2ee.TerminalKeyObjectID(p.InstanceID, domain.NewID().String(), "original-generation", domain.NewID().String())
	if err != nil {
		t.Fatal(err)
	}
	aad := e2ee.AAD{ProtocolVersion: transport.ProtocolVersion, TenantID: p.Context.TenantID, ProtectedContext: &p.Context, ObjectType: e2ee.ObjectTypeRuntimeTerminalSession, ObjectID: object, Sender: p.InstanceID, Recipient: p.Context.OwnerUserID, KeyEpochID: epoch.ID, CreatedAt: time.Now().UTC().Format(time.RFC3339)}
	envelope, err := e2ee.Encrypt([]byte("original private terminal directional keys"), key, aad)
	if err != nil {
		t.Fatal(err)
	}
	browser, err := crypto.NewHostIdentity()
	if err != nil {
		t.Fatal(err)
	}
	session := domain.NewID().String()
	if _, err = d.ownerSessionStart(transport.CryptoSessionStartPayload{EpochID: ready.EpochID, ProtectedContext: &p.Context, TenantID: p.Context.TenantID, UserID: p.Context.OwnerUserID, SessionID: session, BrowserPub: base64.StdEncoding.EncodeToString(browser.X25519Pub)}); err != nil {
		t.Fatal(err)
	}
	unwrap := func(a e2ee.AAD, cipher e2ee.EncryptedPayloadV1) transport.CryptoUnwrapCekResultItem {
		t.Helper()
		result, err := d.ownerUnwrap(transport.CryptoUnwrapCekPayload{ProtectedContext: &p.Context, TenantID: p.Context.TenantID, SessionID: session, Objects: []transport.CryptoUnwrapCekObject{{ObjectID: object, Envelope: cipher, AAD: &a}}})
		if err != nil {
			t.Fatal(err)
		}
		return result.(*transport.CryptoUnwrapCekResult).Results[0]
	}
	item := unwrap(aad, envelope)
	if item.WrappedCek == nil || item.Error != "" {
		t.Fatalf("original terminal denied: %s", item.Error)
	}
	cek, err := e2ee.HPKEUnwrap(browser.X25519Priv, item.WrappedCek.Enc, []byte(e2ee.HPKEInfoOwnerCEK), e2ee.OwnerBrowserSessionAAD(p.Context, session, object), item.WrappedCek.Ciphertext)
	if err != nil || len(cek) != 32 {
		t.Fatal("terminal browser HPKE failed", err)
	}
	clear(cek)
	for _, field := range []string{"instance", "context", "recipient", "type", "object", "ciphertext"} {
		t.Run(field, func(t *testing.T) {
			changed, cipher := aad, envelope
			switch field {
			case "instance":
				changed.Sender = domain.NewID().String()
			case "context":
				context := p.Context
				context.ID = domain.NewID().String()
				changed.ProtectedContext = &context
			case "recipient":
				changed.Recipient = domain.NewID().String()
			case "type":
				changed.ObjectType = e2ee.ObjectTypeAgentDefinition
			case "object":
				changed.ObjectID = domain.NewID().String()
			case "ciphertext":
				cipher.Ciphertext = base64.StdEncoding.EncodeToString([]byte("tampered"))
			}
			got := unwrap(changed, cipher)
			if got.WrappedCek != nil || got.Error == "" {
				t.Fatal("foreign or tampered terminal released CEK")
			}
		})
	}
}
