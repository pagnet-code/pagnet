//go:build unix

package daemon

import (
	"bytes"
	"encoding/base64"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/internal/crypto"
	"github.com/pagnet-code/pagnet/transport"
)

func TestOwnerTemplateBrowserWriteReadAndCommittedEpoch(t *testing.T) {
	d, prepared, ready := preparedOwnerDaemon(t)
	c := prepared.Context
	browser, err := crypto.NewHostIdentity()
	if err != nil {
		t.Fatal(err)
	}
	session := domain.NewID().String()
	start := transport.CryptoSessionStartPayload{ProtectedContext: &c, TenantID: c.TenantID, UserID: c.OwnerUserID, SessionID: session, EpochID: ready.EpochID, BrowserPub: base64.StdEncoding.EncodeToString(browser.X25519Pub)}
	missing := start
	missing.EpochID = ""
	if _, err = d.doCryptoSessionStart(missing); err == nil {
		t.Fatal("session admitted without committed epoch")
	}
	unknown := start
	unknown.EpochID = "unknown"
	if _, err = d.doCryptoSessionStart(unknown); err == nil {
		t.Fatal("session admitted unknown committed epoch")
	}
	if _, err = d.doCryptoSessionStart(start); err != nil {
		t.Fatal(err)
	}
	ring, err := crypto.LoadContextKeyring(d.StateDir, c)
	if err != nil {
		t.Fatal(err)
	}
	epoch, _ := ring.EpochByID(ready.EpochID)
	key, _ := epoch.KeyArray()
	object := domain.NewID().String()
	aad := e2ee.AAD{ProtocolVersion: transport.ProtocolVersion, TenantID: c.TenantID, ProtectedContext: &c, ObjectType: e2ee.ObjectTypeAgentTemplate, ObjectID: object, Sender: c.OwnerUserID, Recipient: c.OwnerUserID, CreatedAt: time.Now().UTC().Format(time.RFC3339), KeyEpochID: ready.EpochID}
	envelope, err := e2ee.Encrypt([]byte("private reusable template"), key, aad)
	if err != nil {
		t.Fatal(err)
	}
	wrapped, _ := base64.StdEncoding.DecodeString(envelope.WrappedContentKey)
	cek, err := e2ee.UnwrapCEK(key, wrapped)
	if err != nil {
		t.Fatal(err)
	}
	host, err := d.cryptoManager().hostIdentity()
	if err != nil {
		t.Fatal(err)
	}
	enc, ct, err := e2ee.HPKEWrap(host.X25519Pub, []byte(e2ee.HPKEInfoCekWrap), e2ee.BrowserSessionAAD(c.ID, session, object), cek[:])
	if err != nil {
		t.Fatal(err)
	}
	request := transport.CryptoWrapCekPayload{ProtectedContext: &c, TenantID: c.TenantID, SessionID: session, ObjectID: object, ObjectType: e2ee.ObjectTypeAgentTemplate, AAD: aad, WrappedCek: transport.CryptoHPKEWrap{Enc: enc, Ciphertext: ct}}
	// A newer local candidate must not change the session's committed write epoch.
	if _, err = ring.Rotate(time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err = crypto.SaveContextKeyring(d.StateDir, ring); err != nil {
		t.Fatal(err)
	}
	result, err := d.doCryptoWrapCek(request)
	if err != nil {
		t.Fatal(err)
	}
	write := result.(*transport.CryptoWrapCekResult)
	if write.KeyEpochID != ready.EpochID {
		t.Fatal("local candidate substituted for committed epoch")
	}
	envelope.WrappedContentKey = write.WrappedContentKey
	read, err := d.doCryptoUnwrapCek(transport.CryptoUnwrapCekPayload{ProtectedContext: &c, TenantID: c.TenantID, SessionID: session, Objects: []transport.CryptoUnwrapCekObject{{ObjectID: object, Envelope: envelope, AAD: &aad}}})
	if err != nil {
		t.Fatal(err)
	}
	item := read.(*transport.CryptoUnwrapCekResult).Results[0]
	if item.WrappedCek == nil {
		t.Fatal("owner template read denied", item.Error)
	}
	opened, err := e2ee.HPKEUnwrap(browser.X25519Priv, item.WrappedCek.Enc, []byte(e2ee.HPKEInfoOwnerCEK), e2ee.OwnerBrowserSessionAAD(c, session, object), item.WrappedCek.Ciphertext)
	if err != nil || !bytes.Equal(opened, cek[:]) {
		t.Fatal("owner write/read changed content key", err)
	}
	for _, variant := range []string{"network", "owner", "context", "epoch", "object", "type", "session", "hpke"} {
		t.Run(variant, func(t *testing.T) {
			bad := request
			switch variant {
			case "network":
				bad.NetworkID = domain.NewID().String()
			case "owner":
				bad.AAD.Sender = domain.NewID().String()
			case "context":
				changed := c
				changed.ID = domain.NewID().String()
				bad.ProtectedContext = &changed
			case "epoch":
				bad.AAD.KeyEpochID = "uncommitted"
			case "object":
				bad.ObjectID = domain.NewID().String()
			case "type":
				bad.ObjectType = e2ee.ObjectTypeRuntimeInteraction
			case "session":
				bad.SessionID = domain.NewID().String()
			case "hpke":
				bad.WrappedCek.Ciphertext = []byte("invalid")
			}
			if _, err := d.doCryptoWrapCek(bad); err == nil {
				t.Fatal("foreign or malformed owner write accepted")
			}
		})
	}
	manager := d.ownerCrypto()
	manager.mu.Lock()
	oldSession := manager.sessions[session]
	expired := oldSession
	expired.ExpiresAt = time.Now().Add(-time.Second)
	manager.sessions[session] = expired
	manager.mu.Unlock()
	if _, err = d.doCryptoWrapCek(request); err == nil {
		t.Fatal("expired browser session wrote template")
	}
	manager.mu.Lock()
	manager.sessions[session] = oldSession
	manager.mu.Unlock()
	if err = ring.Revoke(ready.EpochID); err != nil {
		t.Fatal(err)
	}
	if err = crypto.SaveContextKeyring(d.StateDir, ring); err != nil {
		t.Fatal(err)
	}
	if _, err = d.doCryptoWrapCek(request); err == nil {
		t.Fatal("revoked committed epoch accepted")
	}
}
