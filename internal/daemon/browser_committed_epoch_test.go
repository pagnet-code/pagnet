package daemon

import (
	"bytes"
	"encoding/base64"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/internal/crypto"
	"github.com/pagnet-code/pagnet/transport"
)

func TestBrowserWritesUseCommittedEpochAfterUncommittedRotation(t *testing.T) {
	d := newCryptoDaemon(t)
	const network = "11111111-1111-4111-8111-111111111111"
	activated, err := d.doCryptoActivate(transport.CryptoActivatePayload{TenantID: "tenant", NetworkID: network})
	if err != nil {
		t.Fatal(err)
	}
	committed := activated.(*transport.CryptoActivateResult).EpochID
	rotated, err := d.doCryptoRotate(transport.CryptoRotatePayload{TenantID: "tenant", NetworkID: network})
	if err != nil {
		t.Fatal(err)
	}
	candidate := rotated.(*transport.CryptoRotateResult).EpochID
	if candidate == committed {
		t.Fatal("rotation did not generate a distinct candidate")
	}
	browser, err := crypto.NewHostIdentity()
	if err != nil {
		t.Fatal(err)
	}
	start := transport.CryptoSessionStartPayload{TenantID: "tenant", NetworkID: network, EpochID: committed, SessionID: "session", UserID: "owner", BrowserPub: base64.StdEncoding.EncodeToString(browser.X25519Pub)}
	raw, err := d.doCryptoSessionStart(start)
	if err != nil {
		t.Fatal(err)
	}
	if raw.(*transport.CryptoSessionStartResult).EpochID != committed {
		t.Fatal("browser was offered an uncommitted local rotation candidate")
	}
	host, err := d.cryptoManager().hostIdentity()
	if err != nil {
		t.Fatal(err)
	}
	cek := bytes.Repeat([]byte{7}, e2ee.CEKSize())
	enc, ciphertext, err := e2ee.HPKEWrap(host.X25519Pub, []byte(e2ee.HPKEInfoCekWrap), e2ee.BrowserSessionAAD(network, start.SessionID, "object"), cek)
	if err != nil {
		t.Fatal(err)
	}
	p := transport.CryptoWrapCekPayload{TenantID: "tenant", NetworkID: network, SessionID: start.SessionID, ObjectID: "object", ObjectType: "message", WrappedCek: transport.CryptoHPKEWrap{Enc: enc, Ciphertext: ciphertext}, AAD: e2ee.AAD{ProtocolVersion: transport.ProtocolVersion, TenantID: "tenant", NetworkID: network, KeyEpochID: committed, ObjectID: "object", ObjectType: "message", Sender: "human", CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}}
	wrapped, err := d.doCryptoWrapCek(p)
	if err != nil {
		t.Fatal(err)
	}
	result := wrapped.(*transport.CryptoWrapCekResult)
	if result.KeyEpochID != committed {
		t.Fatal("write used a locally active but uncommitted epoch")
	}
	ring, err := crypto.LoadKeyring(d.StateDir, network)
	if err != nil {
		t.Fatal(err)
	}
	epoch, ok := ring.EpochByID(committed)
	if !ok {
		t.Fatal("original epoch was lost")
	}
	key, err := epoch.KeyArray()
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := base64.StdEncoding.DecodeString(result.WrappedContentKey)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := e2ee.UnwrapCEK(key, sealed)
	if err != nil || !bytes.Equal(opened[:], cek) {
		t.Fatal("original key cannot open the browser write")
	}
	for _, mutation := range []func(*transport.CryptoWrapCekPayload){
		func(p *transport.CryptoWrapCekPayload) { p.AAD.KeyEpochID = "" },
		func(p *transport.CryptoWrapCekPayload) { p.AAD.KeyEpochID = candidate },
		func(p *transport.CryptoWrapCekPayload) { p.AAD.NetworkID = "another-network" },
		func(p *transport.CryptoWrapCekPayload) { p.AAD.ObjectID = "another-object" },
	} {
		bad := p
		mutation(&bad)
		if _, err := d.doCryptoWrapCek(bad); err == nil {
			t.Fatal("write accepted a missing or mismatched committed scope")
		}
	}
	for _, missing := range []string{"", "missing-epoch"} {
		bad := start
		bad.EpochID = missing
		bad.SessionID = "rejected-" + missing
		if _, err := d.doCryptoSessionStart(bad); err == nil {
			t.Fatal("session admitted without the explicit available epoch")
		}
		if _, ok := d.cryptoManager().sessions.get(bad.SessionID, time.Now()); ok {
			t.Fatal("rejected start left a usable session")
		}
	}
	if err := ring.Revoke(committed); err != nil {
		t.Fatal(err)
	}
	if err := crypto.SaveKeyring(d.StateDir, ring); err != nil {
		t.Fatal(err)
	}
	if _, err := d.doCryptoSessionStart(start); err == nil {
		t.Fatal("revoked epoch admitted a browser session")
	}
	if _, err := d.doCryptoWrapCek(p); err == nil {
		t.Fatal("existing session wrote with a revoked epoch")
	}
}
