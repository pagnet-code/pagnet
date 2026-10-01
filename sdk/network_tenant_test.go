package sdk

import (
	"bytes"
	"errors"
	"github.com/pagnet-code/pagnet/e2ee"
	"testing"
)

func TestProtectedContentUsesApprovedNetworkOrganizationNotPrincipalHome(t *testing.T) {
	ring, err := newKeyring(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	client := &Client{kr: ring}
	client.tenantID.Store("principal-home")
	key := [32]byte{7, 8, 9}
	for _, network := range []string{"network-one", "network-two"} {
		if err := ring.StoreEpoch(network, "epoch", key); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := client.encryptObject("network-one", e2ee.ObjectTypeMessage, newObjectID(), "sender", "recipient", []byte("private")); !errors.Is(err, ErrNetworkCryptoNotReady) {
		t.Fatal("missing network owner guessed from principal home")
	}
	if err := client.rememberNetworkTenant("network-one", "organization-one"); err != nil {
		t.Fatal(err)
	}
	if err := client.rememberNetworkTenant("network-two", "organization-two"); err != nil {
		t.Fatal(err)
	}
	for network, tenant := range map[string]string{"network-one": "organization-one", "network-two": "organization-two"} {
		envelope, aad, err := client.encryptObject(network, e2ee.ObjectTypeMessage, newObjectID(), "sender", "recipient", []byte("private"))
		if err != nil {
			t.Fatal(err)
		}
		if aad.TenantID != tenant {
			t.Fatal("content used wrong owning organization")
		}
		plain, err := e2ee.Decrypt(envelope, key, aad)
		if err != nil || !bytes.Equal(plain, []byte("private")) {
			t.Fatal("authorized cross-organization encryption failed")
		}
		aad.TenantID = "principal-home"
		if _, err := e2ee.Decrypt(envelope, key, aad); err == nil {
			t.Fatal("organization AAD substitution accepted")
		}
	}
	if err := client.rememberNetworkTenant("network-one", "changed-organization"); err == nil || client.authorizedNetworkTenant("network-one") != "organization-one" {
		t.Fatal("network ownership pin silently overwritten")
	}
}

func TestIncomingEncryptedHistoryCannotEstablishOutgoingNetworkOwnership(t *testing.T) {
	ring, err := newKeyring(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	client := &Client{kr: ring}
	key := [32]byte{3}
	if err := ring.StoreEpoch("network", "epoch", key); err != nil {
		t.Fatal(err)
	}
	aad := e2ee.AAD{ProtocolVersion: 2, TenantID: "history-organization", NetworkID: "network", ObjectType: e2ee.ObjectTypeMessage, ObjectID: newObjectID(), Sender: "sender", Recipient: "recipient", CreatedAt: "2026-10-01T00:00:00Z", KeyEpochID: "epoch"}
	env, err := e2ee.Encrypt([]byte("old protected message"), key, aad)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.decryptObject("network", env, aad); err != nil {
		t.Fatal(err)
	}
	if client.authorizedNetworkTenant("network") != "" {
		t.Fatal("incoming message established authoritative organization")
	}
	if _, _, err := client.encryptObject("network", e2ee.ObjectTypeMessage, newObjectID(), "sender", "recipient", []byte("outgoing")); !errors.Is(err, ErrNetworkCryptoNotReady) {
		t.Fatal("untrusted history tenant used for new content")
	}
}
