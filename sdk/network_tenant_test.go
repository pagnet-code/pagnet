package sdk

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"errors"
	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/transport"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
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

func TestOldServerKeyPackageBeforeAuthorizedNetworkResponseIsNotReady(t *testing.T) {
	ring, err := newKeyring(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	identity, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	client := &Client{kr: ring, identityPriv: identity.Bytes(), cryptoReadySet: map[string]bool{}}
	client.tenantID.Store("principal-home-must-not-be-used")
	key := [32]byte{41, 42, 43}
	enc, ciphertext, err := e2ee.HPKEWrap(identity.PublicKey().Bytes(), []byte(enrollmentInfo), nil, key[:])
	if err != nil {
		t.Fatal(err)
	}
	// Decode exactly the pre-v067 package shape: tenantId is absent.
	wire, err := json.Marshal(map[string]any{"networkId": "network", "epochId": "epoch", "wrappedKey": transport.CryptoHPKEWrap{Enc: enc, Ciphertext: ciphertext}})
	if err != nil {
		t.Fatal(err)
	}
	var oldPackage EndpointCryptoKeyPackagePayload
	if err := json.Unmarshal(wire, &oldPackage); err != nil {
		t.Fatal(err)
	}
	if err := client.handleCryptoKeyPackage(oldPackage); err != nil {
		t.Fatal(err)
	}
	if client.cryptoReady("network") {
		t.Fatal("key alone reported ready before authenticated ownership")
	}
	if _, _, err := client.encryptObject("network", e2ee.ObjectTypeMessage, newObjectID(), "sender", "recipient", []byte("private")); !errors.Is(err, ErrNetworkCryptoNotReady) {
		t.Fatal("key alone encrypted using guessed ownership")
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/networks" || r.Header.Get("Authorization") != "Bearer fixture-credential" {
			t.Error("unexpected unauthenticated bootstrap request")
			w.WriteHeader(403)
			return
		}
		close(entered)
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		_ = json.NewEncoder(w).Encode([]map[string]any{{"ID": "network", "TenantID": "authorized-network-owner", "Name": "fixture"}})
	}))
	defer server.Close()
	client.rest = newRestClient(server.URL, "fixture", func() string { return "fixture-credential" })
	client.rest.http = server.Client()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		nets, err := client.Networks(ctx)
		if err == nil && (len(nets) != 1 || !nets[0].CryptoReady) {
			err = errors.New("authenticated network response did not make enrolled key ready")
		}
		done <- err
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("network fetch did not start")
	}
	if client.cryptoReady("network") {
		t.Fatal("in-flight HTTP request guessed readiness")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	envelope, aad, err := client.encryptObject("network", e2ee.ObjectTypeMessage, newObjectID(), "sender", "recipient", []byte("private"))
	if err != nil {
		t.Fatal(err)
	}
	if aad.TenantID != "authorized-network-owner" {
		t.Fatal("wrong organization after old-server bootstrap")
	}
	if plain, err := e2ee.Decrypt(envelope, key, aad); err != nil || string(plain) != "private" {
		t.Fatal("first encryption failed after readiness")
	}
}
