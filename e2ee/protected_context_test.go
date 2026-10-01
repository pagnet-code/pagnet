package e2ee

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
)

func TestOwnerContextPublicCanonicalVectorAndNetworkCompatibility(t *testing.T) {
	raw, err := os.ReadFile("testdata/owner_context_public_vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		CanonicalAAD string `json:"canonicalAAD"`
		HPKEAAD      string `json:"hpkeAAD"`
		Proof        string `json:"proof"`
	}
	if err = json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	var aad AAD
	if err = json.Unmarshal([]byte(vector.CanonicalAAD), &aad); err != nil {
		t.Fatal(err)
	}
	if string(aad.CanonicalBytes()) != vector.CanonicalAAD {
		t.Fatal("canonical owner AAD differs from browser public vector")
	}
	if string(OwnerBrowserSessionAAD(*aad.ProtectedContext, "browser-session", aad.ObjectID)) != vector.HPKEAAD {
		t.Fatal("HPKE AAD differs from browser public vector")
	}
	proof, err := ApprovalProof(bytes.Repeat([]byte{7}, 32), aad, aad.Sender, "native-session", "native-approval", "allow-once")
	if err != nil || base64.StdEncoding.EncodeToString(proof) != vector.Proof {
		t.Fatal("approval HMAC differs from browser public vector", err)
	}
	// Adding the optional context must not add a null field to old network AAD.
	network := aad
	network.ProtectedContext = nil
	network.NetworkID = "network"
	if bytes.Contains(network.CanonicalBytes(), []byte("protected_context")) {
		t.Fatal("historical network canonical bytes changed")
	}
	var key [32]byte
	env, err := Encrypt([]byte("private inspection"), key, aad)
	if err != nil {
		t.Fatal(err)
	}
	if plain, err := Decrypt(env, key, aad); err != nil || string(plain) != "private inspection" {
		t.Fatal("owner encryption roundtrip", err)
	}
	for _, mutation := range []func(*AAD){func(a *AAD) { a.NetworkID = "contradiction" }, func(a *AAD) { a.TenantID = "wrong" }, func(a *AAD) { c := *a.ProtectedContext; c.Kind = "network"; a.ProtectedContext = &c }, func(a *AAD) {
		c := *a.ProtectedContext
		c.OwnerUserID = "44444444-4444-4444-8444-444444444444"
		a.ProtectedContext = &c
	}} {
		altered := aad
		mutation(&altered)
		if _, err = Decrypt(env, key, altered); err == nil {
			t.Fatal("tampered scope decrypted owner content")
		}
	}
	changed, err := ApprovalProof(bytes.Repeat([]byte{7}, 32), aad, aad.Sender, "native-session", "native-approval", "allow-always")
	if err != nil || bytes.Equal(changed, proof) {
		t.Fatal("approval proof did not bind exact option")
	}
}
