package fabric

import (
	"crypto/sha256"
	"encoding/json"
	"testing"
)

func TestAuthenticationEvidenceRemainsPrivateAndExact(t *testing.T) {
	principal := Principal{Ref: "spiffe://local/owner", Kind: "local.owner", Issuer: "local.test"}
	evidence := &struct{ Private string }{"actual trusted private token"}
	original := []byte("exact authenticator input")
	caller, err := NewAuthenticatedContextWithEvidence(principal, "local-audience", original, evidence)
	if err != nil {
		t.Fatal(err)
	}
	if caller.AuthenticationEvidence() != evidence || caller.VerifyAuthenticatedDigest(sha256.Sum256(original), "local-audience") != nil {
		t.Fatal("trusted private association lost")
	}
	if caller.VerifyAuthenticatedDigest(sha256.Sum256([]byte("changed")), "local-audience") == nil || caller.VerifyAuthenticatedDigest(sha256.Sum256(original), "foreign") == nil {
		t.Fatal("wrong original/audience admitted")
	}
	if _, err = json.Marshal(caller); err == nil {
		t.Fatal("private evidence serialized")
	}
	var forged ExecutionContext
	if json.Unmarshal([]byte(`{"authenticationEvidence":{"Private":"actual trusted private token"}}`), &forged) == nil {
		t.Fatal("wire recreated private evidence")
	}
	plain, err := NewAuthenticatedContext(principal, "local-audience", original)
	if err != nil || plain.AuthenticationEvidence() != nil {
		t.Fatal("static setup context gained current evidence")
	}
	if _, err = NewAuthenticatedContextWithEvidence(principal, "local-audience", original, nil); err == nil {
		t.Fatal("missing private evidence accepted")
	}
}
