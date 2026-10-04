package registry

import (
	"context"
	"testing"
)

func TestExtensionConfigurationHasGlobalSignedPurposeAndRetainedRecovery(t *testing.T) {
	s, owner, endpointScope, dir := nativeFixture(t)
	global := AuthorityScope{MaxOperations: 4}
	key := AuthorityKey{Kind: AuthorityExtensionConfiguration, ID: "pagnet.extensions.directory"}
	var committed AuthorityRecord
	err := s.WithNativeAuthority(t.Context(), owner, global, func(tx *AuthorityTx) error {
		var e error
		committed, e = tx.CAS(key, 0, []byte(`{"cipher":"operator-protected","format":1}`), false)
		return e
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifyAuthorityRecord(s.AuthorityIdentity(), committed); err != nil {
		t.Fatal(err)
	}
	substituted := committed
	substituted.Key.Kind = AuthorityNativeCheckpoint
	if VerifyAuthorityRecord(s.AuthorityIdentity(), substituted) == nil {
		t.Fatal("signature permits purpose substitution")
	}
	invalid := key
	invalid.Endpoint = endpointScope.Endpoint
	if err = s.WithNativeAuthority(t.Context(), owner, endpointScope, func(tx *AuthorityTx) error { _, e := tx.CAS(invalid, 0, []byte(`{}`), false); return e }); err == nil {
		t.Fatal("global configuration accepts endpoint-scoped alias")
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	retainedIdentity := reopened.AuthorityIdentity()
	err = reopened.WithNativeAuthority(t.Context(), owner, global, func(tx *AuthorityTx) error {
		original, e := tx.Get(key)
		if e != nil {
			return e
		}
		if original.Revision != committed.Revision || original.Sequence != committed.Sequence || string(original.Value) != string(committed.Value) {
			t.Fatal("retained recovery changed signed configuration")
		}
		return VerifyAuthorityRecord(retainedIdentity, original)
	})
	if err != nil {
		t.Fatal(err)
	}
}
