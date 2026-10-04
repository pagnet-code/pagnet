package registry

import (
	"fmt"
	"testing"

	"github.com/pagnet-code/pagnet/fabric"
)

func TestPrivateAuthorityPagesVerifySignedRetiredClaimsAndCurrentSnapshot(t *testing.T) {
	s, owner, _ := fixture(t)
	err := s.WithNativeAuthority(t.Context(), owner, AuthorityScope{}, func(tx *AuthorityTx) error {
		for i := range 5 {
			_, err := tx.CAS(AuthorityKey{Kind: AuthorityNativeCheckpoint, ID: fmt.Sprintf("launch/%02d", i)}, 0, []byte(`{"signed":"claim"}`), false)
			if err != nil {
				return err
			}
		}
		if _, err := tx.CAS(AuthorityKey{Kind: AuthorityNativeCheckpoint, ID: "launch/00"}, 1, []byte(`{"signed":"claim"}`), true); err != nil {
			return err
		}
		_, err := tx.CAS(AuthorityKey{Kind: AuthorityNativeCheckpoint, ID: "source/not-launch"}, 0, []byte(`{}`), false)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	page, err := s.ListGlobalAuthorityRecords(t.Context(), owner, AuthorityNativeCheckpoint, "launch/", "", 2)
	if err != nil || len(page.Records) != 2 || page.NextCursor == "" || !page.Records[0].Retired {
		t.Fatal("bounded signed startup page", err, page)
	}
	for _, record := range page.Records {
		if err = VerifyAuthorityRecord(s.AuthorityIdentity(), record); err != nil {
			t.Fatal(err)
		}
	}
	next, err := s.ListGlobalAuthorityRecords(t.Context(), owner, AuthorityNativeCheckpoint, "launch/", page.NextCursor, 2)
	if err != nil || len(next.Records) != 2 || next.Records[0].Key.ID == page.Records[0].Key.ID {
		t.Fatal("keyset pagination", err)
	}
	if _, err = s.ListGlobalAuthorityRecords(t.Context(), fabric.ExecutionContext{}, AuthorityNativeCheckpoint, "launch/", "", 2); err == nil {
		t.Fatal("unverified owner enumerated authority")
	}
	err = s.WithNativeAuthority(t.Context(), owner, AuthorityScope{}, func(tx *AuthorityTx) error {
		_, e := tx.CAS(AuthorityKey{Kind: AuthorityNativeCheckpoint, ID: "launch/99"}, 0, []byte(`{}`), false)
		return e
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.ListGlobalAuthorityRecords(t.Context(), owner, AuthorityNativeCheckpoint, "launch/", page.NextCursor, 2); err == nil {
		t.Fatal("stale native authority snapshot accepted")
	}
}
