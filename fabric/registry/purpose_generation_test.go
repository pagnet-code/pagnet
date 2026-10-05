package registry

import (
	"bytes"
	"testing"
)

func TestIntrinsicExtensionGenerationAtomicRetryAndCallerDenial(t *testing.T) {
	s, owner, scope, dir := nativeFixture(t)
	key := AuthorityKey{Kind: AuthorityExtensionConfiguration, ID: "test.extension"}
	var first, generation AuthorityRecord
	if err := s.WithNativeAuthority(t.Context(), owner, scope, func(tx *AuthorityTx) error {
		var err error
		first, err = tx.CAS(key, 0, []byte(`{"profile":1}`), false)
		if err != nil {
			return err
		}
		generation, err = tx.ExtensionPurposeGeneration()
		return err
	}); err != nil {
		t.Fatal(err)
	}
	count := nativeCount(t, s)
	if err := s.WithNativeAuthority(t.Context(), owner, scope, func(tx *AuthorityTx) error {
		r, e := tx.CAS(key, 0, first.Value, false)
		if e != nil {
			return e
		}
		if r.Sequence != first.Sequence {
			t.Fatal("retry advanced source")
		}
		g, e := tx.ExtensionPurposeGeneration()
		if e != nil {
			return e
		}
		if g.Sequence != generation.Sequence {
			t.Fatal("retry advanced generation")
		}
		if _, e = tx.CAS(purposeGenerationKey(), 1, g.Value, false); e == nil {
			t.Fatal("intrinsic mutation accepted")
		}
		_, e = tx.CAS(AuthorityKey{Kind: AuthorityController, ID: "unrelated"}, 0, []byte(`{"controller":1}`), false)
		if e != nil {
			return e
		}
		g, e = tx.ExtensionPurposeGeneration()
		if e == nil && !bytes.Equal(g.Signature, generation.Signature) {
			t.Fatal("unrelated purpose advanced extension")
		}
		return e
	}); err != nil {
		t.Fatal(err)
	}
	if nativeCount(t, s) != count+1 {
		t.Fatal("unexpected ledger writes")
	}
	if _, err := s.db.Exec(`CREATE TRIGGER fail_generation BEFORE INSERT ON native_authority_log WHEN CAST(NEW.record AS TEXT) LIKE '%"kind":"purpose_generation"%' BEGIN SELECT RAISE(ABORT,'failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := s.WithNativeAuthority(t.Context(), owner, scope, func(tx *AuthorityTx) error {
		if _, e := tx.CAS(key, 1, []byte(`{"profile":2}`), false); e == nil {
			t.Fatal("injected generation failure accepted")
		}
		r, e := tx.Get(key)
		if e == nil && r.Sequence != first.Sequence {
			t.Fatal("caught failure leaked partial mutation")
		}
		return e
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("DROP TRIGGER fail_generation"); err != nil {
		t.Fatal(err)
	}
	if err := s.WithNativeAuthority(t.Context(), owner, scope, func(tx *AuthorityTx) error {
		_, e := tx.CAS(key, 1, first.Value, true)
		if e != nil {
			return e
		}
		g, e := tx.ExtensionPurposeGeneration()
		if e == nil && g.Revision != 2 {
			t.Fatal("retirement did not advance")
		}
		return e
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(t.Context(), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
}
