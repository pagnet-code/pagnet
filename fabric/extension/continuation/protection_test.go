package continuation

import (
	"bytes"
	"testing"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/events/durable"
)

func TestProtectedStoreNoPlaintextAndExactIdentityAAD(t *testing.T) {
	s, dir, v, c, h, expiry := fixture(t)
	v.State = []byte(`{"private":"original-state-secret"}`)
	x := issue(t, s, c, v, expiry)
	var saved []byte
	if err := s.db.QueryRow("SELECT snapshot FROM continuations WHERE id=?", x.ID).Scan(&saved); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(saved, v.State) || bytes.Contains(saved, v.OriginalEnvelope) {
		t.Fatal("original source persisted as plaintext")
	}
	duplicate, err := s.Create(ctx, c, v, expiry)
	if err != nil || duplicate.Created || duplicate.Capability.Token() != "" {
		t.Fatal("random encryption changed exact create retry", err)
	}
	other := v
	other.DeferralID = ident("protected-other")
	other.State = []byte(`{"private":"second"}`)
	y := issue(t, s, c, other, expiry)
	var foreign []byte
	if err = s.db.QueryRow("SELECT snapshot FROM continuations WHERE id=?", y.ID).Scan(&foreign); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec("UPDATE continuations SET snapshot=? WHERE id=?", foreign, x.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Claim(ctx, h, x.Capability.Token(), ident("protected-claim")); err == nil {
		t.Fatal("foreign continuation ciphertext accepted")
	}
	if _, err = s.db.Exec("UPDATE continuations SET snapshot=? WHERE id=?", saved, x.ID); err != nil {
		t.Fatal(err)
	}
	claim, err := s.Claim(ctx, h, x.Capability.Token(), ident("protected-claim"))
	if err != nil {
		t.Fatal(err)
	}
	out := Outcome{Effect: fabric.EffectUnknown, Data: []byte(`{"private":"outcome-secret"}`)}
	if _, err = s.Complete(ctx, h, claim.Receipt, out); err != nil {
		t.Fatal(err)
	}
	var receipt, outcome []byte
	if err = s.db.QueryRow("SELECT receipt,outcome FROM continuations WHERE id=?", x.ID).Scan(&receipt, &outcome); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(receipt, []byte(h.PrincipalView().Ref)) || bytes.Contains(outcome, out.Data) {
		t.Fatal("claim or outcome persisted plaintext")
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	wrong, err := durable.NewAESGCM(testProtector(t).Reference(), bytes.Repeat([]byte{92}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Open(ctx, dir, Scope{"test:audience"}, DefaultOptions(), wrong); err == nil {
		t.Fatal("same key name with different key accepted")
	}
	reopened, err := Open(ctx, dir, Scope{"test:audience"}, DefaultOptions(), testProtector(t))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	again, err := reopened.Claim(ctx, h, x.Capability.Token(), ident("protected-claim"))
	if err != nil || again.Fresh || again.Outcome == nil || !bytes.Equal(again.Outcome.Data, out.Data) {
		t.Fatal("encrypted restart changed genuine outcome", err)
	}
}
func TestProtectedEmptyStoreAndOldPlaintextFormatFailClosed(t *testing.T) {
	s, dir, _, _, _, _ := fixture(t)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	wrong, err := durable.NewAESGCM(testProtector(t).Reference(), bytes.Repeat([]byte{92}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Open(ctx, dir, Scope{"test:audience"}, DefaultOptions(), wrong); err == nil {
		t.Fatal("empty store did not verify key custody")
	}
	s, err = Open(ctx, dir, Scope{"test:audience"}, DefaultOptions(), testProtector(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec("PRAGMA user_version=1"); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = Open(ctx, dir, Scope{"test:audience"}, DefaultOptions(), testProtector(t)); err == nil {
		t.Fatal("old plaintext storage format accepted")
	}
	if _, err = Open(ctx, dir, Scope{"test:audience"}, DefaultOptions(), nil); err == nil {
		t.Fatal("missing protector accepted")
	}
}
