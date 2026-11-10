package accountmessage

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pagnet-code/pagnet/e2ee"
)

type vector struct {
	Descriptor          Descriptor              `json:"descriptor"`
	DescriptorCanonical string                  `json:"descriptorCanonical"`
	BindingDigest       string                  `json:"bindingDigest"`
	AADCanonical        string                  `json:"aadCanonical"`
	Envelope            e2ee.EncryptedPayloadV1 `json:"envelope"`
	SealedCanonical     string                  `json:"sealedCanonical"`
	SealedDigest        string                  `json:"sealedDigest"`
}

func fixture(t *testing.T) vector {
	t.Helper()
	raw, e := os.ReadFile("testdata/account_message_v1.json")
	if e != nil {
		t.Fatal(e)
	}
	var v vector
	if e = json.Unmarshal(raw, &v); e != nil {
		t.Fatal(e)
	}
	return v
}
func request(t *testing.T) SealRequest {
	d := fixture(t).Descriptor
	return SealRequest{V: 1, Descriptor: d, BindingDigest: d.BindingDigest(), Text: "private account text \u2603"}
}
func TestCanonicalServerVector(t *testing.T) {
	v := fixture(t)
	if e := v.Descriptor.Validate(); e != nil {
		t.Fatal(e)
	}
	if string(v.Descriptor.CanonicalJSON()) != v.DescriptorCanonical || v.Descriptor.BindingDigest() != v.BindingDigest || string(v.Descriptor.AAD(v.BindingDigest).CanonicalBytes()) != v.AADCanonical {
		t.Fatal("canonical descriptor/AAD mismatch")
	}
	s := Sealed{V: 1, Descriptor: v.Descriptor, MessageID: v.Descriptor.MessageID, BindingDigest: v.BindingDigest, Envelope: v.Envelope, SealedDigest: v.SealedDigest}
	if e := s.Validate(); e != nil {
		t.Fatal(e)
	}
}
func TestStrictSealBounds(t *testing.T) {
	r := request(t)
	for _, text := range []string{"", strings.Repeat("a", MaxTextBytes+1), string([]byte{0xff})} {
		r.Text = text
		if r.Validate() == nil {
			t.Fatal("accepted invalid text")
		}
	}
	r = request(t)
	r.Text = strings.Repeat("\u00e9", MaxTextBytes/2)
	raw, _ := json.Marshal(r)
	if _, e := ParseSeal(raw); e != nil {
		t.Fatal(e)
	}
	raw = bytes.Replace(raw, []byte(`"sender":{`), []byte(`"sender":{"unknown":true,`), 1)
	if _, e := ParseSeal(raw); e == nil {
		t.Fatal("accepted unknown sender field")
	}
	r = request(t)
	r.Descriptor.DesiredRevision = "01"
	r.BindingDigest = r.Descriptor.BindingDigest()
	if r.Validate() == nil {
		t.Fatal("accepted noncanonical counter")
	}
	r = request(t)
	r.BindingDigest = strings.Repeat("0", 64)
	if r.Validate() == nil {
		t.Fatal("accepted wrong digest")
	}
}
func TestJournalRestartRetryConflictAndNoPlaintext(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	j, e := OpenJournal(dir)
	if e != nil {
		t.Fatal(e)
	}
	r := request(t)
	key := [32]byte{1}
	guard := func() bool { return true }
	first, e := j.Seal(context.Background(), r, key, guard)
	if e != nil {
		t.Fatal(e)
	}
	again, e := j.Seal(context.Background(), r, key, guard)
	if e != nil || first.Envelope != again.Envelope {
		t.Fatal("retry changed ciphertext", e)
	}
	changed := r
	changed.Text += "x"
	if _, e = j.Seal(context.Background(), changed, key, guard); !errors.Is(e, ErrConflict) {
		t.Fatal("text conflict", e)
	}
	changed = r
	changed.Descriptor.EpochID = "different"
	changed.BindingDigest = changed.Descriptor.BindingDigest()
	if _, e = j.Seal(context.Background(), changed, key, guard); !errors.Is(e, ErrConflict) {
		t.Fatal("descriptor conflict", e)
	}
	for _, name := range []string{"account-messages.sqlite", "account-messages.sqlite-wal"} {
		raw, e := os.ReadFile(filepath.Join(dir, name))
		if e == nil && bytes.Contains(raw, []byte(r.Text)) {
			t.Fatal("plaintext persisted")
		}
	}
	j.Close()
	j, e = OpenJournal(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer j.Close()
	again, e = j.Seal(context.Background(), r, key, guard)
	if e != nil || first.Envelope != again.Envelope {
		t.Fatal("restart changed ciphertext", e)
	}
	key[0]++
	if _, e = j.Seal(context.Background(), r, key, guard); e == nil {
		t.Fatal("accepted different epoch key")
	}
}
func TestCommitAmbiguityRetainsCiphertext(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(map[bool]string{false: "rolledback", true: "committed"}[committed], func(t *testing.T) {
			j, e := OpenJournal(filepath.Join(t.TempDir(), "private"))
			if e != nil {
				t.Fatal(e)
			}
			defer j.Close()
			j.commit = func(tx *sql.Tx) error {
				if committed {
					if e := tx.Commit(); e != nil {
						return e
					}
				}
				return errors.New("ambiguous")
			}
			r := request(t)
			key := [32]byte{1}
			if _, e = j.Seal(context.Background(), r, key, func() bool { return true }); !errors.Is(e, ErrUncertain) {
				t.Fatal(e)
			}
			candidate := j.pending[r.Descriptor.MessageID]
			j.commit = func(tx *sql.Tx) error { return tx.Commit() }
			s, e := j.Seal(context.Background(), r, key, func() bool { return true })
			if e != nil || s.Envelope != candidate.Envelope {
				t.Fatal("ambiguous retry reencrypted", e)
			}
		})
	}
}
func TestMutationFencesBeforeAndAfterCommit(t *testing.T) {
	j, e := OpenJournal(filepath.Join(t.TempDir(), "private"))
	if e != nil {
		t.Fatal(e)
	}
	defer j.Close()
	calls := 0
	_, e = j.Seal(context.Background(), request(t), [32]byte{1}, func() bool { calls++; return calls < 2 })
	if e == nil {
		t.Fatal("mutation before commit was accepted")
	}
	var n int
	j.db.QueryRow(`SELECT COUNT(*) FROM account_message_seals`).Scan(&n)
	if n != 0 {
		t.Fatal("committed fenced candidate")
	}
	calls = 0
	_, e = j.Seal(context.Background(), request(t), [32]byte{1}, func() bool { calls++; return calls < 3 })
	if e == nil {
		t.Fatal("mutation after commit produced reply")
	}
	j.db.QueryRow(`SELECT COUNT(*) FROM account_message_seals`).Scan(&n)
	if n != 1 {
		t.Fatal("lost committed candidate")
	}
}

func TestMalformedSealErrorsRedacted(t *testing.T) {
	secret := "private-input-must-not-be-logged"
	for _, raw := range []string{`{"` + secret + `":true}`, `{"text":{"` + secret + `":true}}`, `{"descriptor":{"sender":{"` + secret + `":true}}}`} {
		_, err := ParseSeal([]byte(raw))
		if err == nil || strings.Contains(err.Error(), secret) {
			t.Fatal("malformed frame error disclosed private input")
		}
	}
}
