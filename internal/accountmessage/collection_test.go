package accountmessage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestCollectionBoundsRetentionAndRestart(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	j, e := OpenJournal(dir)
	if e != nil {
		t.Fatal(e)
	}
	r := request(t)
	key := [32]byte{1}
	s, e := j.Seal(context.Background(), r, key, func() bool { return true })
	if e != nil {
		t.Fatal(e)
	}
	// Populate valid independently bound ciphertext metadata to exercise a full
	// retained store without making the test depend on random IDs or fsync speed.
	tx, e := j.db.Begin()
	if e != nil {
		t.Fatal(e)
	}
	for i := 1; i < MaxRecords; i++ {
		record := s
		record.Descriptor.MessageID = fmt.Sprintf("message-%04d", i)
		record.MessageID = record.Descriptor.MessageID
		record.BindingDigest = record.Descriptor.BindingDigest()
		record.SealedDigest = record.Digest()
		raw, _ := json.Marshal(record)
		if _, e = tx.Exec(`INSERT INTO account_message_seals VALUES(?,?)`, record.MessageID, raw); e != nil {
			t.Fatal(e)
		}
	}
	if e = tx.Commit(); e != nil {
		t.Fatal(e)
	}
	next := r
	next.Descriptor.MessageID = "next"
	next.BindingDigest = next.Descriptor.BindingDigest()
	if _, e = j.Seal(context.Background(), next, key, func() bool { return true }); !errors.Is(e, ErrFull) {
		t.Fatal("full store admitted", e)
	}
	expires, _ := time.Parse(time.RFC3339Nano, r.Descriptor.ExpiresAt)
	if n, e := j.Collect(context.Background(), expires.Add(Retention-time.Nanosecond)); e != nil || n != 0 {
		t.Fatal("early collection", n, e)
	}
	n, e := j.Collect(context.Background(), expires.Add(Retention))
	if e != nil || n != CollectionBatch {
		t.Fatal("collection bound", n, e)
	}
	if _, e = j.Seal(context.Background(), next, key, func() bool { return true }); e != nil {
		t.Fatal("capacity not reclaimed", e)
	}
	if e = j.Close(); e != nil {
		t.Fatal(e)
	}
	j, e = OpenJournal(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer j.Close()
	// The original UUID sorts before message-*; the first page collected it,
	// while later records remain readable and startup validates their metadata.
	var count int
	if e = j.db.QueryRow(`SELECT COUNT(*) FROM account_message_seals`).Scan(&count); e != nil || count != MaxRecords-CollectionBatch+1 {
		t.Fatal(count, e)
	}
}
func TestCollectionReconcilesUncertainAndKeepsUnresolved(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(fmt.Sprint(committed), func(t *testing.T) {
			j, e := OpenJournal(filepath.Join(t.TempDir(), "private"))
			if e != nil {
				t.Fatal(e)
			}
			defer j.Close()
			r := request(t)
			key := [32]byte{1}
			j.commit = func(tx *sql.Tx) error {
				if committed {
					if e := tx.Commit(); e != nil {
						return e
					}
				}
				return errors.New("ambiguous")
			}
			if _, e = j.Seal(context.Background(), r, key, func() bool { return true }); !errors.Is(e, ErrUncertain) {
				t.Fatal(e)
			}
			candidate := j.pending[r.Descriptor.MessageID]
			expires, _ := time.Parse(time.RFC3339Nano, r.Descriptor.ExpiresAt)
			if n, e := j.Collect(context.Background(), expires.Add(Retention)); e != nil || n != 0 {
				t.Fatal(n, e)
			}
			if committed {
				if len(j.pending) != 0 {
					t.Fatal("committed candidate not reconciled")
				}
			} else {
				if j.pending[r.Descriptor.MessageID] != candidate {
					t.Fatal("unresolved candidate lost")
				}
			}
			j.commit = func(tx *sql.Tx) error { return tx.Commit() }
			s, e := j.Seal(context.Background(), r, key, func() bool { return true })
			if e != nil || s.Envelope != candidate.Envelope {
				t.Fatal("reconciliation changed ciphertext", e)
			}
		})
	}
}
func TestStrictJSONDuplicatesAliasesAndUnicode(t *testing.T) {
	r := request(t)
	raw, _ := json.Marshal(r)
	for _, mutate := range []func([]byte) []byte{
		func(b []byte) []byte { return append([]byte(`{"v":1,`), b[1:]...) },
		func(b []byte) []byte { return []byte(strings.ReplaceAll(string(b), `"text":`, `"Text":`)) },
		func(b []byte) []byte {
			return []byte(strings.ReplaceAll(string(b), `"kind":`, `"kind":"browser_account_delegate","kind":`))
		},
		func(b []byte) []byte {
			return []byte(strings.ReplaceAll(string(b), `"text":"private account text ☃"`, `"text":"\ud800"`))
		},
	} {
		if _, e := ParseSeal(mutate(raw)); e == nil {
			t.Fatal("accepted ambiguous or invalid Unicode frame")
		}
	}
}

func TestInvalidationDuringSQLiteCommitRetainsCiphertext(t *testing.T) {
	j, e := OpenJournal(filepath.Join(t.TempDir(), "private"))
	if e != nil {
		t.Fatal(e)
	}
	defer j.Close()
	r := request(t)
	key := [32]byte{1}
	var live atomic.Bool
	live.Store(true)
	entered := make(chan struct{})
	release := make(chan struct{})
	result := make(chan error, 1)
	j.commit = func(tx *sql.Tx) error { close(entered); <-release; return tx.Commit() }
	go func() { _, e := j.Seal(context.Background(), r, key, live.Load); result <- e }()
	<-entered
	live.Store(false)
	close(release)
	if e := <-result; e == nil {
		t.Fatal("returned ciphertext after invalidation during SQLite transaction")
	}
	var raw []byte
	if e := j.db.QueryRow(`SELECT payload FROM account_message_seals WHERE message_id=?`, r.Descriptor.MessageID).Scan(&raw); e != nil {
		t.Fatal(e)
	}
	var stored Sealed
	if e := decode(raw, &stored); e != nil {
		t.Fatal(e)
	}
	live.Store(true)
	j.commit = func(tx *sql.Tx) error { return tx.Commit() }
	again, e := j.Seal(context.Background(), r, key, live.Load)
	if e != nil || again.Envelope != stored.Envelope {
		t.Fatal("invalidated committed ciphertext lost", e)
	}
}
