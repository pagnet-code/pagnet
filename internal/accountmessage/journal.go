// Package accountmessage stages encrypted account delegate messages. It has no
// dispatch, native execution, socket, or principal impersonation capability.
package accountmessage

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"sync"

	"github.com/pagnet-code/pagnet/e2ee"
	_ "modernc.org/sqlite"
)

const MaxRecords = 1024
const MaxRecordBytes = 32768

var ErrConflict = errors.New("account message conflicts with staged ciphertext")
var ErrFull = errors.New("account message staging is full")
var ErrUncertain = errors.New("account message commit uncertain; retry same request")

// Journal never passes plaintext or plaintext digests to SQLite. Failed commits
// retain the encrypted candidate in memory, so a retry cannot reencrypt it.
// Durable records remain immutable until conservative retention collection.
type Journal struct {
	mu                      sync.Mutex
	db                      *sql.DB
	pending                 map[string]Sealed
	commit                  func(*sql.Tx) error
	collectionCursor        string
	pendingCollectionCursor string
}

func OpenJournal(dir string) (*Journal, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return nil, errors.New("account staging requires private directory")
	}
	path := filepath.Join(dir, "account-messages.sqlite")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err == nil {
		err = f.Close()
	} else if os.IsExist(err) {
		info, err = os.Lstat(path)
		if err == nil && (!info.Mode().IsRegular() || info.Mode().Perm() != 0600) {
			err = errors.New("account staging requires private regular file")
		}
	}
	if err != nil {
		return nil, err
	}
	uri := (&url.URL{Scheme: "file", Path: path}).String()
	db, err := sql.Open("sqlite", uri)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	j := &Journal{db: db, pending: make(map[string]Sealed), commit: func(tx *sql.Tx) error { return tx.Commit() }}
	for _, q := range []string{"PRAGMA journal_mode=WAL", "PRAGMA synchronous=FULL", "PRAGMA busy_timeout=5000", `CREATE TABLE IF NOT EXISTS account_message_seals(message_id TEXT PRIMARY KEY,payload BLOB NOT NULL CHECK(length(payload)<=32768))`} {
		if _, err = db.Exec(q); err != nil {
			db.Close()
			return nil, err
		}
	}
	rows, err := db.Query(`SELECT message_id,payload FROM account_message_seals`)
	if err != nil {
		db.Close()
		return nil, err
	}
	count := 0
	for rows.Next() {
		var id string
		var raw []byte
		if err = rows.Scan(&id, &raw); err != nil {
			break
		}
		count++
		var s Sealed
		if count > MaxRecords || len(raw) > MaxRecordBytes || decode(raw, &s) != nil || s.Validate() != nil || s.MessageID != id {
			err = errors.New("invalid stored account seal")
			break
		}
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		db.Close()
		return nil, err
	}
	return j, nil
}
func (j *Journal) Close() error { j.mu.Lock(); defer j.mu.Unlock(); return j.db.Close() }

// Seal validates current authority before encryption and again immediately
// before committing. guard must fence the original subscription and local
// mutation generation; it is not a source of server messaging authority.
func (j *Journal) Seal(ctx context.Context, r SealRequest, key [32]byte, guard func() bool) (Sealed, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if r.Validate() != nil || guard == nil || !guard() {
		return Sealed{}, errors.New("invalid or fenced account seal")
	}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return Sealed{}, err
	}
	defer tx.Rollback()
	var raw []byte
	err = tx.QueryRowContext(ctx, `SELECT payload FROM account_message_seals WHERE message_id=?`, r.Descriptor.MessageID).Scan(&raw)
	var s Sealed
	switch {
	case err == nil:
		if len(raw) > MaxRecordBytes || decode(raw, &s) != nil || s.Validate() != nil {
			return Sealed{}, ErrConflict
		}
	case errors.Is(err, sql.ErrNoRows):
		var count int
		if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM account_message_seals`).Scan(&count); err != nil {
			return Sealed{}, err
		}
		if count >= MaxRecords {
			return Sealed{}, ErrFull
		}
		var ok bool
		s, ok = j.pending[r.Descriptor.MessageID]
		if !ok {
			if count+len(j.pending) >= MaxRecords {
				return Sealed{}, ErrFull
			}
			envelope, e := e2ee.Encrypt([]byte(r.Text), key, r.Descriptor.AAD(r.BindingDigest))
			if e != nil {
				return Sealed{}, e
			}
			s = Sealed{V: 1, MessageID: r.Descriptor.MessageID, BindingDigest: r.BindingDigest, Descriptor: r.Descriptor, Envelope: envelope}
			s.SealedDigest = s.Digest()
			j.pending[s.MessageID] = s
		}
	default:
		return Sealed{}, err
	}
	if s.Descriptor != r.Descriptor || s.BindingDigest != r.BindingDigest {
		return Sealed{}, ErrConflict
	}
	plain, err := e2ee.Decrypt(s.Envelope, key, r.Descriptor.AAD(r.BindingDigest))
	if err != nil {
		return Sealed{}, err
	}
	same := bytes.Equal(plain, []byte(r.Text))
	clear(plain)
	if !same {
		return Sealed{}, ErrConflict
	}
	if !guard() {
		return Sealed{}, errors.New("account seal fenced")
	}
	raw, err = json.Marshal(s)
	if err != nil || len(raw) > MaxRecordBytes {
		return Sealed{}, errors.New("account seal exceeds bound")
	}
	if _, err = tx.ExecContext(ctx, `INSERT OR IGNORE INTO account_message_seals(message_id,payload) VALUES(?,?)`, s.MessageID, raw); err != nil {
		return Sealed{}, err
	}
	if err = j.commit(tx); err != nil {
		return Sealed{}, ErrUncertain
	}
	delete(j.pending, s.MessageID)
	if !guard() {
		return Sealed{}, errors.New("account seal fenced after commit")
	}
	return s, nil
}
