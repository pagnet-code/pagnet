package daemon

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sync"

	"github.com/pagnet-code/pagnet/sdk"
)

// Mailboxes retain at most 10,000 records and 64 MiB of encrypted payload per
// installation. One encoded record is limited to 1 MiB; SQLite is additionally
// limited to 20,000 4 KiB pages. Full mailboxes leave SDK receipts pending.
const sharingMailboxMaxCount = 10000
const sharingMailboxMaxBytes = 64 << 20
const sharingMailboxMaxRecord = 1 << 20

// This immutable local scope does not establish browser or owner authorization.
type sharingMailboxBinding struct {
	InstallationID string
	ServiceID      string
	TenantID       string
	HostID         string
}
type sharingMailboxRecord struct {
	Message       sdk.SharingMessage
	Text          string
	ReplyMaterial []byte
}
type sharingMailboxAAD struct {
	Binding    sharingMailboxBinding
	GrantID    string
	Generation int64
	MessageID  string
}
type sharingMailbox struct {
	mu      sync.Mutex
	db      *sql.DB
	aead    cipher.AEAD
	binding sharingMailboxBinding
}

func syncSharingMailboxDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func sharingMailboxKey(dir string, databaseExists bool) ([]byte, error) {
	path := filepath.Join(dir, "key")
	key, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) && !databaseExists {
		key = make([]byte, 32)
		if _, err = rand.Read(key); err != nil {
			return nil, err
		}
		f, err := os.CreateTemp(dir, ".key-*")
		if err != nil {
			return nil, err
		}
		defer os.Remove(f.Name())
		if _, err = f.Write(key); err != nil {
			f.Close()
			return nil, err
		}
		if err = f.Sync(); err != nil {
			f.Close()
			return nil, err
		}
		if err = f.Close(); err != nil {
			return nil, err
		}
		// Link publishes a complete key atomically without replacing an existing key.
		if err = os.Link(f.Name(), path); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		if err = syncSharingMailboxDir(dir); err != nil {
			return nil, err
		}
		key, err = os.ReadFile(path)
	}
	if err != nil || len(key) != 32 {
		return nil, errors.New("sharing mailbox key unavailable")
	}
	if err = os.Chmod(path, 0600); err != nil {
		return nil, err
	}
	return key, nil
}

func openSharingMailbox(dir string, binding sharingMailboxBinding) (_ *sharingMailbox, err error) {
	if binding.InstallationID == "" || binding.ServiceID == "" || binding.TenantID == "" || binding.HostID == "" {
		return nil, errors.New("sharing mailbox binding unavailable")
	}
	if err = os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if err = os.Chmod(dir, 0700); err != nil {
		return nil, err
	}
	if err = syncSharingMailboxDir(filepath.Dir(dir)); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "inbound.sqlite")
	_, statErr := os.Stat(path)
	if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return nil, statErr
	}
	key, err := sharingMailboxKey(dir, statErr == nil)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if statErr == nil {
		m, err := openSharingMailboxDatabase(path, aead, binding, false)
		if err != nil {
			return nil, err
		}
		if err = syncSharingMailboxDir(dir); err != nil {
			m.db.Close()
			return nil, err
		}
		return m, nil
	}
	if err = publishSharingMailboxDatabase(dir, path, func(temporary string) error {
		initial, err := openSharingMailboxDatabase(temporary, aead, binding, true)
		if err != nil {
			return err
		}
		return initial.db.Close()
	}); err != nil {
		return nil, err
	}
	return openSharingMailboxDatabase(path, aead, binding, false)
}

// The established path is published only after the complete authenticated
// database has committed and closed. A crash before publication leaves an
// unused temporary file; the next startup can initialize a fresh one.
func publishSharingMailboxDatabase(dir, path string, initialize func(string) error) error {
	f, err := os.CreateTemp(dir, ".inbound-*")
	if err != nil {
		return err
	}
	temporary := f.Name()
	defer os.Remove(temporary)
	if err = f.Close(); err != nil {
		return err
	}
	if err = initialize(temporary); err != nil {
		return err
	}
	// Link publishes atomically without replacing an established mailbox.
	if err = os.Link(temporary, path); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	return syncSharingMailboxDir(dir)
}

func openSharingMailboxDatabase(path string, aead cipher.AEAD, binding sharingMailboxBinding, initialize bool) (_ *sharingMailbox, err error) {
	if err = os.Chmod(path, 0600); err != nil {
		return nil, err
	}
	// Driver pragmas run for every physical connection, including replacements
	// created by database/sql. EXTRA syncs the DELETE journal's unlink before
	// commit returns: https://www.sqlite.org/pragma.html#pragma_synchronous.
	query := url.Values{"mode": {"rw"}, "_pragma": {"page_size=4096", "max_page_count=20000", "journal_mode=DELETE", "synchronous=EXTRA", "busy_timeout=5000"}}
	dsn := (&url.URL{Scheme: "file", Path: path, RawQuery: query.Encode()}).String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	m := &sharingMailbox{db: db, aead: aead, binding: binding}
	defer func() {
		if err != nil {
			db.Close()
		}
	}()
	var synchronous int
	if err = db.QueryRow("PRAGMA synchronous").Scan(&synchronous); err != nil {
		return nil, err
	}
	if synchronous != 3 {
		return nil, errors.New("sharing mailbox durability unavailable")
	}
	if initialize {
		for _, stmt := range []string{
			"CREATE TABLE mailbox_binding (id INTEGER PRIMARY KEY CHECK(id=1), sealed BLOB NOT NULL)",
			"CREATE TABLE inbound (grant_id TEXT NOT NULL, generation INTEGER NOT NULL, message_id TEXT NOT NULL, sealed BLOB NOT NULL, PRIMARY KEY(grant_id,generation,message_id))",
		} {
			if _, err = db.Exec(stmt); err != nil {
				return nil, err
			}
		}
	}
	aad, _ := json.Marshal(binding)
	var sealed []byte
	err = db.QueryRow("SELECT sealed FROM mailbox_binding WHERE id=1").Scan(&sealed)
	if errors.Is(err, sql.ErrNoRows) && initialize {
		sealed, err = m.seal([]byte("sharing-mailbox-v1"), aad)
		if err != nil {
			return nil, err
		}
		_, err = db.Exec("INSERT INTO mailbox_binding(id,sealed) VALUES(1,?)", sealed)
	} else if err == nil {
		var plain []byte
		plain, err = m.unseal(sealed, aad)
		if err == nil && string(plain) != "sharing-mailbox-v1" {
			err = errors.New("sharing mailbox binding invalid")
		}
	}
	if err != nil {
		return nil, err
	}
	if _, err = db.Exec("CREATE TABLE IF NOT EXISTS outbound (operation_id TEXT PRIMARY KEY, message_id TEXT NOT NULL UNIQUE, sealed BLOB NOT NULL)"); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *sharingMailbox) seal(plain, aad []byte) ([]byte, error) {
	nonce := make([]byte, m.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return m.aead.Seal(nonce, nonce, plain, aad), nil
}
func (m *sharingMailbox) unseal(sealed, aad []byte) ([]byte, error) {
	n := m.aead.NonceSize()
	if len(sealed) < n {
		return nil, errors.New("sharing mailbox ciphertext invalid")
	}
	return m.aead.Open(nil, sealed[:n], sealed[n:], aad)
}
func (m *sharingMailbox) aad(grant string, generation int64, id string) []byte {
	b, _ := json.Marshal(sharingMailboxAAD{m.binding, grant, generation, id})
	return b
}
func (m *sharingMailbox) receive(ctx context.Context, message sdk.SharingMessage) error {
	material, err := message.ExportReplyMaterial()
	if err != nil {
		return err
	}
	return m.put(ctx, sharingMailboxRecord{message, message.TextBody(), material})
}
func (m *sharingMailbox) put(ctx context.Context, record sharingMailboxRecord) error {
	msg := record.Message
	if msg.GrantID == "" || msg.Generation <= 0 || msg.ID == "" || msg.RecipientPrincipalID != m.binding.ServiceID || len(record.ReplyMaterial) == 0 {
		return errors.New("sharing mailbox message invalid")
	}
	plain, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if len(plain) > sharingMailboxMaxRecord {
		return errors.New("sharing mailbox record full")
	}
	aad := m.aad(msg.GrantID, msg.Generation, msg.ID)
	m.mu.Lock()
	defer m.mu.Unlock()
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var synchronous int
	if err = tx.QueryRowContext(ctx, "PRAGMA synchronous").Scan(&synchronous); err != nil {
		return err
	}
	if synchronous != 3 {
		return errors.New("sharing mailbox durability unavailable")
	}
	var previous []byte
	err = tx.QueryRowContext(ctx, "SELECT sealed FROM inbound WHERE grant_id=? AND generation=? AND message_id=?", msg.GrantID, msg.Generation, msg.ID).Scan(&previous)
	if err == nil {
		prior, err := m.unseal(previous, aad)
		if err != nil {
			return err
		}
		if !bytes.Equal(prior, plain) {
			return errors.New("sharing mailbox message conflict")
		}
		return tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	sealed, err := m.seal(plain, aad)
	if err != nil {
		return err
	}
	var count, total int64
	if err = tx.QueryRowContext(ctx, "SELECT count(*), coalesce(sum(length(sealed)),0) FROM inbound").Scan(&count, &total); err != nil {
		return err
	}
	if count >= sharingMailboxMaxCount || total+int64(len(sealed)) > sharingMailboxMaxBytes {
		return errors.New("sharing mailbox full")
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO inbound(grant_id,generation,message_id,sealed) VALUES(?,?,?,?)", msg.GrantID, msg.Generation, msg.ID, sealed); err != nil {
		return err
	}
	return tx.Commit()
}

// load authenticates the stored scope before exposing content or reply material.
// It is deliberately local; no browser/owner mailbox endpoint is installed.
func (m *sharingMailbox) load(ctx context.Context, grant string, generation int64, id string) (sharingMailboxRecord, error) {
	var out sharingMailboxRecord
	var sealed []byte
	if err := m.db.QueryRowContext(ctx, "SELECT sealed FROM inbound WHERE grant_id=? AND generation=? AND message_id=?", grant, generation, id).Scan(&sealed); err != nil {
		return out, err
	}
	plain, err := m.unseal(sealed, m.aad(grant, generation, id))
	if err != nil {
		return out, err
	}
	err = json.Unmarshal(plain, &out)
	return out, err
}
