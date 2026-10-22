package daemon

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/pagnet-code/pagnet/sdk"
)

func mailboxFixture(t *testing.T) (*sharingMailbox, string, sharingMailboxBinding, sharingMailboxRecord) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "mailbox")
	binding := sharingMailboxBinding{"installation", "service", "tenant", "host"}
	m, err := openSharingMailbox(dir, binding)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.db.Close() })
	msg := sdk.SharingMessage{GrantID: "grant", Generation: 1, Message: sdk.Message{ID: "message", RecipientPrincipalID: "service", SenderPrincipalID: "sender", Parts: []sdk.MessagePart{sdk.TextPart("private inbound")}}}
	return m, dir, binding, sharingMailboxRecord{msg, msg.TextBody(), []byte("opaque reply material")}
}
func TestSharingMailboxDurableDuplicateBoundary(t *testing.T) {
	m, dir, binding, record := mailboxFixture(t)
	ctx := context.Background()
	if err := m.put(ctx, record); err != nil {
		t.Fatal(err)
	}
	if err := m.put(ctx, record); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := m.db.QueryRow("SELECT count(*) FROM inbound").Scan(&count); err != nil || count != 1 {
		t.Fatalf("count=%d error=%v", count, err)
	}
	changed := record
	changed.Text = "conflicting authenticated content"
	if err := m.put(ctx, changed); err == nil {
		t.Fatal("conflicting retry acknowledged")
	}
	if err := m.db.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := openSharingMailbox(dir, binding)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.db.Close()
	restored, err := restarted.load(ctx, "grant", 1, "message")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restored.ReplyMaterial, record.ReplyMaterial) || restored.Text != record.Text || restored.Message.TextBody() != record.Text {
		t.Fatal("restart lost display or reply material")
	}
	if err := restarted.put(ctx, record); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "inbound.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(record.Text)) || bytes.Contains(raw, record.ReplyMaterial) {
		t.Fatal("plaintext stored in database")
	}
	for _, name := range []string{"key", "inbound.sqlite"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("%s permissions: %v %v", name, info, err)
		}
	}
	info, err := os.Stat(dir)
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatal("mailbox directory permissions")
	}
}
func TestSharingMailboxTamperAndBinding(t *testing.T) {
	for _, kind := range []string{"ciphertext", "grant", "generation", "message", "service", "installation", "tenant", "host", "key loss", "short key", "wrong key"} {
		t.Run(kind, func(t *testing.T) {
			m, dir, binding, record := mailboxFixture(t)
			ctx := context.Background()
			if err := m.put(ctx, record); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "ciphertext":
				if _, err := m.db.Exec("UPDATE inbound SET sealed=zeroblob(length(sealed))"); err != nil {
					t.Fatal(err)
				}
				if _, err := m.load(ctx, "grant", 1, "message"); err == nil {
					t.Fatal("tamper accepted")
				}
				if err := m.put(ctx, record); err == nil {
					t.Fatal("tamper duplicate acknowledged")
				}
				return
			case "grant", "generation", "message":
				column, value := "grant_id", any("other")
				if kind == "generation" {
					column, value = "generation", int64(2)
				}
				if kind == "message" {
					column = "message_id"
				}
				if _, err := m.db.Exec("UPDATE inbound SET "+column+"=?", value); err != nil {
					t.Fatal(err)
				}
				grant, generation, id := "grant", int64(1), "message"
				if kind == "grant" {
					grant = "other"
				}
				if kind == "generation" {
					generation = 2
				}
				if kind == "message" {
					id = "other"
				}
				if _, err := m.load(ctx, grant, generation, id); err == nil {
					t.Fatal("scope substitution accepted")
				}
				return
			case "service":
				binding.ServiceID = "other"
			case "installation":
				binding.InstallationID = "other"
			case "tenant":
				binding.TenantID = "other"
			case "host":
				binding.HostID = "other"
			}
			m.db.Close()
			keyPath := filepath.Join(dir, "key")
			switch kind {
			case "key loss":
				if err := os.Remove(keyPath); err != nil {
					t.Fatal(err)
				}
			case "short key":
				if err := os.WriteFile(keyPath, []byte("short"), 0600); err != nil {
					t.Fatal(err)
				}
			case "wrong key":
				if err := os.WriteFile(keyPath, make([]byte, 32), 0600); err != nil {
					t.Fatal(err)
				}
			}
			reopened, err := openSharingMailbox(dir, binding)
			if err == nil {
				reopened.db.Close()
				t.Fatal("unavailable key or changed scope accepted")
			}
			if kind == "key loss" {
				if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
					t.Fatal("lost key silently regenerated")
				}
			}
		})
	}
}
func TestSharingMailboxCapsAndStorageFailure(t *testing.T) {
	for _, kind := range []string{"count", "bytes", "record", "database closed", "read only", "forged SDK message"} {
		t.Run(kind, func(t *testing.T) {
			m, _, _, record := mailboxFixture(t)
			ctx := context.Background()
			switch kind {
			case "count":
				_, err := m.db.Exec("WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x < ?) INSERT INTO inbound SELECT 'full',1,cast(x AS TEXT),x'00' FROM n", sharingMailboxMaxCount)
				if err != nil {
					t.Fatal(err)
				}
			case "bytes":
				// Fill with bounded chunks; SQLite's independent physical cap also applies.
				for i := 0; i < 64; i++ {
					if _, err := m.db.Exec("INSERT INTO inbound VALUES('full',1,?,zeroblob(?))", i, 1<<20); err != nil {
						t.Fatal(err)
					}
				}
			case "record":
				record.Text = string(bytes.Repeat([]byte("x"), sharingMailboxMaxRecord))
			case "database closed":
				m.db.Close()
			case "read only":
				if _, err := m.db.Exec("PRAGMA query_only=ON"); err != nil {
					t.Fatal(err)
				}
			case "forged SDK message":
				if err := m.receive(ctx, record.Message); err == nil {
					t.Fatal("unvalidated SDK message acknowledged")
				}
				return
			}
			if err := m.put(ctx, record); err == nil {
				t.Fatal("failed or full storage acknowledged")
			}
		})
	}
}
func TestSharingMailboxRetirePreservesHistory(t *testing.T) {
	m, dir, binding, record := mailboxFixture(t)
	if err := m.put(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	m.db.Close()
	// Production mailbox is a sibling of sdk under the installation directory.
	if err := retireSharingBridge(filepath.Dir(dir)); err != nil {
		t.Fatal(err)
	}
	restarted, err := openSharingMailbox(dir, binding)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.db.Close()
	if _, err := restarted.load(context.Background(), "grant", 1, "message"); err != nil {
		t.Fatal(err)
	}
}

func TestSharingMailboxInterruptedInitialization(t *testing.T) {
	for _, stage := range []string{"empty", "schema", "bound"} {
		t.Run(stage, func(t *testing.T) {
			dir := t.TempDir()
			binding := sharingMailboxBinding{"installation", "service", "tenant", "host"}
			key, err := sharingMailboxKey(dir, false)
			if err != nil {
				t.Fatal(err)
			}
			// Simulate a process dying before the initialized temporary database is
			// published. No established path has existed, and no receipt was ACKed.
			temporary := filepath.Join(dir, ".inbound-interrupted")
			if err := os.WriteFile(temporary, nil, 0600); err != nil {
				t.Fatal(err)
			}
			if stage == "schema" {
				db, err := sql.Open("sqlite", temporary)
				if err != nil {
					t.Fatal(err)
				}
				_, err = db.Exec("CREATE TABLE mailbox_binding (id INTEGER PRIMARY KEY, sealed BLOB NOT NULL)")
				db.Close()
				if err != nil {
					t.Fatal(err)
				}
			}
			if stage == "bound" {
				// Build a complete unpublished database using the real initializer.
				if err := os.Remove(temporary); err != nil {
					t.Fatal(err)
				}
				unpublished, err := openSharingMailbox(filepath.Join(dir, "unpublished"), binding)
				if err != nil {
					t.Fatal(err)
				}
				unpublished.db.Close()
				if err := os.Rename(filepath.Join(dir, "unpublished", "inbound.sqlite"), temporary); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := os.Stat(filepath.Join(dir, "inbound.sqlite")); !os.IsNotExist(err) {
				t.Fatal("established database appeared before publication")
			}
			recovered, err := openSharingMailbox(dir, binding)
			if err != nil {
				t.Fatal(err)
			}
			recovered.db.Close()
			retained, err := os.ReadFile(filepath.Join(dir, "key"))
			if err != nil || !bytes.Equal(key, retained) {
				t.Fatal("interrupted initialization replaced existing key")
			}
			restarted, err := openSharingMailbox(dir, binding)
			if err != nil {
				t.Fatal(err)
			}
			restarted.db.Close()
		})
	}
}
func TestSharingMailboxInitializationFailureDoesNotPublish(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "inbound.sqlite")
	interrupted := errors.New("interrupted before binding commit")
	err := publishSharingMailboxDatabase(dir, path, func(temporary string) error {
		db, err := sql.Open("sqlite", temporary)
		if err != nil {
			return err
		}
		defer db.Close()
		if _, err = db.Exec("CREATE TABLE mailbox_binding (id INTEGER PRIMARY KEY, sealed BLOB NOT NULL)"); err != nil {
			return err
		}
		if _, err = os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("unbound database published during initialization")
		}
		return interrupted
	})
	if !errors.Is(err, interrupted) {
		t.Fatalf("initialization failure: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("failed initialization left established unbound database")
	}
	recovered, err := openSharingMailbox(dir, sharingMailboxBinding{"installation", "service", "tenant", "host"})
	if err != nil {
		t.Fatal(err)
	}
	recovered.db.Close()
}

func TestSharingMailboxEstablishedMissingBindingFailsClosed(t *testing.T) {
	m, dir, binding, _ := mailboxFixture(t)
	if _, err := m.db.Exec("DELETE FROM mailbox_binding"); err != nil {
		t.Fatal(err)
	}
	m.db.Close()
	if reopened, err := openSharingMailbox(dir, binding); err == nil {
		reopened.db.Close()
		t.Fatal("established missing binding regenerated")
	}
}
func TestSharingMailboxExtraSynchronousEveryConnection(t *testing.T) {
	m, _, _, record := mailboxFixture(t)
	// Force database/sql to replace the physical connection between operations.
	m.db.SetMaxIdleConns(0)
	for i := 0; i < 3; i++ {
		var synchronous int
		if err := m.db.QueryRow("PRAGMA synchronous").Scan(&synchronous); err != nil || synchronous != 3 {
			t.Fatalf("synchronous=%d err=%v", synchronous, err)
		}
		if err := m.put(context.Background(), record); err != nil {
			t.Fatal(err)
		}
	}
	m.db.SetMaxIdleConns(1)
	if _, err := m.db.Exec("PRAGMA synchronous=FULL"); err != nil {
		t.Fatal(err)
	}
	if err := m.put(context.Background(), record); err == nil {
		t.Fatal("weakened synchronous mode acknowledged duplicate")
	}
}
func TestPrepareSharingBridgeDirDurability(t *testing.T) {
	stateDir := t.TempDir()
	var synced []string
	dir, err := prepareSharingBridgeDir(stateDir, "installation", func(path string) error {
		if _, err := os.Stat(filepath.Join(stateDir, "sharing-bridges", "installation")); err != nil {
			return err
		}
		synced = append(synced, path)
		return syncSharingMailboxDir(path)
	})
	if err != nil {
		t.Fatal(err)
	}
	if dir != filepath.Join(stateDir, "sharing-bridges", "installation") || !reflect.DeepEqual(synced, []string{stateDir, filepath.Join(stateDir, "sharing-bridges")}) {
		t.Fatalf("directory sync chain: %v", synced)
	}
	failure := errors.New("directory fsync failed")
	if _, err := prepareSharingBridgeDir(stateDir, "other", func(string) error { return failure }); !errors.Is(err, failure) {
		t.Fatal("directory sync failure ignored")
	}
}
