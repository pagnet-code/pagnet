//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type endpointMaterialContextFixture struct {
	registry                   *NativeWorkerRegistry
	namespace, credential, key string
	call                       func(context.Context, endpointMaterialFence, func(endpointMaterial) error) error
	unavailable                error
}

func endpointMaterialContextStore(t *testing.T, source bool) endpointMaterialContextFixture {
	t.Helper()
	if source {
		keys, issue, session := directSourceCredentialFixtureV2(t)
		if _, err := keys.InstallCredential(issue, "https://example.test", session, directSourceCredentialScopeOKV2, directSourceCredentialFenceOKV2); err != nil {
			t.Fatal(err)
		}
		store, err := newDirectManagedSourceKeyStoreV2Context(context.Background(), keys.registry)
		if err != nil {
			t.Fatal(err)
		}
		store.now = func() time.Time { return issue.InstallExpiresAt.Add(time.Nanosecond) }
		return endpointMaterialContextFixture{
			registry: keys.registry, namespace: nativeDirectManagedSourceKeyNamespaceV2,
			credential:  directSourceCredentialPathV2(keys, issue),
			key:         filepath.Join(keys.registry.root, nativeDirectManagedSourceKeyNamespaceV2, directManagedSourceKeyScopeV2(keys.installation, "https://example.test", issue.PoP.Prepare.Subject)+".json"),
			unavailable: errDirectManagedSourceKeyV2,
			call: func(ctx context.Context, fence endpointMaterialFence, use func(endpointMaterial) error) error {
				return store.withDirectManagedSourceEndpointMaterialV2Context(ctx, issue, "https://example.test", session, endpointMaterialScope{store.installation, issue.CredentialID, "S", endpointMaterialLiveUse}, directSourceCredentialScopeOKV2, fence, use)
			},
		}
	}
	keys, issue, session, _ := managedCredentialStoreFixture(t)
	if _, err := keys.InstallCredential(issue, "https://example.test", session, managedCredentialScopeOK, managedCredentialFenceOK); err != nil {
		t.Fatal(err)
	}
	store, err := newManagedEndpointKeyStoreContext(context.Background(), keys.registry)
	if err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return issue.InstallExpiresAt.Add(time.Nanosecond) }
	return endpointMaterialContextFixture{
		registry: keys.registry, namespace: nativeManagedEndpointKeyNamespace,
		credential:  managedCredentialPath(keys, issue),
		key:         filepath.Join(keys.registry.root, nativeManagedEndpointKeyNamespace, managedEndpointKeyScope(keys.installation, "https://example.test", issue.PoP.Prepare.Subject)+".json"),
		unavailable: errManagedEndpointKey,
		call: func(ctx context.Context, fence endpointMaterialFence, use func(endpointMaterial) error) error {
			return store.withManagedTargetEndpointMaterialContext(ctx, issue, "https://example.test", session, endpointMaterialScope{store.installation, issue.CredentialID, "P", endpointMaterialLiveUse}, managedCredentialScopeOK, fence, use)
		},
	}
}

func TestEndpointMaterialContextAcquisition(t *testing.T) {
	for _, source := range []bool{false, true} {
		for _, held := range []string{"registry", "namespace", "sql writer", "sql connection", "canceled"} {
			t.Run(map[bool]string{false: "target", true: "source"}[source]+"/"+held, func(t *testing.T) {
				f := endpointMaterialContextStore(t, source)
				before, err := os.ReadFile(f.credential)
				if err != nil {
					t.Fatal(err)
				}
				defer clear(before)
				release := func() {}
				switch held {
				case "registry":
					f.registry.mu.Lock()
					release = f.registry.mu.Unlock
				case "namespace":
					directEndpointHoldChildFlock(t, filepath.Join(f.registry.root, f.namespace, "holder.lock"))
				case "sql writer":
					db, err := sql.Open("sqlite", filepath.Join(f.registry.root, "registry.sqlite"))
					if err != nil {
						t.Fatal(err)
					}
					if _, err := db.Exec("BEGIN IMMEDIATE"); err != nil {
						db.Close()
						t.Fatal(err)
					}
					release = func() { _, _ = db.Exec("ROLLBACK"); db.Close() }
				case "sql connection":
					conn, err := f.registry.db.Conn(context.Background())
					if err != nil {
						t.Fatal(err)
					}
					release = func() { conn.Close() }
				}
				ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
				defer cancel()
				if held == "canceled" {
					cancel()
				}
				start := time.Now()
				err = f.call(ctx, func(*sql.Conn) (func(), func() error, error) {
					t.Error("failed acquisition reached fence")
					return endpointMaterialFenceOK(nil)
				}, func(endpointMaterial) error { t.Error("failed acquisition exposed material"); return nil })
				release()
				if err != f.unavailable {
					t.Fatalf("failed acquisition: %v", err)
				}
				if time.Since(start) > time.Second {
					t.Fatal("local acquisition waited")
				}
				after, err := os.ReadFile(f.credential)
				if err != nil {
					t.Fatal(err)
				}
				defer clear(after)
				if !bytes.Equal(before, after) {
					t.Fatal("failed acquisition changed retained bytes")
				}
				var timeout int
				if err := f.registry.db.QueryRow("PRAGMA busy_timeout").Scan(&timeout); err != nil || timeout != 5000 {
					t.Fatalf("timeout not restored: %d %v", timeout, err)
				}
			})
		}
	}
}

func TestEndpointMaterialContextLifetime(t *testing.T) {
	for _, source := range []bool{false, true} {
		for _, kind := range []string{"live", "cancel in fence", "cancel in check", "cancel after use", "callback error", "panic"} {
			t.Run(map[bool]string{false: "target", true: "source"}[source]+"/"+kind, func(t *testing.T) {
				f := endpointMaterialContextStore(t, source)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				called, released := false, false
				var secret, private []byte
				fence := func(conn *sql.Conn) (func(), func() error, error) {
					if kind == "cancel in fence" {
						cancel()
					}
					return func() {
						released = true
						var timeout int
						if err := conn.QueryRowContext(context.Background(), "PRAGMA busy_timeout").Scan(&timeout); err != nil || timeout != 5000 {
							t.Errorf("fence released before timeout restoration: %d %v", timeout, err)
						}
						if _, err := conn.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err != nil {
							t.Errorf("fence released before transaction cleanup: %v", err)
						} else {
							_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
						}
					}, func() error {
						if kind == "cancel in check" {
							cancel()
						}
						return nil
					}, nil
				}
				var recovered any
				var err error
				func() {
					defer func() { recovered = recover() }()
					err = f.call(ctx, fence, func(m endpointMaterial) error {
						called = true
						secret, private = m.secret, m.private
						if len(secret) != 32 || len(private) != 32 {
							t.Error("invalid material length")
						}
						switch kind {
						case "cancel after use":
							cancel()
						case "callback error":
							return errors.New(string(m.secret))
						case "panic":
							panic("interrupted")
						}
						return nil
					})
				}()
				if kind == "panic" {
					if recovered != "interrupted" {
						t.Fatal("missing callback panic")
					}
				} else if recovered != nil || (err == nil) != (kind == "live") {
					t.Fatalf("unexpected outcome: %v", err)
				}
				if called != (kind != "cancel in fence" && kind != "cancel in check") || !released {
					t.Fatal("callback or release lifecycle changed")
				}
				if !bytes.Equal(secret, make([]byte, len(secret))) || !bytes.Equal(private, make([]byte, len(private))) {
					t.Fatal("material escaped scope")
				}
				if err != nil && err != f.unavailable {
					t.Fatal("private callback error escaped")
				}
			})
		}
	}
}

func TestEndpointMaterialContextConstructors(t *testing.T) {
	r, err := OpenNativeWorkerRegistry(registryCustodyState(t))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	var journalsBefore int
	if err := r.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master`).Scan(&journalsBefore); err != nil {
		t.Fatal(err)
	}
	for _, constructor := range []func(context.Context) error{
		func(ctx context.Context) error { _, err := newManagedEndpointKeyStoreContext(ctx, r); return err },
		func(ctx context.Context) error { _, err := newDirectManagedSourceKeyStoreV2Context(ctx, r); return err },
	} {
		before, err := os.ReadDir(r.root)
		if err != nil {
			t.Fatal(err)
		}
		if err := constructor(context.Background()); err != nil {
			t.Fatal(err)
		}
		after, err := os.ReadDir(r.root)
		if err != nil {
			t.Fatal(err)
		}
		if len(before) != len(after) {
			t.Fatal("constructor created unrelated namespace")
		}
		var journals int
		if err := r.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master`).Scan(&journals); err != nil || journals != journalsBefore {
			t.Fatalf("constructor initialized unrelated journals: %d %v", journals, err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := constructor(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled constructor: %v", err)
		}
		r.mu.Lock()
		err = constructor(context.Background())
		r.mu.Unlock()
		if err != errDirectEndpointLocalBusy {
			t.Fatalf("held constructor: %v", err)
		}
	}
	if _, err := r.db.Exec(`UPDATE native_registry_metadata SET value='invalid' WHERE name='installation_id'`); err != nil {
		t.Fatal(err)
	}
	if keys, err := newManagedEndpointKeyStoreContext(context.Background(), r); keys != nil || err == nil {
		t.Fatal("invalid installation accepted by target")
	}
	if keys, err := newDirectManagedSourceKeyStoreV2Context(context.Background(), r); keys != nil || err == nil {
		t.Fatal("invalid installation accepted by source")
	}
}

func TestEndpointMaterialContextTamper(t *testing.T) {
	for _, source := range []bool{false, true} {
		for _, kind := range []string{"credential", "private key", "installation", "mode"} {
			t.Run(map[bool]string{false: "target", true: "source"}[source]+"/"+kind, func(t *testing.T) {
				f := endpointMaterialContextStore(t, source)
				var err error
				switch kind {
				case "credential":
					err = os.WriteFile(f.credential, []byte("corrupt"), 0600)
				case "private key":
					err = os.WriteFile(f.key, []byte("corrupt"), 0600)
				case "installation":
					_, err = f.registry.db.Exec(`UPDATE native_registry_metadata SET value='invalid' WHERE name='installation_id'`)
				case "mode":
					err = os.Chmod(f.credential, 0644)
				}
				if err != nil {
					t.Fatal(err)
				}
				if err := f.call(context.Background(), endpointMaterialFenceOK, func(endpointMaterial) error { t.Error("tampered custody exposed material"); return nil }); err != f.unavailable {
					t.Fatalf("tampered custody: %v", err)
				}
			})
		}
	}
}

func TestEndpointMaterialContextCleanup(t *testing.T) {
	for _, source := range []bool{false, true} {
		for _, failure := range []string{"COMMIT", "ROLLBACK", "PRAGMA busy_timeout=5000"} {
			t.Run(map[bool]string{false: "target", true: "source"}[source]+"/"+failure, func(t *testing.T) {
				f := endpointMaterialContextStore(t, source)
				connector := enrollmentContextWrap(t, &directEnrollmentJournal{registry: f.registry})
				connector.exec = func(ctx context.Context, query string, args []driver.NamedValue, next driver.ExecerContext) (driver.Result, error) {
					if query == failure {
						return nil, errors.New("injected cleanup failure")
					}
					return next.ExecContext(ctx, query, args)
				}
				released := false
				var secret, private []byte
				err := f.call(context.Background(), func(*sql.Conn) (func(), func() error, error) {
					return func() {
						released = true
						if failure != "COMMIT" && connector.closed.Load() != 1 {
							t.Error("fence released before failed connection was discarded")
						}
					}, func() error { return nil }, nil
				}, func(m endpointMaterial) error {
					secret, private = m.secret, m.private
					if failure == "ROLLBACK" {
						return errors.New("abort callback")
					}
					return nil
				})
				if err != f.unavailable || !released {
					t.Fatal("cleanup failure mishandled")
				}
				if !bytes.Equal(secret, make([]byte, len(secret))) || !bytes.Equal(private, make([]byte, len(private))) {
					t.Fatal("cleanup failure leaked material")
				}
				connector.exec = nil
				if _, err := f.registry.db.Exec("BEGIN IMMEDIATE"); err != nil {
					t.Fatal(err)
				}
				if _, err := f.registry.db.Exec("ROLLBACK"); err != nil {
					t.Fatal(err)
				}
				if failure == "COMMIT" {
					var timeout int
					if err := f.registry.db.QueryRow("PRAGMA busy_timeout").Scan(&timeout); err != nil || timeout != 5000 {
						t.Fatalf("timeout not restored: %d %v", timeout, err)
					}
				}
			})
		}
	}
}
