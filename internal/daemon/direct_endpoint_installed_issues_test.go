//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
)

type installedIssuesFixture struct {
	registry                 *NativeWorkerRegistry
	table                    string
	session                  transport.HostSessionPayload
	subject                  nativeManagedSubject
	discover                 func(context.Context, string, transport.HostSessionPayload, nativeManagedSubject, installedCredentialIssueCursor) ([]any, installedCredentialIssueCursor, bool, error)
	reopen                   func()
	now                      func(time.Time)
	installExpiry, useExpiry time.Time
	secretPath               string
}

func newInstalledIssuesFixture(t *testing.T, role string) *installedIssuesFixture {
	t.Helper()
	f := &installedIssuesFixture{}
	if role == "source" {
		keys, issue, session := directSourceCredentialFixtureV2(t)
		if _, err := keys.InstallCredential(issue, "https://example.test", session, directSourceCredentialScopeOKV2, directSourceCredentialFenceOKV2); err != nil {
			t.Fatal(err)
		}
		f.registry, f.table, f.session = keys.registry, "native_direct_managed_source_v2_credentials", session
		f.subject = nativeManagedSubjectFromSourceV2(issue.PoP.Prepare.Subject)
		f.installExpiry, f.useExpiry = issue.InstallExpiresAt, issue.CredentialExpiresAt
		f.secretPath = directSourceCredentialPathV2(keys, issue)
		f.reopen = func() {
			var err error
			keys, err = NewDirectManagedSourceKeyStoreV2(f.registry)
			if err != nil {
				t.Fatal(err)
			}
		}
		f.now = func(now time.Time) { keys.now = func() time.Time { return now } }
		f.discover = func(ctx context.Context, server string, session transport.HostSessionPayload, subject nativeManagedSubject, cursor installedCredentialIssueCursor) ([]any, installedCredentialIssueCursor, bool, error) {
			issues, next, more, err := keys.installedCredentialIssuesContext(ctx, server, session, subject, cursor)
			out := make([]any, len(issues))
			for i := range issues {
				out[i] = issues[i]
			}
			return out, next, more, err
		}
	} else {
		keys, issue, session, _ := managedCredentialStoreFixture(t)
		installManagedCredential(t, keys, issue, session)
		f.registry, f.table, f.session = keys.registry, "native_managed_direct_v1_credentials", session
		f.subject = nativeManagedSubjectFromEndpoint(issue.PoP.Prepare.Subject)
		f.installExpiry, f.useExpiry = issue.InstallExpiresAt, issue.CredentialExpiresAt
		f.secretPath = managedCredentialPath(keys, issue)
		f.reopen = func() {
			var err error
			keys, err = NewManagedEndpointKeyStore(f.registry)
			if err != nil {
				t.Fatal(err)
			}
		}
		f.now = func(now time.Time) { keys.now = func() time.Time { return now } }
		f.discover = func(ctx context.Context, server string, session transport.HostSessionPayload, subject nativeManagedSubject, cursor installedCredentialIssueCursor) ([]any, installedCredentialIssueCursor, bool, error) {
			issues, next, more, err := keys.installedCredentialIssuesContext(ctx, server, session, subject, cursor)
			out := make([]any, len(issues))
			for i := range issues {
				out[i] = issues[i]
			}
			return out, next, more, err
		}
	}
	return f
}

func (f *installedIssuesFixture) scan(ctx context.Context) ([]any, installedCredentialIssueCursor, bool, error) {
	return f.discover(ctx, "https://example.test", f.session, f.subject, installedCredentialIssueCursor{})
}

func TestInstalledCredentialIssuesRestartAndPublicOnly(t *testing.T) {
	for _, role := range []string{"source", "target"} {
		t.Run(role, func(t *testing.T) {
			f := newInstalledIssuesFixture(t, role)
			before, _, more, err := f.scan(context.Background())
			if err != nil || len(before) != 1 || more {
				t.Fatalf("initial discovery: count=%d more=%v err=%v", len(before), more, err)
			}
			f.reopen()
			after, _, _, err := f.scan(context.Background())
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatalf("restart lost installed issue: %v", err)
			}
			// Public recovery must neither require nor repair secret material.
			if err := os.Remove(f.secretPath); err != nil {
				t.Fatal(err)
			}
			var retained []byte
			if err := f.registry.db.QueryRow("SELECT issue FROM " + f.table).Scan(&retained); err != nil {
				t.Fatal(err)
			}
			after, _, _, err = f.scan(context.Background())
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatalf("missing secret prevented public recovery: %v", err)
			}
			if _, err := os.Lstat(f.secretPath); !os.IsNotExist(err) {
				t.Fatalf("discovery recreated secret: %v", err)
			}
			var current []byte
			if err := f.registry.db.QueryRow("SELECT issue FROM " + f.table).Scan(&current); err != nil || !bytes.Equal(retained, current) {
				t.Fatalf("discovery mutated issue: %v", err)
			}
		})
	}
}

func TestInstalledCredentialIssuesScopeAndLifetime(t *testing.T) {
	for _, role := range []string{"source", "target"} {
		t.Run(role, func(t *testing.T) {
			for _, mismatch := range []string{"server", "session", "subject"} {
				t.Run(mismatch, func(t *testing.T) {
					f := newInstalledIssuesFixture(t, role)
					server, session, subject := "https://example.test", f.session, f.subject
					switch mismatch {
					case "server":
						server = "https://other.test"
					case "session":
						session.RunnerID = domain.NewID().String()
					case "subject":
						subject.InstanceID = domain.NewID()
					}
					got, _, _, err := f.discover(context.Background(), server, session, subject, installedCredentialIssueCursor{})
					if len(got) != 0 || (mismatch == "session" && err != errInstalledCredentialIssues) || (mismatch != "session" && err != nil) {
						t.Fatalf("scope mismatch: count=%d err=%v", len(got), err)
					}
				})
			}
			t.Run("native-enrollment-deadline-excluded", func(t *testing.T) {
				f := newInstalledIssuesFixture(t, role)
				_, cursor, _, err := f.scan(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				changed := f.subject
				changed.ExpiresAt = time.Time{}
				got, _, _, err := f.discover(context.Background(), "https://example.test", f.session, changed, installedCredentialIssueCursor{})
				if err != nil || len(got) != 1 {
					t.Fatalf("enrollment deadline entered native identity: count=%d err=%v", len(got), err)
				}
				if _, _, _, err := f.discover(context.Background(), "https://example.test", f.session, changed, cursor); err != nil {
					t.Fatalf("enrollment deadline entered cursor scope: %v", err)
				}
			})
			t.Run("installation-expired", func(t *testing.T) {
				f := newInstalledIssuesFixture(t, role)
				f.now(f.installExpiry.Add(time.Nanosecond))
				got, _, _, err := f.scan(context.Background())
				if err != nil || len(got) != 1 {
					t.Fatalf("installation deadline hid usable issue: count=%d err=%v", len(got), err)
				}
				f.now(f.useExpiry)
				got, _, _, err = f.scan(context.Background())
				if err != nil || len(got) != 0 {
					t.Fatalf("expired issue discovered: count=%d err=%v", len(got), err)
				}
			})
			t.Run("attempted", func(t *testing.T) {
				f := newInstalledIssuesFixture(t, role)
				if _, err := f.registry.db.Exec("UPDATE " + f.table + " SET state='attempted',credential_hash=NULL,ack=NULL"); err != nil {
					t.Fatal(err)
				}
				got, _, _, err := f.scan(context.Background())
				if err != nil || len(got) != 0 {
					t.Fatalf("attempted issue discovered: count=%d err=%v", len(got), err)
				}
			})
		})
	}
}

func TestInstalledCredentialIssuesCorruption(t *testing.T) {
	for _, role := range []string{"source", "target"} {
		t.Run(role, func(t *testing.T) {
			var fixedError string
			for _, mutation := range []string{"issue=x'00'", "issue_digest=zeroblob(32)", "ack=x'00'", "credential_hash='gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg'"} {
				t.Run(mutation, func(t *testing.T) {
					f := newInstalledIssuesFixture(t, role)
					if _, err := f.registry.db.Exec("UPDATE " + f.table + " SET " + mutation); err != nil {
						t.Fatal(err)
					}
					got, _, _, err := f.scan(context.Background())
					if err == nil || len(got) != 0 {
						t.Fatalf("corruption returned partial success: count=%d err=%v", len(got), err)
					}
					if fixedError == "" {
						fixedError = err.Error()
					} else if fixedError != err.Error() {
						t.Fatalf("corruption exposed varying errors: %q versus %q", fixedError, err)
					}
				})
			}
		})
	}
}

func TestInstalledCredentialIssuesCursorRejectsOtherScope(t *testing.T) {
	for _, role := range []string{"source", "target"} {
		t.Run(role, func(t *testing.T) {
			f := newInstalledIssuesFixture(t, role)
			_, cursor, _, err := f.scan(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			other := f.subject
			other.InstanceID = domain.NewID()
			got, _, _, err := f.discover(context.Background(), "https://example.test", f.session, other, cursor)
			if err == nil || len(got) != 0 {
				t.Fatalf("cursor reused for different subject: count=%d err=%v", len(got), err)
			}
			cursor.table = "wrong-role"
			got, _, _, err = f.discover(context.Background(), "https://example.test", f.session, f.subject, cursor)
			if err == nil || len(got) != 0 {
				t.Fatalf("cursor reused for different role: count=%d err=%v", len(got), err)
			}
		})
	}
}

func TestInstalledCredentialIssuesContextAcquisition(t *testing.T) {
	for _, role := range []string{"source", "target"} {
		t.Run(role, func(t *testing.T) {
			for _, held := range []string{"canceled", "registry", "sql-connection", "sql-writer"} {
				t.Run(held, func(t *testing.T) {
					f := newInstalledIssuesFixture(t, role)
					release := func() {}
					if held == "registry" {
						f.registry.mu.Lock()
						release = f.registry.mu.Unlock
					}
					if held == "sql-connection" {
						conn, err := f.registry.db.Conn(context.Background())
						if err != nil {
							t.Fatal(err)
						}
						release = func() { _ = conn.Close() }
					}
					if held == "sql-writer" {
						db, err := sql.Open("sqlite", filepath.Join(f.registry.root, "registry.sqlite"))
						if err != nil {
							t.Fatal(err)
						}
						if _, err := db.Exec("BEGIN IMMEDIATE"); err != nil {
							db.Close()
							t.Fatal(err)
						}
						release = func() { _, _ = db.Exec("ROLLBACK"); _ = db.Close() }
					}
					ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
					defer cancel()
					if held == "canceled" {
						cancel()
					}
					start := time.Now()
					got, _, _, err := f.scan(ctx)
					release()
					if err == nil || len(got) != 0 {
						t.Fatalf("blocked discovery succeeded: count=%d err=%v", len(got), err)
					}
					if time.Since(start) > time.Second {
						t.Fatal("discovery ignored acquisition deadline")
					}
					got, _, _, err = f.scan(context.Background())
					if err != nil || len(got) != 1 {
						t.Fatalf("failed scan poisoned retry: count=%d err=%v", len(got), err)
					}
				})
			}
		})
	}
}

func TestInstalledCredentialIssuesPaginationPinsHighWatermark(t *testing.T) {
	for _, role := range []string{"source", "target"} {
		t.Run(role, func(t *testing.T) {
			f := newInstalledIssuesFixture(t, role)
			binding := "binding_id"
			if role == "target" {
				binding = "enrollment_id"
			}
			if _, err := f.registry.db.Exec("UPDATE " + f.table + " SET rowid=66"); err != nil {
				t.Fatal(err)
			}
			insert := "INSERT INTO " + f.table + "(rowid,credential_id," + binding + ",direct_intent_id,installation_id,issue,issue_digest,state) SELECT ?,?,?,?,installation_id,x'00',zeroblob(32),'attempted' FROM " + f.table + " WHERE rowid=66"
			for i := 1; i <= 65; i++ {
				if _, err := f.registry.db.Exec(insert, i, domain.NewID(), domain.NewID(), domain.NewID()); err != nil {
					t.Fatal(err)
				}
			}
			got, cursor, more, err := f.scan(context.Background())
			if err != nil || len(got) != 0 || !more || cursor.afterRowID != 64 || cursor.maxRowID != 66 {
				t.Fatalf("first bounded page: count=%d cursor=%+v more=%v err=%v", len(got), cursor, more, err)
			}
			// Rows installed after the initial query belong to the next pass.
			if _, err := f.registry.db.Exec(insert, 1000, domain.NewID(), domain.NewID(), domain.NewID()); err != nil {
				t.Fatal(err)
			}
			got, cursor, more, err = f.discover(context.Background(), "https://example.test", f.session, f.subject, cursor)
			if err != nil || len(got) != 1 || more || cursor.afterRowID != 66 || cursor.maxRowID != 66 {
				t.Fatalf("candidate after attempted page: count=%d cursor=%+v more=%v err=%v", len(got), cursor, more, err)
			}
			got, cursor, more, err = f.discover(context.Background(), "https://example.test", f.session, f.subject, cursor)
			if err != nil || len(got) != 0 || more || cursor.maxRowID != 66 {
				t.Fatalf("completed cursor included new row: count=%d cursor=%+v more=%v err=%v", len(got), cursor, more, err)
			}
		})
	}
}

func TestInstalledCredentialIssuesCorruptionDiscardsWholePage(t *testing.T) {
	for _, role := range []string{"source", "target"} {
		t.Run(role, func(t *testing.T) {
			f := newInstalledIssuesFixture(t, role)
			binding := "binding_id"
			if role == "target" {
				binding = "enrollment_id"
			}
			query := "INSERT INTO " + f.table + "(credential_id," + binding + ",direct_intent_id,installation_id,issue,issue_digest,state,credential_hash,ack) SELECT ?,?,?,installation_id,x'00',issue_digest,state,credential_hash,ack FROM " + f.table
			if _, err := f.registry.db.Exec(query, domain.NewID(), domain.NewID(), domain.NewID()); err != nil {
				t.Fatal(err)
			}
			got, cursor, more, err := f.scan(context.Background())
			if err != errInstalledCredentialIssues || len(got) != 0 || more || cursor != (installedCredentialIssueCursor{}) {
				t.Fatalf("partial corrupted page escaped: count=%d cursor=%+v more=%v err=%v", len(got), cursor, more, err)
			}
		})
	}
}

func TestInstalledCredentialIssuesDuplicateRows(t *testing.T) {
	for _, role := range []string{"source", "target"} {
		t.Run(role, func(t *testing.T) {
			f := newInstalledIssuesFixture(t, role)
			// Rebuild the public table without its constraints to model a damaged registry.
			for _, query := range []string{
				"ALTER TABLE " + f.table + " RENAME TO installed_issues_original",
				"CREATE TABLE " + f.table + " AS SELECT * FROM installed_issues_original",
				"INSERT INTO " + f.table + " SELECT * FROM installed_issues_original",
			} {
				if _, err := f.registry.db.Exec(query); err != nil {
					t.Fatal(err)
				}
			}
			got, cursor, more, err := f.scan(context.Background())
			if err != errInstalledCredentialIssues || len(got) != 0 || more || cursor != (installedCredentialIssueCursor{}) {
				t.Fatalf("duplicate rows escaped: count=%d cursor=%+v more=%v err=%v", len(got), cursor, more, err)
			}
		})
	}
}
