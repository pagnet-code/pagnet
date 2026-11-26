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
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/transport"
	"modernc.org/sqlite"
)

func enrollmentContextPayload(t *testing.T, j *directEnrollmentJournal) []byte {
	t.Helper()
	var raw []byte
	if err := j.registry.db.QueryRow(`SELECT payload FROM native_direct_enrollment_v1`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	return raw
}

func enrollmentContextTimeout(t *testing.T, j *directEnrollmentJournal) int {
	t.Helper()
	var timeout int
	if err := j.registry.db.QueryRow(`PRAGMA busy_timeout`).Scan(&timeout); err != nil {
		t.Fatal(err)
	}
	return timeout
}

func TestDirectEnrollmentContextAcquisition(t *testing.T) {
	for _, held := range []string{"registry", "custody", "namespace", "sql writer", "sql connection", "subscription", "canceled"} {
		t.Run(held, func(t *testing.T) {
			j, s, b, _ := enrollmentFixture(t)
			if _, err := j.reserve(s, b); err != nil {
				t.Fatal(err)
			}
			before := enrollmentContextPayload(t, j)
			release := func() {}
			switch held {
			case "registry":
				j.registry.mu.Lock()
				release = j.registry.mu.Unlock
			case "custody":
				directEndpointHoldChildFlock(t, filepath.Join(j.registry.root, "registry.custody.lock"))
			case "namespace":
				directEndpointHoldChildFlock(t, filepath.Join(j.registry.root, directEnrollmentNamespace, "holder.lock"))
			case "subscription":
				s.owner.mu.Lock()
				release = s.owner.mu.Unlock
			case "sql writer":
				db, err := sql.Open("sqlite", filepath.Join(j.registry.root, "registry.sqlite"))
				if err != nil {
					t.Fatal(err)
				}
				if _, err := db.Exec("BEGIN IMMEDIATE"); err != nil {
					db.Close()
					t.Fatal(err)
				}
				release = func() { _, _ = db.Exec("ROLLBACK"); db.Close() }
			case "sql connection":
				conn, err := j.registry.db.Conn(context.Background())
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
			_, err := j.materialContext(ctx, s, b, func() ([]byte, []byte, error) { t.Fatal("failed acquisition generated material"); return nil, nil, nil })
			release()
			if err == nil {
				t.Fatal("held acquisition succeeded")
			}
			if time.Since(start) > time.Second {
				t.Fatal("local acquisition waited")
			}
			if j.poisoned {
				t.Fatal("failed acquisition poisoned journal")
			}
			if !bytes.Equal(before, enrollmentContextPayload(t, j)) {
				t.Fatal("failed acquisition changed retained bytes")
			}
			if timeout := enrollmentContextTimeout(t, j); timeout != 5000 {
				t.Fatalf("timeout not restored: %d", timeout)
			}
		})
	}
}

func TestDirectEnrollmentContextCancellationRollback(t *testing.T) {
	j, s, b, v := enrollmentFixture(t)
	if _, err := j.reserveContext(context.Background(), s, b); err != nil {
		t.Fatal(err)
	}
	before := enrollmentContextPayload(t, j)
	ctx, cancel := context.WithCancel(context.Background())
	_, err := j.materialContext(ctx, s, b, func() ([]byte, []byte, error) {
		cancel()
		return bytes.Clone(v.EpochKey), bytes.Clone(v.Publication), nil
	})
	if !errors.Is(err, context.Canceled) || j.poisoned {
		t.Fatal("precommit cancellation mishandled")
	}
	if !bytes.Equal(before, enrollmentContextPayload(t, j)) {
		t.Fatal("cancellation changed retained bytes")
	}
	if timeout := enrollmentContextTimeout(t, j); timeout != 5000 {
		t.Fatalf("timeout not restored: %d", timeout)
	}
	if _, err := j.materialContext(context.Background(), s, b, func() ([]byte, []byte, error) { return bytes.Clone(v.EpochKey), bytes.Clone(v.Publication), nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := j.materialContext(context.Background(), s, b, func() ([]byte, []byte, error) { t.Fatal("retained material regenerated"); return nil, nil, nil }); err != nil {
		t.Fatal(err)
	}
}

// Wrap the real driver to inject exact transaction boundary failures while all
// journal schema, validation and retained-byte checks still use SQLite.
type enrollmentContextConnector struct {
	path   string
	opened atomic.Int32
	closed atomic.Int32
	exec   func(context.Context, string, []driver.NamedValue, driver.ExecerContext) (driver.Result, error)
}

func (c *enrollmentContextConnector) Driver() driver.Driver { return &sqlite.Driver{} }
func (c *enrollmentContextConnector) Connect(context.Context) (driver.Conn, error) {
	conn, err := c.Driver().Open(c.path)
	if err != nil {
		return nil, err
	}
	c.opened.Add(1)
	return &enrollmentContextConn{Conn: conn, owner: c}, nil
}

type enrollmentContextConn struct {
	driver.Conn
	owner *enrollmentContextConnector
}

func (c *enrollmentContextConn) Close() error { c.owner.closed.Add(1); return c.Conn.Close() }
func (c *enrollmentContextConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	next := c.Conn.(driver.ExecerContext)
	if c.owner.exec != nil {
		return c.owner.exec(ctx, query, args, next)
	}
	return next.ExecContext(ctx, query, args)
}
func (c *enrollmentContextConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	return c.Conn.(driver.QueryerContext).QueryContext(ctx, query, args)
}
func enrollmentContextWrap(t *testing.T, j *directEnrollmentJournal) *enrollmentContextConnector {
	t.Helper()
	if err := j.registry.db.Close(); err != nil {
		t.Fatal(err)
	}
	connector := &enrollmentContextConnector{path: filepath.Join(j.registry.root, "registry.sqlite")}
	j.registry.db = sql.OpenDB(connector)
	j.registry.db.SetMaxOpenConns(1)
	if _, err := j.registry.db.Exec("PRAGMA busy_timeout=5000"); err != nil {
		t.Fatal(err)
	}
	return connector
}

func TestDirectEnrollmentContextBeforeCommit(t *testing.T) {
	j, s, b, _ := enrollmentFixture(t)
	if _, err := j.reserve(s, b); err != nil {
		t.Fatal(err)
	}
	before := enrollmentContextPayload(t, j)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err := j.lockedContext(ctx, func(conn *sql.Conn, key []byte) error {
		if _, err := conn.ExecContext(ctx, `UPDATE native_direct_enrollment_v1 SET payload='changed'`); err != nil {
			return err
		}
		cancel()
		return nil
	})
	if !errors.Is(err, context.Canceled) || j.poisoned {
		t.Fatalf("known precommit cancellation: %v poisoned=%v", err, j.poisoned)
	}
	if !bytes.Equal(before, enrollmentContextPayload(t, j)) {
		t.Fatal("canceled transaction retained changed bytes")
	}
	if timeout := enrollmentContextTimeout(t, j); timeout != 5000 {
		t.Fatalf("timeout not restored: %d", timeout)
	}
}

func TestDirectEnrollmentContextAtCommit(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(map[bool]string{false: "rolled back", true: "committed"}[committed], func(t *testing.T) {
			j, s, b, v := enrollmentFixture(t)
			if _, err := j.reserve(s, b); err != nil {
				t.Fatal(err)
			}
			before := enrollmentContextPayload(t, j)
			connector := enrollmentContextWrap(t, j)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			connector.exec = func(ctx context.Context, query string, args []driver.NamedValue, next driver.ExecerContext) (driver.Result, error) {
				if query == "COMMIT" {
					if committed {
						if _, err := next.ExecContext(ctx, query, args); err != nil {
							return nil, err
						}
					}
					cancel()
					return nil, context.Canceled
				}
				return next.ExecContext(ctx, query, args)
			}
			if _, err := j.materialContext(ctx, s, b, func() ([]byte, []byte, error) { return bytes.Clone(v.EpochKey), bytes.Clone(v.Publication), nil }); err == nil || !j.poisoned {
				t.Fatal("uncertain COMMIT did not poison handle")
			}
			connector.exec = nil
			if committed && connector.closed.Load() != 1 {
				t.Fatal("failed rollback did not discard connection")
			}
			if !committed {
				if !bytes.Equal(before, enrollmentContextPayload(t, j)) {
					t.Fatal("failed COMMIT changed bytes")
				}
				if timeout := enrollmentContextTimeout(t, j); timeout != 5000 {
					t.Fatalf("timeout not restored: %d", timeout)
				}
			}
			reopened, err := newDirectEnrollmentJournalContext(context.Background(), j.registry)
			if err != nil {
				t.Fatal(err)
			}
			generated := 0
			row, err := reopened.materialContext(context.Background(), s, b, func() ([]byte, []byte, error) {
				generated++
				return bytes.Clone(v.EpochKey), bytes.Clone(v.Publication), nil
			})
			if err != nil {
				t.Fatal(err)
			}
			want := 1
			if committed {
				want = 0
			}
			if generated != want || !bytes.Equal(row.Root, v.EpochKey) || !bytes.Equal(row.Publication, v.Publication) {
				t.Fatal("COMMIT recovery changed material")
			}
		})
	}
}

func TestDirectEnrollmentContextCleanupDiscard(t *testing.T) {
	for _, failure := range []string{"ROLLBACK", "PRAGMA busy_timeout=5000"} {
		t.Run(failure, func(t *testing.T) {
			j, _, _, _ := enrollmentFixture(t)
			connector := enrollmentContextWrap(t, j)
			connector.exec = func(ctx context.Context, query string, args []driver.NamedValue, next driver.ExecerContext) (driver.Result, error) {
				if query == failure {
					if ctx.Err() != nil {
						t.Error("cleanup inherited canceled context")
					}
					return nil, errors.New("injected cleanup failure")
				}
				return next.ExecContext(ctx, query, args)
			}
			ctx, cancel := context.WithCancel(context.Background())
			err := j.lockedContext(ctx, func(*sql.Conn, []byte) error {
				if failure == "ROLLBACK" {
					cancel()
					return context.Canceled
				}
				return nil
			})
			cancel()
			if err == nil || connector.closed.Load() != 1 {
				t.Fatal("cleanup failure returned connection to pool")
			}
			connector.exec = nil
			if _, err := j.registry.db.Exec("BEGIN IMMEDIATE"); err != nil {
				t.Fatal(err)
			}
			if _, err := j.registry.db.Exec("ROLLBACK"); err != nil {
				t.Fatal(err)
			}
			if connector.opened.Load() != 2 {
				t.Fatal("discarded connection reused")
			}
		})
	}
}

func TestDirectEnrollmentContextSecurity(t *testing.T) {
	for _, name := range []string{"registry.custody.lock", filepath.Join(directEnrollmentNamespace, "holder.lock"), filepath.Join(directEnrollmentNamespace, "journal.mac")} {
		t.Run(strings.ReplaceAll(name, string(os.PathSeparator), "_"), func(t *testing.T) {
			j, s, b, _ := enrollmentFixture(t)
			if _, err := j.reserve(s, b); err != nil {
				t.Fatal(err)
			}
			before := enrollmentContextPayload(t, j)
			path := filepath.Join(j.registry.root, name)
			if err := os.Chmod(path, 0644); err != nil {
				t.Fatal(err)
			}
			if _, err := j.materialContext(context.Background(), s, b, func() ([]byte, []byte, error) { t.Fatal("unsafe state generated material"); return nil, nil, nil }); err == nil {
				t.Fatal("unsafe state accepted")
			}
			if !bytes.Equal(before, enrollmentContextPayload(t, j)) {
				t.Fatal("unsafe state changed retained bytes")
			}
		})
	}
}

func TestDirectEnrollmentContextOperations(t *testing.T) {
	j, s, b, v := enrollmentFixture(t)
	ctx := context.Background()
	challenge, err := transport.DecodeDirectChannelReadinessChallengeV2(v.Challenges[0])
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := transport.DecodeDirectChannelDescriptorV2(v.Descriptor)
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range []func() (directEnrollmentRecord, error){
		func() (directEnrollmentRecord, error) { return j.reserveContext(ctx, s, b) },
		func() (directEnrollmentRecord, error) {
			return j.materialContext(ctx, s, b, func() ([]byte, []byte, error) { return bytes.Clone(v.EpochKey), bytes.Clone(v.Publication), nil })
		},
		func() (directEnrollmentRecord, error) { return j.markDispatchContext(ctx, s, b, "publication") },
		func() (directEnrollmentRecord, error) { return j.observeAbsentContext(ctx, s, b, "publication") },
		func() (directEnrollmentRecord, error) {
			return j.observePublicationContext(ctx, s, b, enrollmentHash(v.Publication))
		},
		func() (directEnrollmentRecord, error) { return j.observeChallengeContext(ctx, s, b, v.Challenges[0]) },
		func() (directEnrollmentRecord, error) {
			return j.bindProofContext(ctx, s, b, v.Challenges[0], v.Proofs[0])
		},
		func() (directEnrollmentRecord, error) {
			return j.observeProofContext(ctx, s, b, enrollmentHash(v.Proofs[0]), challenge.ExpiresAt)
		},
		func() (directEnrollmentRecord, error) {
			return j.observeActivationContext(ctx, s, b, b.Channel, challenge.ExpiresAt, descriptor.ExpiresAt)
		},
	} {
		if _, err := operation(); err != nil {
			t.Fatal(err)
		}
	}
	row, err := j.reserveContext(ctx, s, b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(row.Root, v.EpochKey) || !bytes.Equal(row.Publication, v.Publication) || !bytes.Equal(row.Challenge, v.Challenges[0]) || !bytes.Equal(row.Proof, v.Proofs[0]) || len(row.Activation) == 0 {
		t.Fatal("context operations changed material")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if journal, err := newDirectEnrollmentJournalContext(canceled, j.registry); journal != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled constructor: %v", err)
	}
	j.registry.mu.Lock()
	journal, err := newDirectEnrollmentJournalContext(ctx, j.registry)
	j.registry.mu.Unlock()
	if journal != nil || err != errDirectEndpointLocalBusy {
		t.Fatalf("busy constructor: %v", err)
	}
}
