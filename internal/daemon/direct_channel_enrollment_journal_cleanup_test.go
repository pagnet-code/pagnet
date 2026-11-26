//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strings"
	"testing"
)

func enrollmentCleanupZero(t *testing.T, name string, raw []byte) {
	t.Helper()
	if len(raw) == 0 || !bytes.Equal(raw, make([]byte, len(raw))) {
		t.Errorf("%s buffer was not cleared", name)
	}
}

func TestDirectEnrollmentCleanupMACKey(t *testing.T) {
	for _, outcome := range []string{"success", "error", "panic"} {
		t.Run(outcome, func(t *testing.T) {
			j, _, _, _ := enrollmentFixture(t)
			var retained []byte
			var err error
			panicked := false
			func() {
				defer func() { panicked = recover() != nil }()
				err = j.lockedContext(context.Background(), func(_ *sql.Conn, key []byte) error {
					retained = key
					switch outcome {
					case "error":
						return errors.New("callback failed")
					case "panic":
						panic("callback failed")
					}
					return nil
				})
			}()
			if (outcome == "panic") != panicked || (outcome == "error") != (err != nil) {
				t.Fatal("unexpected callback outcome")
			}
			enrollmentCleanupZero(t, "MAC key", retained)
		})
	}
}

func TestDirectEnrollmentCleanupRootAndPayload(t *testing.T) {
	for _, outcome := range []string{"success", "callback error", "callback panic", "cancel", "commit error", "commit panic"} {
		t.Run(outcome, func(t *testing.T) {
			j, s, b, v := enrollmentFixture(t)
			if _, err := j.reserve(s, b); err != nil {
				t.Fatal(err)
			}
			seed, err := j.material(s, b, func() ([]byte, []byte, error) { return bytes.Clone(v.EpochKey), v.Publication, nil })
			if err != nil {
				t.Fatal(err)
			}
			clear(seed.Root)
			connector := enrollmentContextWrap(t, j)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var payload, ownedRoot []byte
			connector.exec = func(ctx context.Context, query string, args []driver.NamedValue, next driver.ExecerContext) (driver.Result, error) {
				if strings.HasPrefix(query, "INSERT INTO native_direct_enrollment_v1 VALUES") {
					payload = args[3].Value.([]byte)
				}
				if query == "COMMIT" {
					switch outcome {
					case "commit error":
						return nil, errors.New("lost COMMIT acknowledgement")
					case "commit panic":
						panic("COMMIT failed")
					}
				}
				return next.ExecContext(ctx, query, args)
			}
			var result directEnrollmentRecord
			panicked := false
			func() {
				defer func() { panicked = recover() != nil }()
				result, err = j.applyContext(ctx, s, b, func(row *directEnrollmentRecord, exists bool) error {
					if !exists {
						t.Fatal("missing material")
					}
					ownedRoot = row.Root
					switch outcome {
					case "callback error":
						return errors.New("change failed")
					case "callback panic":
						panic("change failed")
					case "cancel":
						cancel()
					}
					return nil
				})
			}()
			if (strings.Contains(outcome, "panic")) != panicked {
				t.Fatal("unexpected panic outcome")
			}
			enrollmentCleanupZero(t, "journal row root", ownedRoot)
			if len(payload) > 0 {
				enrollmentCleanupZero(t, "write payload", payload)
			}
			if outcome == "success" {
				if err != nil || !bytes.Equal(result.Root, v.EpochKey) {
					t.Fatal("successful root ownership transfer failed")
				}
				clear(result.Root)
			} else if len(result.Root) != 0 || (!panicked && err == nil) {
				clear(result.Root)
				t.Fatal("failed transaction exposed root")
			}
			if outcome == "commit error" && !j.poisoned {
				t.Fatal("uncertain COMMIT did not poison handle")
			}
			connector.exec = nil
		})
	}
}
