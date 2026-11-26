//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"database/sql/driver"
	"errors"
	"testing"
	"time"
)

func TestDirectEnrollmentContextRejectsProxyAbort(t *testing.T) {
	for _, stage := range []string{"before material", "owner held", "during change"} {
		t.Run(stage, func(t *testing.T) {
			j, s, b, _ := enrollmentFixture(t)
			p := &NativeWorkerProxy{abortDone: make(chan struct{}), done: make(chan struct{}), connection: &NativeObservationConnection{closed: make(chan struct{})}}
			s.binding.proxy = p
			p.directInvalidations.register(s.owner)
			if _, err := j.reserveContext(t.Context(), s, b); err != nil {
				t.Fatal(err)
			}
			before := enrollmentContextPayload(t, j)
			connector := enrollmentContextWrap(t, j)
			commits := 0
			connector.exec = func(ctx context.Context, query string, args []driver.NamedValue, next driver.ExecerContext) (driver.Result, error) {
				if query == "COMMIT" {
					commits++
				}
				return next.ExecContext(ctx, query, args)
			}
			// Abort must revoke authority before ordered cleanup acquires publicationMu.
			p.publicationMu.Lock()
			watcherDone := make(chan struct{})
			go func() { defer close(watcherDone); p.watchLifecycle() }()
			defer func() { p.publicationMu.Unlock(); waitNativeProxySignal(t, watcherDone) }()
			ctx := t.Context()
			generated, changed := false, false
			var result directEnrollmentRecord
			var err error
			if stage == "during change" {
				result, err = j.applyContext(ctx, s, b, func(row *directEnrollmentRecord, exists bool) error {
					changed = true
					if !exists {
						t.Fatal("reserved row missing")
					}
					row.State = "started"
					p.abort()
					return nil
				})
			} else {
				p.abort()
				if stage == "owner held" {
					s.owner.mu.Lock()
					start := time.Now()
					matchErr := j.matchesContext(ctx, s, b)
					s.owner.mu.Unlock()
					if !errors.Is(matchErr, errDirectEnrollment) {
						t.Fatalf("aborted membership disposition: %v", matchErr)
					}
					if time.Since(start) > time.Second {
						t.Fatal("aborted membership waited for owner cleanup")
					}
				}
				result, err = j.materialContext(ctx, s, b, func() ([]byte, []byte, error) { generated = true; return nil, nil, nil })
			}
			if !errors.Is(err, errDirectEnrollment) || errors.Is(err, errDirectEndpointLocalBusy) || ctx.Err() != nil {
				t.Fatalf("abort disposition: %v", err)
			}
			if generated || changed != (stage == "during change") {
				t.Fatal("abort did not fence journal change")
			}
			if result.State != "" || len(result.Root) != 0 {
				t.Fatal("aborted journal exposed a result")
			}
			if j.poisoned || commits != 0 {
				t.Fatal("abort attempted COMMIT or poisoned journal")
			}
			if !bytes.Equal(before, enrollmentContextPayload(t, j)) {
				t.Fatal("aborted journal mutated the durable row")
			}
			select {
			case <-s.Done():
				t.Fatal("ordered subscription cleanup already completed")
			default:
			}
			select {
			case <-p.done:
				t.Fatal("ordered proxy cleanup already completed")
			default:
			}
		})
	}
}
