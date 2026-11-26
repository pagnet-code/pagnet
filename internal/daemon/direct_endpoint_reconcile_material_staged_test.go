//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestDirectReconcileMaterialStagesSourceRootMissing(t *testing.T) {
	for _, loseLease := range []bool{false, true} {
		t.Run(map[bool]string{false: "accepted", true: "lease lost"}[loseLease], func(t *testing.T) {
			f := newReconcileOperationFixture(t, "S")
			b, e, _ := reconcileSourceOperationBinding(t, f)
			e = publishedEnrollment(e, []byte("authenticated publication"))
			operation, err := f.factory()
			if err != nil {
				t.Fatal(err)
			}
			called := false
			wrapped := func(ctx context.Context, use func(context.Context, endpointMaterial) error) error {
				return operation(ctx, func(opctx context.Context, custody endpointMaterial) error {
					called = true
					if err := use(opctx, custody); err != nil {
						t.Error("local error escaped into role operation")
						return err
					}
					if loseLease {
						f.token.proxy.abort()
					}
					return nil
				})
			}
			material, wire, err := acquireDirectSourceReconcileMaterial(context.Background(), f.s, b, e, f.d.nativeRegistry, time.Now, wrapped)
			want := errDirectEndpointReconcileSourceRootMissing
			if loseLease {
				want = errDirectEndpointOperationUnknown
			}
			if err != want || !called || material != nil || wire != nil {
				if material != nil {
					material.Clear()
				}
				t.Fatalf("staged result error=%v called=%v", err, called)
			}
			if loseLease {
				return
			}
			binding, err := enrollmentBinding(f.s, b.Protocol, b.DescriptorBytes, b.LocalFingerprint, b.PeerFingerprint)
			if err != nil {
				t.Fatal(err)
			}
			journal, err := newDirectEnrollmentJournal(f.d.nativeRegistry)
			if err != nil {
				t.Fatal(err)
			}
			row, err := journal.reserve(f.s, binding)
			defer clear(row.Root)
			if err != nil || row.State != "reserved" || len(row.Root) != 0 || len(row.Publication) != 0 || row.Binding.Generation != binding.Generation || row.Binding.DescriptorHash != binding.DescriptorHash {
				t.Fatal("missing source root changed retained generation or material")
			}
		})
	}
}

func TestDirectReconcileMaterialStagesUnknownCommitWithRoleOperation(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(map[bool]string{false: "rollback", true: "commit"}[committed], func(t *testing.T) {
			f := newReconcileOperationFixture(t, "S")
			b, e, _ := reconcileSourceOperationBinding(t, f)
			operation, err := f.factory()
			if err != nil {
				t.Fatal(err)
			}
			journal, err := newDirectEnrollmentJournal(f.d.nativeRegistry)
			if err != nil {
				t.Fatal(err)
			}
			connector := enrollmentContextWrap(t, journal)
			materialWrite, injected := false, false
			connector.exec = func(ctx context.Context, query string, args []driver.NamedValue, next driver.ExecerContext) (driver.Result, error) {
				if strings.HasPrefix(query, "INSERT INTO native_direct_enrollment_v1 VALUES") && len(args) == 5 {
					var record struct{ State string }
					if payload, ok := args[3].Value.([]byte); ok && json.Unmarshal(payload, &record) == nil {
						materialWrite = record.State == "material"
					}
				}
				if query == "COMMIT" {
					if materialWrite && !injected {
						injected = true
						if committed {
							if _, err := next.ExecContext(ctx, query, args); err != nil {
								return nil, err
							}
						}
						return nil, errors.New("lost acknowledgement")
					}
				}
				return next.ExecContext(ctx, query, args)
			}
			material, wire, err := acquireDirectSourceReconcileMaterial(context.Background(), f.s, b, e, f.d.nativeRegistry, time.Now, operation)
			if !injected || err != errDirectEnrollment || errors.Is(err, errDirectEndpointReconcileSourceRootMissing) || material != nil || wire != nil {
				if material != nil {
					material.Clear()
				}
				t.Fatalf("unknown commit result error=%v", err)
			}
			connector.exec = nil
			fresh, err := newDirectEnrollmentJournal(f.d.nativeRegistry)
			if err != nil {
				t.Fatal(err)
			}
			binding, err := enrollmentBinding(f.s, b.Protocol, b.DescriptorBytes, b.LocalFingerprint, b.PeerFingerprint)
			if err != nil {
				t.Fatal(err)
			}
			row, err := fresh.reserve(f.s, binding)
			defer clear(row.Root)
			if err != nil {
				t.Fatal(err)
			}
			if committed {
				if row.State != "material" {
					t.Fatal("fresh journal lost committed material")
				}
				e = publishedEnrollment(e, row.Publication)
			} else if row.State != "reserved" || len(row.Root) != 0 {
				t.Fatal("fresh journal did not confirm rollback")
			}
			material, wire, err = acquireDirectSourceReconcileMaterial(context.Background(), f.s, b, e, f.d.nativeRegistry, time.Now, operation)
			if err != nil {
				t.Fatal(err)
			}
			defer material.Clear()
			if committed && (!bytes.Equal(material.Key[:], row.Root) || !bytes.Equal(wire, row.Publication)) {
				t.Fatal("fresh attempt changed committed material")
			}
		})
	}
}
