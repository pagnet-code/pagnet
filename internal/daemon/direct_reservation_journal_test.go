//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/internal/sessionworker"
)

func reservationJournalFixture(t *testing.T) *directReservationStore {
	t.Helper()
	r, err := OpenNativeWorkerRegistry(registryCustodyState(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return &directReservationStore{registry: r}
}

func TestDirectReservationJournalDuplicateAndTransitions(t *testing.T) {
	s := reservationJournalFixture(t)
	ctx := context.Background()
	source, wire := proxyDirectASKSource(t)
	v, err := s.claim(ctx, source, wire)
	if err != nil || v.Stage != "prepared" {
		t.Fatalf("claim: %s %v", v.Stage, err)
	}
	key, _ := directReservationKey(source)
	fresh := source
	fresh.AdmissionID = "fresh-admission"
	fresh.EndpointLeaseID = "fresh-lease"
	fresh.Deadline = source.Deadline.Add(-time.Second)
	duplicate, err := s.claim(ctx, fresh, wire)
	if err != nil || duplicate.Source.AdmissionID != source.AdmissionID || duplicate.Source.EndpointLeaseID != source.EndpointLeaseID || !duplicate.Source.Deadline.Equal(source.Deadline) {
		t.Fatalf("duplicate did not retain original source: %v", err)
	}
	fresh.ConsentRevision++
	if _, err = s.claim(ctx, fresh, wire); !errors.Is(err, errDirectReservationRejected) {
		t.Fatalf("changed source accepted: %v", err)
	}
	v.Stage = "attempted"
	if err = s.save(ctx, key, "prepared", v); err != nil {
		t.Fatal(err)
	}
	if err = s.save(ctx, key, "prepared", v); !errors.Is(err, errDirectReservationRecovery) {
		t.Fatalf("stale stage accepted: %v", err)
	}
	v.Stage = "unknown"
	if err = s.save(ctx, key, "attempted", v); err != nil {
		t.Fatal(err)
	}
	v.Stage = "attempted"
	if err = s.save(ctx, key, "unknown", v); err != nil {
		t.Fatal(err)
	}
	v.Stage = "reserved"
	v.Result = &sessionworker.DirectASKReservation{Source: source, Wire: wire, State: "reserved"}
	if err = s.save(ctx, key, "attempted", v); err != nil {
		t.Fatal(err)
	}
	loaded, err := s.load(ctx, key)
	if err != nil || loaded.Stage != "reserved" || loaded.Result == nil || !bytes.Equal(loaded.Wire, wire) {
		t.Fatalf("load: %s %v", loaded.Stage, err)
	}
	v.Stage, v.Result = "prepared", nil
	if err = s.save(ctx, key, "reserved", v); !errors.Is(err, errDirectReservationRejected) {
		t.Fatalf("reserved reopened: %v", err)
	}
	v.Stage = "unknown"
	v.Result = &sessionworker.DirectASKReservation{Source: source, Wire: wire, State: "unknown"}
	if err = s.save(ctx, key, "reserved", v); err != nil {
		t.Fatalf("worker restart state: %v", err)
	}
}

func TestDirectReservationJournalRejectsTampering(t *testing.T) {
	for _, name := range []string{"noncanonical", "unknown-field", "stage", "result-source", "trigger", "schema"} {
		t.Run(name, func(t *testing.T) {
			s := reservationJournalFixture(t)
			ctx := context.Background()
			source, wire := proxyDirectASKSource(t)
			v, err := s.claim(ctx, source, wire)
			if err != nil {
				t.Fatal(err)
			}
			key, _ := directReservationKey(source)
			raw, _ := json.Marshal(v)
			switch name {
			case "noncanonical":
				raw = append(raw, '\n')
			case "unknown-field":
				raw = append(raw[:len(raw)-1:len(raw)-1], []byte(`,"Extra":true}`)...)
			case "stage":
				v.Stage = "complete"
				raw, _ = json.Marshal(v)
			case "result-source":
				other := source
				other.AdmissionID = "other"
				v.Stage = "reserved"
				v.Result = &sessionworker.DirectASKReservation{Source: other, Wire: wire, State: "reserved"}
				raw, _ = json.Marshal(v)
			case "trigger":
				_, err = s.registry.db.Exec(`CREATE TRIGGER reservation_tamper AFTER INSERT ON native_direct_reservation_v1 BEGIN SELECT 1; END`)
			case "schema":
				_, err = s.registry.db.Exec(`ALTER TABLE native_direct_reservation_v1 ADD COLUMN extra TEXT`)
			}
			if err != nil {
				t.Fatal(err)
			}
			if name != "trigger" && name != "schema" {
				if _, err = s.registry.db.Exec("UPDATE native_direct_reservation_v1 SET record=? WHERE delivery_key=?", raw, key); err != nil {
					t.Fatal(err)
				}
			}
			if _, err = s.load(ctx, key); err == nil {
				t.Fatal("tampered journal accepted")
			}
		})
	}
}

// Manually completing the connection transaction simulates a lost COMMIT
// acknowledgement: the outer COMMIT fails after either durable outcome.
func TestDirectReservationJournalAmbiguousCommit(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(fmt.Sprint(committed), func(t *testing.T) {
			store := reservationJournalFixture(t)
			source, wire := proxyDirectASKSource(t)
			key, _ := directReservationKey(source)
			record := directReservationRecord{Source: source, Wire: wire, Stage: "attempted"}
			raw, err := directReservationBytes(key, record)
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			err = store.locked(ctx, func(conn *sql.Conn) error {
				if _, e := conn.ExecContext(ctx, "INSERT INTO native_direct_reservation_v1 VALUES(?,?)", key, raw); e != nil {
					return e
				}
				operation := "ROLLBACK"
				if committed {
					operation = "COMMIT"
				}
				_, e := conn.ExecContext(ctx, operation)
				return e
			})
			if err == nil || !store.poisoned {
				t.Fatal("ambiguous commit did not poison attempt")
			}
			if _, err = store.load(ctx, key); err == nil {
				t.Fatal("poisoned attempt reused")
			}
			fresh := &directReservationStore{registry: store.registry}
			found, err := fresh.load(ctx, key)
			if committed {
				if err != nil || found.Stage != "attempted" || found.Source.AdmissionID != source.AdmissionID {
					t.Fatal("committed immutable attempt lost", err)
				}
			} else if !errors.Is(err, sql.ErrNoRows) {
				t.Fatal("rollback retained candidate", err)
			}
		})
	}
}
