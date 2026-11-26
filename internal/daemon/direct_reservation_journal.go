//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/pagnet-code/pagnet/internal/nativedirect"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
)

var errDirectReservationRejected = errors.New("direct reservation rejected")
var errDirectReservationRecovery = errors.New("direct reservation recovery required")

// This journal stores encrypted provenance only, never native prompt authority.
type directReservationRecord struct {
	Source nativedirect.NativeDirectASKSource
	Wire   json.RawMessage
	Stage  string
	Result *sessionworker.DirectASKReservation
}

type directReservationStore struct {
	registry *NativeWorkerRegistry
	poisoned bool
}

const directReservationSchema = `CREATE TABLE native_direct_reservation_v1(delivery_key TEXT PRIMARY KEY,record BLOB NOT NULL CHECK(length(record)<=524288))`

func (s *directReservationStore) schema(ctx context.Context, c *sql.Conn) error {
	var got string
	err := c.QueryRowContext(ctx, "SELECT sql FROM sqlite_master WHERE type='table' AND name='native_direct_reservation_v1'").Scan(&got)
	if errors.Is(err, sql.ErrNoRows) {
		if _, err = c.ExecContext(ctx, directReservationSchema); err != nil {
			return err
		}
		got = directReservationSchema
	} else if err != nil {
		return err
	}
	if got != directReservationSchema {
		return errDirectReservationRejected
	}
	var triggers int
	if err = c.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type='trigger' AND tbl_name='native_direct_reservation_v1'").Scan(&triggers); err != nil {
		return err
	}
	if triggers != 0 {
		return errDirectReservationRejected
	}
	return nil
}

func (s *directReservationStore) locked(ctx context.Context, fn func(*sql.Conn) error) error {
	if s == nil {
		return errDirectReservationRejected
	}
	return nativeRegistryCustodyTransaction(ctx, s.registry, &s.poisoned, s.schema, fn, nil)
}

func directReservationKey(source nativedirect.NativeDirectASKSource) (string, error) {
	key, err := source.DeliveryKey()
	if err != nil {
		return "", errDirectReservationRejected
	}
	return hex.EncodeToString(key[:]), nil
}

func directReservationBytes(key string, v directReservationRecord) ([]byte, error) {
	actual, err := directReservationKey(v.Source)
	if err != nil || actual != key || v.Source.ValidateWire(v.Wire) != nil {
		return nil, errDirectReservationRejected
	}
	switch v.Stage {
	case "prepared", "attempted":
		if v.Result != nil {
			return nil, errDirectReservationRejected
		}
	case "reserved", "unknown":
		if v.Result == nil {
			if v.Stage == "reserved" {
				return nil, errDirectReservationRejected
			}
		} else {
			want, _ := v.Source.CanonicalBytes()
			got, e := v.Result.Source.CanonicalBytes()
			if e != nil || !bytes.Equal(want, got) || !bytes.Equal(v.Result.Wire, v.Wire) || v.Result.State != v.Stage {
				return nil, errDirectReservationRejected
			}
		}
	default:
		return nil, errDirectReservationRejected
	}
	raw, err := json.Marshal(v)
	if err != nil || len(raw) > 524288 {
		return nil, errDirectReservationRejected
	}
	return raw, nil
}

func decodeDirectReservation(key string, raw []byte) (v directReservationRecord, err error) {
	if len(raw) == 0 || len(raw) > 524288 || json.Unmarshal(raw, &v) != nil {
		return directReservationRecord{}, errDirectReservationRecovery
	}
	canonical, err := directReservationBytes(key, v)
	if err != nil || !bytes.Equal(raw, canonical) {
		return directReservationRecord{}, errDirectReservationRecovery
	}
	return v, nil
}

func readDirectReservation(ctx context.Context, c *sql.Conn, key string) (directReservationRecord, error) {
	var raw []byte
	if err := c.QueryRowContext(ctx, "SELECT CASE WHEN length(record)<=524288 THEN record ELSE NULL END FROM native_direct_reservation_v1 WHERE delivery_key=?", key).Scan(&raw); err != nil {
		return directReservationRecord{}, err
	}
	return decodeDirectReservation(key, raw)
}

func (s *directReservationStore) claim(ctx context.Context, source nativedirect.NativeDirectASKSource, wire json.RawMessage) (v directReservationRecord, err error) {
	key, err := directReservationKey(source)
	if err != nil {
		return v, err
	}
	v = directReservationRecord{Source: source, Wire: wire, Stage: "prepared"}
	raw, err := directReservationBytes(key, v)
	if err != nil {
		return directReservationRecord{}, err
	}
	err = s.locked(ctx, func(c *sql.Conn) error {
		old, e := readDirectReservation(ctx, c, key)
		if e == nil {
			comparison := source
			// Fresh local admission, lease, and deadline candidates are discarded;
			// the first committed source remains immutable across reconnects.
			comparison.AdmissionID = old.Source.AdmissionID
			comparison.EndpointLeaseID = old.Source.EndpointLeaseID
			comparison.Deadline = old.Source.Deadline
			want, _ := comparison.CanonicalBytes()
			got, _ := old.Source.CanonicalBytes()
			if !bytes.Equal(want, got) || !bytes.Equal(wire, old.Wire) {
				return errDirectReservationRejected
			}
			v = old
			return nil
		}
		if !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		var count int
		if e = c.QueryRowContext(ctx, "SELECT count(*) FROM native_direct_reservation_v1").Scan(&count); e != nil {
			return e
		}
		if count >= 4096 {
			return errDirectReservationRecovery
		}
		_, e = c.ExecContext(ctx, "INSERT INTO native_direct_reservation_v1(delivery_key,record) VALUES(?,?)", key, raw)
		if e == nil {
			v, e = decodeDirectReservation(key, raw)
		}
		return e
	})
	if err != nil {
		v = directReservationRecord{}
	}
	return
}

func (s *directReservationStore) load(ctx context.Context, key string) (v directReservationRecord, err error) {
	err = s.locked(ctx, func(c *sql.Conn) error {
		var e error
		v, e = readDirectReservation(ctx, c, key)
		return e
	})
	if err != nil {
		v = directReservationRecord{}
	}
	return
}

func (s *directReservationStore) save(ctx context.Context, key, prior string, v directReservationRecord) error {
	raw, err := directReservationBytes(key, v)
	if err != nil {
		return err
	}
	valid := prior == "prepared" && v.Stage == "attempted" ||
		(prior == "attempted" || prior == "unknown") && (v.Stage == "attempted" || v.Stage == "reserved" || v.Stage == "unknown") ||
		prior == "reserved" && (v.Stage == "attempted" || v.Stage == "reserved" || v.Stage == "unknown")
	if !valid {
		return errDirectReservationRejected
	}
	return s.locked(ctx, func(c *sql.Conn) error {
		old, e := readDirectReservation(ctx, c, key)
		if e != nil {
			return e
		}
		want, _ := v.Source.CanonicalBytes()
		got, _ := old.Source.CanonicalBytes()
		if old.Stage != prior || !bytes.Equal(want, got) || !bytes.Equal(v.Wire, old.Wire) {
			return errDirectReservationRecovery
		}
		_, e = c.ExecContext(ctx, "UPDATE native_direct_reservation_v1 SET record=? WHERE delivery_key=?", raw, key)
		return e
	})
}
