package sessionworker

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/pagnet-code/pagnet/internal/nativedirect"
	"github.com/pagnet-code/pagnet/transport"
)

// directASKController is a package-private authenticated-controller capability.
// It is minted only from an authenticated controller connection's durable lease,
// never from request data.
type directASKController struct {
	owner *SessionOwner
	lease int64
}

// DirectASKReservation describes journal provenance only. Neither state proves
// native acceptance. Lookup of missing provenance returns nil without insertion.
type DirectASKReservation struct {
	Source nativedirect.NativeDirectASKSource `json:"source"`
	Wire   json.RawMessage                    `json:"wire"`
	State  string                             `json:"state"`
}

func (j *Journal) initializeDirectAdmissions() error {
	if err := j.migrateDirectAdmissions(); err != nil {
		return err
	}
	if _, err := j.db.Exec(`CREATE TABLE IF NOT EXISTS worker_direct_turn_sources(admission_id TEXT PRIMARY KEY,native_generation TEXT NOT NULL,logical_turn TEXT NOT NULL,native_session TEXT NOT NULL,source TEXT NOT NULL,UNIQUE(native_generation,logical_turn))`); err != nil {
		return err
	}
	rows, err := j.db.Query(`SELECT admission_id,delivery_key,digest,record,state FROM worker_direct_admissions`)
	if err != nil {
		return err
	}
	count := 0
	for rows.Next() {
		var id, key, digest, state string
		var raw []byte
		var r DirectASKReservation
		if err = rows.Scan(&id, &key, &digest, &raw, &state); err != nil {
			break
		}
		if len(raw) > 98304 {
			err = errors.New("oversized direct ASK reservation history")
			break
		}
		if err = json.Unmarshal(raw, &r); err != nil {
			break
		}
		canonical, marshalErr := json.Marshal(r)
		if marshalErr != nil || !bytes.Equal(raw, canonical) {
			err = errors.New("noncanonical direct ASK reservation history")
			break
		}
		sum, e := r.Source.Digest()
		delivery, ke := r.Source.DeliveryKey()
		count++
		if e != nil || ke != nil || r.Source.ValidateWire(r.Wire) != nil || r.Source.Scope != j.scope || j.isLocal() || id != r.Source.AdmissionID || key != hex.EncodeToString(delivery[:]) || digest != hex.EncodeToString(sum[:]) || r.State != "" || (state != "reserved" && state != "submitted" && state != "unknown") || count > maxCommands || len(raw) > 98304 {
			err = errors.New("invalid direct ASK reservation history")
			break
		}
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return err
	}
	if err = j.validateDirectExecution(); err != nil {
		return err
	}
	_, err = j.db.Exec(`UPDATE worker_direct_admissions SET state='unknown' WHERE state IN ('reserved','submitted')`)
	return err
}

// ReserveDirectASK authenticates and durably reserves encrypted provenance. It
// never calls Execute or Submit and consumes no Cloud dispatch sequence.
func (o *SessionOwner) ReserveDirectASK(ctx context.Context, controller *directASKController, source nativedirect.NativeDirectASKSource, wire json.RawMessage) (*DirectASKReservation, error) {
	return o.directASK(ctx, controller, source, wire, true, time.Now().UTC(), o.physicalSnapshot)
}

// LookupDirectASK performs authenticated exact status recovery only. An
// authenticated controller permits recovery after the source deadline has passed.
// It still requires the original live physical identity. A replaced or missing
// native process returns a fence/busy error, never an absent reservation.
func (o *SessionOwner) LookupDirectASK(ctx context.Context, controller *directASKController, source nativedirect.NativeDirectASKSource, wire json.RawMessage) (*DirectASKReservation, error) {
	return o.directASK(ctx, controller, source, wire, false, time.Now().UTC(), o.physicalSnapshot)
}

func (o *SessionOwner) directASK(ctx context.Context, controller *directASKController, source nativedirect.NativeDirectASKSource, wire json.RawMessage, reserve bool, now time.Time, collect func() NativeSnapshot) (*DirectASKReservation, error) {
	started := time.Now()
	if o == nil || o.journal == nil || source.ValidateWire(wire) != nil || source.Scope != o.journal.scope || controller == nil || controller.owner != o || controller.lease <= 0 || now.IsZero() || reserve && !now.Before(source.Deadline) {
		return nil, ErrFenced
	}
	lease := controller.lease
	verified, err := o.journal.verifyOwnershipSnapshot(ctx, lease, NativeOwnershipVerifyRequest{Ownership: source.Ownership}, collect)
	if err != nil {
		return nil, err
	}
	s := verified.Snapshot
	if s.NativeGeneration != source.NativeGeneration || s.NativeSessionID != source.NativeSessionID || s.NativeStartIdentity != source.NativeStartIdentity || s.PID != source.NativePID {
		return nil, ErrFenced
	}
	return o.journal.directASKReservation(ctx, lease, source, wire, reserve, func() error {
		if reserve && !now.Add(time.Since(started)).Before(source.Deadline) {
			return ErrFenced
		}
		return nil
	})
}

func (j *Journal) directASKReservation(ctx context.Context, lease int64, source nativedirect.NativeDirectASKSource, wire json.RawMessage, reserve bool, authorize func() error) (*DirectASKReservation, error) {
	digest, err := source.Digest()
	if err != nil || source.ValidateWire(wire) != nil || source.Scope != j.scope || j.isLocal() {
		return nil, ErrFenced
	}
	key, _ := source.DeliveryKey()
	record, err := json.Marshal(DirectASKReservation{Source: source, Wire: wire})
	if err != nil || len(record) > 98304 {
		return nil, ErrConflict
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, _, err = checkLease(ctx, tx, lease); err != nil {
		return nil, err
	}
	if authorize == nil {
		return nil, ErrFenced
	}
	if err = authorize(); err != nil {
		return nil, err
	}
	var owned string
	var retired bool
	if err = tx.QueryRowContext(ctx, `SELECT ownership,EXISTS(SELECT 1 FROM worker_ownership_retirement) FROM worker_dispatch_meta WHERE singleton=1`).Scan(&owned, &retired); err != nil {
		return nil, err
	}
	var bound transport.NativeWorkerOwnership
	if retired {
		return nil, ErrRetired
	}
	if json.Unmarshal([]byte(owned), &bound) != nil || !transport.SameNativeWorkerOwnership(bound, source.Ownership) {
		return nil, ErrFenced
	}
	var raw []byte
	var oldDigest, state string
	err = tx.QueryRowContext(ctx, `SELECT digest,record,state FROM worker_direct_admissions WHERE admission_id=? OR delivery_key=?`, source.AdmissionID, hex.EncodeToString(key[:])).Scan(&oldDigest, &raw, &state)
	if err == nil {
		if oldDigest != hex.EncodeToString(digest[:]) || !bytes.Equal(raw, record) {
			return nil, ErrConflict
		}
		if err = tx.Commit(); err != nil {
			return nil, err
		}
		return &DirectASKReservation{Source: source, Wire: append(json.RawMessage(nil), wire...), State: state}, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if !reserve {
		return nil, tx.Commit()
	}
	var count int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM worker_direct_admissions`).Scan(&count); err != nil {
		return nil, err
	}
	if count >= maxCommands {
		return nil, ErrFull
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO worker_direct_admissions(admission_id,delivery_key,digest,record,state) VALUES(?,?,?,?,'reserved')`, source.AdmissionID, hex.EncodeToString(key[:]), hex.EncodeToString(digest[:]), record); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return &DirectASKReservation{Source: source, Wire: append(json.RawMessage(nil), wire...), State: "reserved"}, nil
}
