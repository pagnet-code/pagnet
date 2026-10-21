package sessionworker

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sync"

	"github.com/pagnet-code/pagnet/internal/session"
	"github.com/pagnet-code/pagnet/transport"
)

// A producer is an unexported, worker-memory append capability. Native readers
// get only its paired Observe/Retire registration; IPC has no append operation.
// Source descriptors, generations and ciphertext are never rewritten to retire.
type nativeSourceProducer struct {
	journal          *Journal
	originID         string
	generation       string
	origin           json.RawMessage
	closed           bool // journal mutex
	stoppedCommitted bool // own reserved terminal capacity consumed
}

func (p *nativeSourceProducer) owns(origin json.RawMessage) bool {
	return bytes.Equal(p.origin, origin)
}

func (j *Journal) initializeSourceRetirement() error {
	for _, q := range []string{
		`CREATE TABLE IF NOT EXISTS worker_source_registration_protocol(singleton INTEGER PRIMARY KEY CHECK(singleton=1))`,
		`CREATE TABLE IF NOT EXISTS worker_source_registration(origin_id TEXT PRIMARY KEY,native_generation TEXT NOT NULL UNIQUE,quiesced INTEGER NOT NULL CHECK(quiesced IN (0,1)))`,
	} {
		if _, err := j.db.Exec(q); err != nil {
			return err
		}
	}
	columns, err := j.db.Query(`PRAGMA table_info(worker_source_registration)`)
	if err != nil {
		return err
	}
	hasProof := false
	for columns.Next() {
		var cid, notNull, pk int
		var name, typ string
		var defaultValue any
		if err = columns.Scan(&cid, &name, &typ, &notNull, &defaultValue, &pk); err != nil {
			columns.Close()
			return err
		}
		hasProof = hasProof || name == "activation_proof"
	}
	err = columns.Err()
	columns.Close()
	if err != nil {
		return err
	}
	if !hasProof {
		if _, err = j.db.Exec(`ALTER TABLE worker_source_registration ADD COLUMN activation_proof BLOB`); err != nil {
			return err
		}
	}
	var registered int
	if err := j.db.QueryRow(`SELECT COUNT(*) FROM worker_source_registration_protocol`).Scan(&registered); err != nil {
		return err
	}
	j.strictSourceProducer = registered > 0
	var count int
	if err := j.db.QueryRow(`SELECT COUNT(*) FROM worker_source_registration`).Scan(&count); err != nil {
		return err
	}
	if count > maxPendingObservations || (count > 0 && registered == 0) {
		return errors.New("original source registration protocol is corrupt")
	}
	rows, err := j.db.Query(`SELECT origin_id,native_generation,activation_proof FROM worker_source_registration`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var id, generation string
		var activation []byte
		if err = rows.Scan(&id, &generation, &activation); err != nil {
			rows.Close()
			return err
		}
		if activation != nil {
			var proof transport.NativeDispatchProof
			if json.Unmarshal(activation, &proof) != nil || proof.DispatchSequence <= 0 || proof.OwnershipGeneration != j.scope.Generation || proof.OwnershipID == "" || proof.SourceCommandID == "" || proof.SourceAdmissionID == "" || proof.SourceRunnerID == "" || proof.SourceBootID == "" || proof.SourceRunnerEpoch.IsZero() {
				rows.Close()
				return ErrConflict
			}
		}
		if id == "" || len(id) > 256 || generation == "" || len(generation) > 256 {
			rows.Close()
			return errors.New("original source registration is corrupt")
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if err = j.db.QueryRow(`SELECT COUNT(*) FROM worker_source_registration r JOIN worker_observations o ON json_extract(o.payload,'$.origin.id')=r.origin_id OR json_extract(o.payload,'$.nativeGeneration')=r.native_generation WHERE json_extract(o.payload,'$.origin.id')!=r.origin_id OR json_extract(o.payload,'$.nativeGeneration')!=r.native_generation`).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return errors.New("original source registration binding is corrupt")
	}
	if err = j.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM worker_source_registration r WHERE r.activation_proof IS NOT NULL AND NOT EXISTS(SELECT 1 FROM worker_dispatch_meta d WHERE json_extract(d.ownership,'$.id')=json_extract(r.activation_proof,'$.ownershipId')))`).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return errors.New("original activation ownership binding is corrupt")
	}

	// OpenJournal owns the exclusive worker lifetime lock. No prior callback or
	// in-memory append capability survives that worker's death. New owners can
	// only launch fresh ownedDriver generations; private IPC cannot append.
	if _, err := j.db.Exec(`UPDATE worker_source_registration SET quiesced=1`); err != nil {
		return err
	}
	return j.reclaimSourceStreamsLocked(context.Background())
}
func (j *Journal) registerNativeSource(ctx context.Context, generation string, origin json.RawMessage) (*nativeSourceProducer, error) {
	return j.registerNativeSourceActivation(ctx, generation, origin, false)
}

func (j *Journal) registerNativeSourceActivation(ctx context.Context, generation string, origin json.RawMessage, bind bool) (*nativeSourceProducer, error) {
	var descriptor struct {
		ID               string `json:"id"`
		NativeGeneration string `json:"nativeGeneration"`
	}
	if generation == "" || len(generation) > 256 || len(origin) > 8192 || json.Unmarshal(origin, &descriptor) != nil || descriptor.ID == "" || len(descriptor.ID) > 256 || (descriptor.NativeGeneration != "" && descriptor.NativeGeneration != generation) {
		return nil, errors.New("invalid original source producer")
	}
	p := &nativeSourceProducer{journal: j, originID: descriptor.ID, generation: generation, origin: append(json.RawMessage(nil), origin...)}
	j.mu.Lock()
	defer j.mu.Unlock()
	for active := range j.sourceProducers {
		if active.originID == p.originID || active.generation == generation {
			return nil, ErrConflict
		}
	}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var pending, total int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(SUM(size),0)+(SELECT COALESCE(SUM(size),0) FROM worker_source_captures)+(SELECT COALESCE(SUM(size),0) FROM worker_source_dispositions)+(SELECT COALESCE(SUM(size),0) FROM worker_output_spools)+(SELECT COALESCE(SUM(length(payload)),0) FROM worker_resource_interruptions)+(SELECT COALESCE(SUM(length(payload)),0) FROM worker_resource_settlements)+(SELECT COALESCE(SUM(length(payload)),0) FROM worker_owner_stop_settlements)+(SELECT COALESCE(SUM(length(payload)),0) FROM worker_stopped_receipts) FROM worker_observations`).Scan(&pending, &total); err != nil {
		return nil, err
	}
	var unmarked int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM worker_observations o WHERE NOT EXISTS(SELECT 1 FROM worker_source_dispositions d WHERE d.observation_id=o.id)`).Scan(&unmarked); err != nil {
		return nil, err
	}
	terminalRows, terminalBytes, _, err := terminalReservationsTx(ctx, tx)
	if err != nil {
		return nil, err
	}
	reserved := j.sourceStopReservationsLocked() + 1
	if pending+reserved+terminalRows > maxPendingObservations || total+unmarked*sourceDispositionReserveBytes+reserved*sourceStopReserveBytes+terminalBytes > maxPendingObservationBytes {
		return nil, ErrFull
	}
	var count int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM worker_source_registration`).Scan(&count); err != nil {
		return nil, err
	}
	if count >= maxPendingObservations {
		return nil, ErrFull
	}
	var existing int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM worker_source_registration WHERE origin_id=? OR native_generation=?`, p.originID, generation).Scan(&existing); err != nil {
		return nil, err
	}
	if existing > 0 {
		return nil, ErrConflict
	}
	var activation []byte
	if bind {
		activation, err = j.activationDispatchProofTx(ctx, tx, generation, origin)
		if err != nil {
			return nil, err
		}
	}
	// Existing quiesced registrations cannot be revived. A fresh launch uses
	// ownedDriver's fresh generation and authenticated new original origin.
	if _, err = tx.ExecContext(ctx, `INSERT INTO worker_source_registration(origin_id,native_generation,quiesced,activation_proof) VALUES(?,?,0,?)`, p.originID, generation, activation); err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT OR IGNORE INTO worker_source_registration_protocol VALUES(1)`); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	j.strictSourceProducer = true
	if j.sourceProducers == nil {
		j.sourceProducers = make(map[*nativeSourceProducer]bool)
	}
	j.sourceProducers[p] = true
	return p, nil
}
func (j *Journal) retireNativeSource(ctx context.Context, p *nativeSourceProducer) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if p == nil || p.journal != j {
		return ErrFenced
	}
	p.closed = true // invalidate memory capability even if SQLite commit is uncertain
	delete(j.sourceProducers, p)
	if _, err := j.db.ExecContext(ctx, `UPDATE worker_source_registration SET quiesced=1 WHERE origin_id=? AND native_generation=?`, p.originID, p.generation); err != nil {
		return err
	}
	return j.reclaimSourceStreamsLocked(ctx)
}

// Reclamation is bounded and selects eligible generations, so one unresolved
// old source cannot starve later settled generations. Turn pruning additionally
// requires the original contiguous intent ACK floor and native completion.
func (j *Journal) reclaimSourceStreamsLocked(ctx context.Context) error {
	if len(j.sourceRetries) > 0 {
		return nil
	}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = j.reclaimSourceStreamsTx(ctx, tx, false); err != nil {
		return err
	}
	return tx.Commit()
}

func (j *Journal) reclaimSourceStreamsTx(ctx context.Context, tx *sql.Tx, retiring bool) error {
	var err error
	limit := 32
	if retiring {
		limit = maxPendingObservations
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM worker_turn_sources AS t WHERE NOT EXISTS(SELECT 1 FROM worker_invocation_streams s WHERE s.sequence=t.sequence AND s.closed=0) AND completed=1 AND NOT EXISTS(SELECT 1 FROM worker_terminal_reservations q WHERE q.sequence=t.sequence) AND NOT EXISTS(SELECT 1 FROM worker_resource_interruptions q WHERE q.sequence=t.sequence) AND NOT EXISTS(SELECT 1 FROM worker_output_spools p WHERE p.sequence=t.sequence) AND sequence<=(SELECT retired FROM worker_meta WHERE singleton=1) AND EXISTS(SELECT 1 FROM worker_source_registration r WHERE r.quiesced=1 AND r.native_generation=t.native_generation) AND NOT EXISTS(SELECT 1 FROM worker_interaction_sources i WHERE i.native_generation=t.native_generation AND i.logical_turn=t.logical_turn) AND NOT EXISTS(SELECT 1 FROM worker_observations o WHERE json_extract(o.payload,'$.nativeGeneration')=t.native_generation AND json_extract(o.payload,'$.turnSource.logicalTurnId')=t.logical_turn)`+j.localStreamRetentionPredicate()); err != nil {
		return err
	}
	// The server can keep referring to the latest activation after all its
	// output drains. Preserve that generation (including dispatch ties) and
	// unbound legacy sources until authenticated ownership retirement commits.
	rows, err := tx.QueryContext(ctx, `SELECT r.origin_id FROM worker_source_registration r WHERE r.quiesced=1 AND NOT EXISTS(SELECT 1 FROM worker_resource_interruptions q WHERE q.native_generation=r.native_generation) AND NOT EXISTS(SELECT 1 FROM worker_output_spools p WHERE p.native_generation=r.native_generation) AND NOT EXISTS(SELECT 1 FROM worker_observations o WHERE json_extract(o.payload,'$.origin.id')=r.origin_id OR json_extract(o.payload,'$.nativeGeneration')=r.native_generation) AND NOT EXISTS(SELECT 1 FROM worker_intent w WHERE json_valid(w.result) AND json_extract(w.result,'$.nativeGeneration')=r.native_generation) AND NOT EXISTS(SELECT 1 FROM worker_observation_sequence s WHERE s.origin_id=r.origin_id) AND NOT EXISTS(SELECT 1 FROM worker_turn_sources t WHERE t.native_generation=r.native_generation) AND NOT EXISTS(SELECT 1 FROM worker_interaction_sources i WHERE i.native_generation=r.native_generation) AND NOT EXISTS(SELECT 1 FROM worker_source_captures c LEFT JOIN worker_observations o ON o.id=c.id WHERE o.id IS NULL) AND NOT EXISTS(SELECT 1 FROM worker_content_fragments f LEFT JOIN worker_observations o ON o.id=f.observation_id WHERE o.id IS NULL) AND (? OR NOT EXISTS(SELECT 1 FROM worker_dispatch_meta) OR (r.activation_proof IS NOT NULL AND json_extract(r.activation_proof,'$.dispatchSequence') < (SELECT MAX(json_extract(newer.activation_proof,'$.dispatchSequence')) FROM worker_source_registration newer))) ORDER BY r.origin_id LIMIT ?`, retiring, limit)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, id := range ids {
		active := false
		for producer := range j.sourceProducers {
			if producer.originID == id && !producer.closed {
				active = true
				break
			}
		}
		if active {
			continue
		}
		if _, err = tx.ExecContext(ctx, `DELETE FROM worker_stopped_receipts WHERE json_extract(payload,'$.observation.origin.id')=?`, id); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `DELETE FROM worker_source_stream WHERE origin_id=?`, id); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `DELETE FROM worker_source_registration WHERE origin_id=? AND quiesced=1`, id); err != nil {
			return err
		}
	}
	return nil
}

func (o *SessionOwner) nativeEventRegistration(instanceID string) session.NativeEventObserverRegistration {
	o.mu.Lock()
	if o.nativeObserverRegistered || o.closing {
		o.mu.Unlock()
		return session.NativeEventObserverRegistration{Observe: func(session.SessionEvent) error { return ErrFenced }, Retire: func() {}}
	}
	o.nativeObserverRegistered = true
	o.nativeObserverWG.Add(1)
	generation := o.generation
	origin := append(json.RawMessage(nil), o.origin...)
	o.mu.Unlock()
	o.journal.mu.Lock()
	var producer *nativeSourceProducer
	for candidate := range o.journal.sourceProducers {
		if !candidate.closed && candidate.generation == generation && candidate.owns(origin) {
			producer = candidate
			break
		}
	}
	o.journal.mu.Unlock()
	var err error
	if producer == nil {
		producer, err = o.journal.registerNativeSource(o.ctx, generation, origin)
	}
	if err != nil {
		o.nativeObserverWG.Done()
		o.failPersistence(err)
		return session.NativeEventObserverRegistration{Observe: func(session.SessionEvent) error { return err }, Retire: func() {}}
	}
	observer, _, batch := o.nativeCapturedSourceObservers(instanceID, producer, generation, origin)
	return nativeObserverRegistration(observer, func() {
		defer o.nativeObserverWG.Done()
		o.releaseNativeTaskPins(generation)
		if err := o.journal.retireNativeSource(context.Background(), producer); err != nil {
			o.failPersistence(err)
		}
	}, batch)
}
func nativeObserverRegistration(observer session.NativeEventObserver, retire func(), batches ...session.NativeEventBatchObserver) session.NativeEventObserverRegistration {
	var gate sync.RWMutex
	closed := false
	var batch session.NativeEventBatchObserver
	if len(batches) > 0 {
		batch = batches[0]
	}
	registration := session.NativeEventObserverRegistration{
		Observe: func(event session.SessionEvent) error {
			gate.RLock()
			defer gate.RUnlock()
			if closed {
				return ErrFenced
			}
			return observer(event)
		},
		Retire: func() {
			gate.Lock()
			defer gate.Unlock()
			if closed {
				return
			}
			closed = true
			retire()
		},
	}
	if batch != nil {
		registration.ObserveBatch = func(events []session.SessionEvent) error {
			gate.RLock()
			defer gate.RUnlock()
			if closed {
				return ErrFenced
			}
			return batch(events)
		}
	}
	return registration
}

// Active original producers reserve their eventual genuine process EOF within
// the existing aggregate quota. No extra queue or lifetime tombstone is added.
const sourceStopReserveBytes = 64 << 10

func (j *Journal) sourceStopReservationsLocked() int {
	count := 0
	for p := range j.sourceProducers {
		if !p.closed && !p.stoppedCommitted {
			count++
		}
	}
	return count
}

// requireNativeReadersQuiesced fences explicit fresh restart until every old
// reader has committed its final capture and surrendered its append capability.
// Pending ciphertext remains untouched; backend origin admission still orders
// receipt delivery before accepting a replacement native generation.
func (j *Journal) requireNativeReadersQuiesced(ctx context.Context) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	for producer := range j.sourceProducers {
		if !producer.closed {
			return session.ErrBusy
		}
	}
	var active int
	if err := j.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM worker_source_registration WHERE quiesced=0`).Scan(&active); err != nil {
		return err
	}
	if active != 0 {
		return session.ErrBusy
	}
	return nil
}

// Bind only the original accepted dispatch and admission, before native exec.
// A missing ownership record denotes the older standalone/local protocol.
func (j *Journal) activationDispatchProofTx(ctx context.Context, tx *sql.Tx, generation string, raw json.RawMessage) ([]byte, error) {
	var ownership string
	err := tx.QueryRowContext(ctx, `SELECT ownership FROM worker_dispatch_meta WHERE singleton=1`).Scan(&ownership)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var owned transport.NativeWorkerOwnership
	var origin transport.NativeObservationOrigin
	if json.Unmarshal([]byte(ownership), &owned) != nil || json.Unmarshal(raw, &origin) != nil || origin.ID == "" || origin.NativeGeneration != generation || origin.HostID != j.scope.HostID || origin.InstanceID != j.scope.InstanceID || origin.Runtime != owned.Runtime || origin.CreatedAt.IsZero() {
		return nil, ErrConflict
	}
	var proofRaw, admissionRaw []byte
	var sequence int64
	err = tx.QueryRowContext(ctx, `SELECT d.proof,a.admission,d.dispatch_sequence FROM worker_dispatches d JOIN worker_intent_admission a ON a.sequence=d.operation_sequence WHERE d.command_id=?`, origin.CommandID).Scan(&proofRaw, &admissionRaw, &sequence)
	if err != nil {
		return nil, err
	}
	var proof transport.NativeDispatchProof
	var admission Admission
	if json.Unmarshal(proofRaw, &proof) != nil || json.Unmarshal(admissionRaw, &admission) != nil || proof.DispatchSequence != sequence || proof.OwnershipID != owned.ID || proof.OwnershipGeneration != j.scope.Generation || proof.SourceCommandID != origin.CommandID || proof.SourceAdmissionID != origin.NativeAdmissionID || proof.SourceRunnerID != origin.RunnerID || !proof.SourceRunnerEpoch.Equal(origin.RunnerEpoch) || proof.SourceBootID != origin.BootID || admission.Scope != j.scope || admission.NativeAdmissionID != proof.SourceAdmissionID || admission.RunnerID != proof.SourceRunnerID || !admission.RunnerEpoch.Equal(proof.SourceRunnerEpoch) || admission.BootID != proof.SourceBootID {
		return nil, ErrConflict
	}
	return proofRaw, nil
}
