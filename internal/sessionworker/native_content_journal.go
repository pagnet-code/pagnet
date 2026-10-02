package sessionworker

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/pagnet-code/pagnet/nativecontent"
	"github.com/pagnet-code/pagnet/transport"
)

// This budget counts actual immutable encoded ciphertext, independently of
// small observations/private captures. Two maximum vendor request/answer
// transfers fit; an unlimited approval flood does not.
const maxWorkerContentBytes = 128 << 20

func (j *Journal) initializeContentTransfers() error {
	_, err := j.db.Exec(`CREATE TABLE IF NOT EXISTS worker_content_fragments(observation_id TEXT NOT NULL,content_id TEXT NOT NULL,ordinal INTEGER NOT NULL,payload BLOB NOT NULL,size INTEGER NOT NULL,PRIMARY KEY(content_id,ordinal))`)
	if err != nil {
		return err
	}
	var size int64
	if err = j.db.QueryRow(`SELECT COALESCE(SUM(size),0) FROM worker_content_fragments`).Scan(&size); err != nil {
		return err
	}
	if size > maxWorkerContentBytes {
		return errors.New("worker encrypted content exceeds aggregate bound")
	}
	return j.verifyStoredContent()

}

func validateOriginalTransfer(observation NativeObservation, transfer nativecontent.Transfer) error {
	ref := transfer.Reference
	var attached *transport.NativeContentReference
	if observation.Inspection != nil && ref.Purpose == "interaction_detail" {
		attached = observation.Inspection.DetailContent
	}
	if observation.Resolution != nil && ref.Purpose == "interaction_answer" {
		attached = observation.Resolution.DetailContent
	}
	expected, _ := json.Marshal(attached)
	actual, _ := json.Marshal(ref)
	if attached == nil || string(expected) != string(actual) {
		return errors.New("encrypted transfer is not attached to exact observation")
	}

	var origin struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(observation.Origin, &origin) != nil || ref.ObservationID != observation.ID || ref.OriginID != origin.ID || ref.NativeGeneration != observation.NativeGeneration || ref.NativeSessionID != observation.NativeSessionID || ref.SubjectID != observation.InteractionID || ref.SubjectType != "runtime_interaction" {
		return errors.New("encrypted native content differs from original source")
	}
	commitment, err := nativecontent.CiphertextCommitment(ref, transfer.Fragments)
	if err != nil || commitment != ref.CiphertextDigest {
		return errors.New("encrypted native content is incomplete")
	}
	return nil
}

// Called in the observation admission transaction; a partial transfer never
// becomes visible as a complete original source.
func insertOriginalTransfer(ctx context.Context, tx *sql.Tx, observation NativeObservation, transfer nativecontent.Transfer) error {
	if err := validateOriginalTransfer(observation, transfer); err != nil {
		return err
	}
	var retained int64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(SUM(size),0) FROM worker_content_fragments`).Scan(&retained); err != nil {
		return err
	}
	rows := make([][]byte, len(transfer.Fragments))
	for i, fragment := range transfer.Fragments {
		raw, err := json.Marshal(fragment)
		if err != nil || len(raw) > 128<<10 {
			return errors.New("native encrypted fragment exceeds frame bound")
		}
		rows[i] = raw
		retained += int64(len(raw))
	}
	if retained > maxWorkerContentBytes {
		return ErrFull
	}
	for i, raw := range rows {
		if _, err := tx.ExecContext(ctx, `INSERT INTO worker_content_fragments(observation_id,content_id,ordinal,payload,size) VALUES(?,?,?,?,?)`, observation.ID, transfer.Reference.ContentID, i, raw, len(raw)); err != nil {
			return err
		}
	}
	return nil
}

// The observation digest and current lease are checked in the same read
// transaction; a superseded controller cannot drain private ciphertext.
func (j *Journal) ReadContentFragment(ctx context.Context, lease int64, observationID, digest, contentID string, ordinal int) (*transport.NativeContentFragment, error) {
	if observationID == "" || len(digest) != 64 || contentID == "" || ordinal < 0 || ordinal >= 320 {
		return nil, errors.New("invalid original content cursor")
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
	var actual string
	if err = tx.QueryRowContext(ctx, `SELECT digest FROM worker_observations WHERE id=?`, observationID).Scan(&actual); err != nil {
		return nil, err
	}
	if actual != digest {
		return nil, ErrConflict
	}
	var raw []byte
	if err = tx.QueryRowContext(ctx, `SELECT payload FROM worker_content_fragments WHERE observation_id=? AND content_id=? AND ordinal=?`, observationID, contentID, ordinal).Scan(&raw); err != nil {
		return nil, err
	}
	if len(raw) > 128<<10 {
		return nil, errors.New("stored native content frame exceeds bound")
	}
	var fragment transport.NativeContentFragment
	if err = json.Unmarshal(raw, &fragment); err != nil {
		return nil, err
	}
	if fragment.ContentID != contentID || fragment.Ordinal != ordinal {
		return nil, ErrConflict
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return &fragment, nil
}

func (j *Journal) verifyStoredContent() error {
	rows, err := j.db.Query(`SELECT DISTINCT observation_id,content_id FROM worker_content_fragments`)
	if err != nil {
		return err
	}
	type binding struct{ observation, content string }
	var bindings []binding
	for rows.Next() {
		var b binding
		if err = rows.Scan(&b.observation, &b.content); err != nil {
			rows.Close()
			return err
		}
		bindings = append(bindings, b)
		if len(bindings) > maxPendingObservations*2 {
			rows.Close()
			return ErrFull
		}
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, b := range bindings {
		var raw []byte
		if err = j.db.QueryRow(`SELECT payload FROM worker_observations WHERE id=?`, b.observation).Scan(&raw); err != nil {
			return errors.New("encrypted native content has no owning observation")
		}
		var observation NativeObservation
		if json.Unmarshal(raw, &observation) != nil {
			return errors.New("invalid content owner observation")
		}
		var ref *transport.NativeContentReference
		if observation.Inspection != nil && observation.Inspection.DetailContent != nil && observation.Inspection.DetailContent.ContentID == b.content {
			ref = observation.Inspection.DetailContent
		}
		if observation.Resolution != nil && observation.Resolution.DetailContent != nil && observation.Resolution.DetailContent.ContentID == b.content {
			ref = observation.Resolution.DetailContent
		}
		if ref == nil || ref.ObservationID != b.observation {
			return errors.New("stored content is not attached to its original source")
		}
		fragments, err := j.db.Query(`SELECT ordinal,payload,size FROM worker_content_fragments WHERE observation_id=? AND content_id=? ORDER BY ordinal`, b.observation, b.content)
		if err != nil {
			return err
		}
		digest, verifyErr := nativecontent.CiphertextCommitmentStream(*ref, func() (transport.NativeContentFragment, bool, error) {
			if !fragments.Next() {
				return transport.NativeContentFragment{}, false, fragments.Err()
			}
			var ordinal, size int
			var payload []byte
			if err := fragments.Scan(&ordinal, &payload, &size); err != nil {
				return transport.NativeContentFragment{}, false, err
			}
			if len(payload) != size || size > 128<<10 {
				return transport.NativeContentFragment{}, false, errors.New("stored content fragment size is invalid")
			}
			var fragment transport.NativeContentFragment
			if err := json.Unmarshal(payload, &fragment); err != nil {
				return fragment, false, err
			}
			if fragment.Ordinal != ordinal || fragment.ContentID != b.content {
				return fragment, false, ErrConflict
			}
			return fragment, true, nil
		})
		fragments.Close()
		if verifyErr != nil || digest != ref.CiphertextDigest {
			return errors.New("stored encrypted native content is incomplete or corrupt")
		}
	}
	return nil
}
