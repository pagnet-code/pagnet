package sessionworker

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/pagnet-code/pagnet/transport"
)

// Private observations with no accepted turn/source adapter are local captures,
// not unpublished task effects. Only original reader quiescence plus the exact
// backend retirement transaction permits their removal. Supported observations,
// accepted-turn evidence and authenticated quarantine dispositions stay fenced.
func (j *Journal) collectClosedPrivateObservationsTx(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, `SELECT o.id,o.digest,o.payload FROM worker_observations o JOIN worker_source_registration r ON r.origin_id=json_extract(o.payload,'$.origin.id') AND r.native_generation=json_extract(o.payload,'$.nativeGeneration') WHERE r.quiesced=1 AND NOT EXISTS(SELECT 1 FROM worker_source_dispositions d WHERE d.observation_id=o.id) LIMIT ?`, maxPendingObservations)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id, digest string
		var raw []byte
		if err = rows.Scan(&id, &digest, &raw); err != nil {
			rows.Close()
			return err
		}
		var o NativeObservation
		var origin transport.NativeObservationOrigin
		if len(raw) > maxFrame*3/4 || json.Unmarshal(raw, &o) != nil || o.ID != id || o.SourceDigest != digest || o.TurnSource != nil {
			continue
		}
		if json.Unmarshal(o.Origin, &origin) != nil || origin.HostID != j.scope.HostID || origin.InstanceID != j.scope.InstanceID || origin.NativeGeneration != o.NativeGeneration {
			continue
		}
		actual, digestErr := observationDigest(o)
		if digestErr != nil || actual != digest {
			continue
		}
		if _, wireErr := NativeBackendObservation(o); !errors.Is(wireErr, ErrNativeSourceUnsupported) {
			continue
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, id := range ids {
		for _, q := range []string{`DELETE FROM worker_observation_sequence WHERE observation_id=?`, `DELETE FROM worker_content_fragments WHERE observation_id=?`, `DELETE FROM worker_source_captures WHERE id=?`, `DELETE FROM worker_observations WHERE id=?`} {
			if _, err = tx.ExecContext(ctx, q, id); err != nil {
				return err
			}
		}
	}
	return nil
}
