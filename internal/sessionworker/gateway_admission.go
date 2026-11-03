package sessionworker

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/pagnet-code/pagnet/internal/managedgateway"
)

// gatewayAdmissionCapability is a memory-only pin installed by trusted owner
// composition. No IPC, controller, or wire descriptor can construct this token.
// This phase deliberately has no production installer or native submit caller.
type gatewayAdmissionCapability struct {
	journal *Journal
	pin     managedgateway.GatewayAdmission
}

type gatewayJournalAdmission struct {
	Admission managedgateway.GatewayAdmission
	State     string // reserved | unknown; neither state proves native acceptance
}

func gatewayPin(a managedgateway.GatewayAdmission) managedgateway.GatewayAdmission {
	a.OperationID = ""
	a.ASKID = ""
	a.ASKWireDigest = ""
	a.InputDigest = ""
	a.Deadline = time.Time{}
	return a
}

// installGatewayAdmissionCapability is owner-local composition only. Structural
// validation is not authentication; a future owner integration must authenticate
// the installation and verify the exact live endpoint before using this journal.
func (j *Journal) installGatewayAdmissionCapability(pin managedgateway.GatewayAdmission) (*gatewayAdmissionCapability, error) {
	if pin.Validate() != nil || j.isLocal() || pin.OwnerID != j.scope.AccountID || pin.TenantID != j.scope.TenantID || pin.HostID != j.scope.HostID || pin.WorkerInstanceID != j.scope.InstanceID || pin.WorkerIncarnation != j.scope.Generation {
		return nil, ErrFenced
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	c := &gatewayAdmissionCapability{journal: j, pin: gatewayPin(pin)}
	j.gatewayCapability = c
	return c, nil
}

func (j *Journal) initializeGatewayAdmissions() error {
	if _, err := j.db.Exec(`CREATE TABLE IF NOT EXISTS worker_gateway_admissions(operation_id TEXT PRIMARY KEY,ask_id TEXT NOT NULL UNIQUE,digest TEXT NOT NULL,admission BLOB NOT NULL,state TEXT NOT NULL CHECK(state IN ('reserved','unknown')))`); err != nil {
		return err
	}
	rows, err := j.db.Query(`SELECT operation_id,ask_id,digest,admission,state FROM worker_gateway_admissions`)
	if err != nil {
		return err
	}
	count := 0
	for rows.Next() {
		var operation, ask, digest, state string
		var raw []byte
		var a managedgateway.GatewayAdmission
		if err = rows.Scan(&operation, &ask, &digest, &raw, &state); err != nil {
			break
		}
		if err = json.Unmarshal(raw, &a); err != nil {
			break
		}
		sum, e := a.Digest()
		count++
		if e != nil || operation != a.OperationID || ask != a.ASKID || digest != hex.EncodeToString(sum[:]) || (state != "reserved" && state != "unknown") || j.isLocal() || a.OwnerID != j.scope.AccountID || a.TenantID != j.scope.TenantID || a.HostID != j.scope.HostID || a.WorkerInstanceID != j.scope.InstanceID || a.WorkerIncarnation != j.scope.Generation || count > maxCommands {
			err = errors.New("invalid gateway admission history")
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
	// Reservations never authorize repeating a possible native effect after loss
	// of the process that held the capability.
	_, err = j.db.Exec(`UPDATE worker_gateway_admissions SET state='unknown' WHERE state='reserved'`)
	return err
}

// admitGateway records immutable Gateway provenance separately from Cloud
// command IDs, ordinals and dispatch proofs. inserted is journal admission only,
// never permission to submit. This dormant phase has no native-effect path.
func (j *Journal) admitGateway(ctx context.Context, capability *gatewayAdmissionCapability, a managedgateway.GatewayAdmission, now time.Time) (out gatewayJournalAdmission, inserted bool, err error) {
	digest, err := a.Digest()
	if err != nil {
		return out, false, err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.isLocal() || capability == nil || capability != j.gatewayCapability || capability.journal != j || capability.pin != gatewayPin(a) {
		return out, false, ErrFenced
	}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return out, false, err
	}
	defer tx.Rollback()
	var retired bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM worker_ownership_retirement)`).Scan(&retired); err != nil {
		return out, false, err
	}
	if retired {
		return out, false, ErrRetired
	}
	var oldDigest string
	var raw []byte
	err = tx.QueryRowContext(ctx, `SELECT digest,admission,state FROM worker_gateway_admissions WHERE operation_id=? OR ask_id=?`, a.OperationID, a.ASKID).Scan(&oldDigest, &raw, &out.State)
	if err == nil {
		if oldDigest != hex.EncodeToString(digest[:]) {
			return out, false, ErrConflict
		}
		if err = json.Unmarshal(raw, &out.Admission); err != nil {
			return out, false, err
		}
		return out, false, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return out, false, err
	}
	if now.IsZero() || !now.Before(a.Deadline) {
		return out, false, ErrFenced
	}
	var count int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM worker_gateway_admissions`).Scan(&count); err != nil {
		return out, false, err
	}
	if count >= maxCommands {
		return out, false, ErrFull
	}
	raw, err = json.Marshal(a)
	if err != nil {
		return out, false, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO worker_gateway_admissions(operation_id,ask_id,digest,admission,state) VALUES(?,?,?,?,'reserved')`, a.OperationID, a.ASKID, hex.EncodeToString(digest[:]), raw); err != nil {
		return out, false, err
	}
	if err = tx.Commit(); err != nil {
		return out, false, err
	}
	return gatewayJournalAdmission{Admission: a, State: "reserved"}, true, nil
}
