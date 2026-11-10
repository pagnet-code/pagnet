package sessionworker

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/pagnet-code/pagnet/internal/accountmessage"
	"github.com/pagnet-code/pagnet/transport"
)

func validateAccountOperation(op Operation, p transport.NativeDispatchProof) error {
	if (op.SourceCommandID != "" && op.SourceCommandID != p.SourceCommandID) || (op.SourceAdmissionID != "" && op.SourceAdmissionID != p.SourceAdmissionID) || op.Input != "" || op.InputKind != "account_message" || op.SealedAccountMessage == nil || op.SourceAccountMessage == nil || p.AccountMessageSource == nil || !transport.ValidNativeSourceUnion(op.SourceTask, op.SourceInvocation, op.SourceAccountMessage) || !transport.ValidNativeSourceUnion(p.TaskSource, p.InvocationSource, p.AccountMessageSource) || !bytes.Equal(op.SourceAccountMessage.CanonicalJSON(), p.AccountMessageSource.CanonicalJSON()) {
		return errors.New("invalid sealed account operation")
	}
	s := op.SourceAccountMessage
	sealed := accountmessage.Sealed{V: 1, MessageID: s.MessageID, BindingDigest: s.BindingDigest, SealedDigest: s.SealedDigest, Envelope: *op.SealedAccountMessage, Descriptor: accountmessage.Descriptor(s.Descriptor)}
	return sealed.Validate()
}

func (j *Journal) initializeAccountInputs() error {
	for _, q := range []string{
		`CREATE TABLE IF NOT EXISTS worker_account_inputs(sequence INTEGER PRIMARY KEY,command_id TEXT NOT NULL UNIQUE,source BLOB NOT NULL,proof BLOB NOT NULL,envelope BLOB NOT NULL)`,
		`CREATE TRIGGER IF NOT EXISTS worker_account_inputs_no_update BEFORE UPDATE ON worker_account_inputs BEGIN SELECT RAISE(ABORT,'immutable account input'); END`,
		`CREATE TRIGGER IF NOT EXISTS worker_account_inputs_no_delete BEFORE DELETE ON worker_account_inputs BEGIN SELECT RAISE(ABORT,'immutable account input'); END`,
	} {
		if _, err := j.db.Exec(q); err != nil {
			return err
		}
	}
	return nil
}

func accountInputBytes(op Operation, p transport.NativeDispatchProof) ([]byte, []byte, []byte, error) {
	if err := validateAccountOperation(op, p); err != nil {
		return nil, nil, nil, err
	}
	proof, err := MarshalNativeJSON(p)
	if err != nil {
		return nil, nil, nil, err
	}
	envelope, err := json.Marshal(op.SealedAccountMessage)
	return op.SourceAccountMessage.CanonicalJSON(), proof, envelope, err
}

func (j *Journal) verifyAccountInput(ctx context.Context, tx *sql.Tx, sequence int64, op Operation, p transport.NativeDispatchProof) error {
	source, proof, envelope, err := accountInputBytes(op, p)
	if err != nil {
		return err
	}
	var command string
	var storedSource, storedProof, storedEnvelope []byte
	if err = tx.QueryRowContext(ctx, `SELECT command_id,source,proof,envelope FROM worker_account_inputs WHERE sequence=?`, sequence).Scan(&command, &storedSource, &storedProof, &storedEnvelope); err != nil {
		return err
	}
	if command != p.SourceCommandID || !bytes.Equal(source, storedSource) || !bytes.Equal(proof, storedProof) || !bytes.Equal(envelope, storedEnvelope) {
		return ErrConflict
	}
	return nil
}

func (j *Journal) admitAccountInput(ctx context.Context, tx *sql.Tx, sequence int64, op Operation, p transport.NativeDispatchProof, current *Admission) error {
	source, proof, envelope, err := accountInputBytes(op, p)
	if err != nil {
		return err
	}
	d := op.SourceAccountMessage.Descriptor
	connected, _ := time.Parse(time.RFC3339Nano, d.RunnerConnectedAt)
	created, _ := time.Parse(time.RFC3339Nano, d.CreatedAt)
	expires, _ := time.Parse(time.RFC3339Nano, d.ExpiresAt)
	now := time.Now()
	if current == nil || current.Scope != j.scope || current.NetworkID != d.NetworkID || current.Kind != "worker" || current.NativeAdmissionID != p.SourceAdmissionID || current.RunnerID != p.SourceRunnerID || !current.RunnerEpoch.Equal(p.SourceRunnerEpoch) || current.BootID != p.SourceBootID || d.TenantID != j.scope.TenantID || d.OwnerUserID != j.scope.AccountID || d.HostID != j.scope.HostID || d.TargetInstanceID != j.scope.InstanceID || d.RunnerID != p.SourceRunnerID || !connected.Equal(p.SourceRunnerEpoch) || now.Before(created) || !now.Before(expires) {
		return ErrConflict
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO worker_account_inputs(sequence,command_id,source,proof,envelope) VALUES(?,?,?,?,?)`, sequence, p.SourceCommandID, source, proof, envelope)
	return err
}

// accountInputForTurn binds native execution to the immutable admitted ciphertext.
func (j *Journal) accountInputForTurn(ctx context.Context, tx *sql.Tx, source NativeTurnSource) error {
	if source.SourceAccountMessage == nil || source.InputKind != "account_message" || !transport.ValidNativeSourceUnion(source.SourceTask, source.SourceInvocation, source.SourceAccountMessage) {
		return ErrConflict
	}
	var command string
	var storedSource, proof []byte
	if err := tx.QueryRowContext(ctx, `SELECT command_id,source,proof FROM worker_account_inputs WHERE sequence=?`, source.Sequence).Scan(&command, &storedSource, &proof); err != nil {
		return err
	}
	var p transport.NativeDispatchProof
	if json.Unmarshal(proof, &p) != nil || command != source.SourceCommandID || p.SourceCommandID != source.SourceCommandID || p.SourceAdmissionID != source.SourceAdmissionID || !bytes.Equal(storedSource, source.SourceAccountMessage.CanonicalJSON()) || p.AccountMessageSource == nil || !bytes.Equal(storedSource, p.AccountMessageSource.CanonicalJSON()) {
		return ErrConflict
	}
	return nil
}

// verifyAccountInputForExecution checks the durable record before decryption.
func (j *Journal) verifyAccountInputForExecution(ctx context.Context, sequence int64, commandID string, op Operation) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var raw []byte
	var state, storedCommand string
	if err = tx.QueryRowContext(ctx, `SELECT a.proof,i.state,i.command_id FROM worker_account_inputs a JOIN worker_intent i ON i.sequence=a.sequence WHERE a.sequence=?`, sequence).Scan(&raw, &state, &storedCommand); err != nil {
		return err
	}
	var p transport.NativeDispatchProof
	if json.Unmarshal(raw, &p) != nil || state != "admitted" || commandID != storedCommand || commandID != p.SourceCommandID || op.SourceCommandID != p.SourceCommandID || op.SourceAdmissionID != p.SourceAdmissionID {
		return ErrConflict
	}
	return j.verifyAccountInput(ctx, tx, sequence, op, p)
}
