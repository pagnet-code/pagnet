package sessionworker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	"github.com/pagnet-code/pagnet/transport"
)

// CloudInvocationSourceRequest names a genuinely retained operation. Generation
// and session IDs are outputs, never adoption credentials supplied by a caller.
type CloudInvocationSourceRequest struct {
	Sequence    int64                            `json:"sequence"`
	CommandID   string                           `json:"commandId"`
	AdmissionID string                           `json:"admissionId"`
	Invocation  transport.NativeInvocationSource `json:"invocation"`
}
type CloudInvocationSourceResult struct {
	Source *NativeTurnSource `json:"source,omitempty"`
	State  string            `json:"state"`
	Ready  ReadinessToken    `json:"ready"`
}

func (j *Journal) cloudInvocationSource(ctx context.Context, lease int64, r CloudInvocationSourceRequest) (*CloudInvocationSourceResult, error) {
	if j.isLocal() || r.Sequence <= 0 || r.CommandID == "" || len(r.CommandID) > 256 || r.AdmissionID == "" || len(r.AdmissionID) > 256 || r.Invocation.Validate() != nil {
		return nil, ErrFenced
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	tx, e := j.db.BeginTx(ctx, nil)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	if _, _, e = checkLease(ctx, tx, lease); e != nil {
		return nil, e
	}
	var command, kind, state string
	var raw []byte
	e = tx.QueryRowContext(ctx, `SELECT i.command_id,i.kind,i.state,a.admission FROM worker_intent i JOIN worker_intent_admission a ON a.sequence=i.sequence WHERE i.sequence=?`, r.Sequence).Scan(&command, &kind, &state, &raw)
	if e != nil {
		return nil, e
	}
	var admission Admission
	if command != r.CommandID || kind != "prompt" || json.Unmarshal(raw, &admission) != nil || admission.Scope != j.scope || admission.NativeAdmissionID != r.AdmissionID || admission.TenantID != j.scope.TenantID {
		return nil, ErrConflict
	}
	// Account representatives have a network-independent original controller;
	// the exact invocation's network/AAD is bound by its committed turn source.
	// Ordinary fixed-network workers must still match their admitted network.
	if admission.NetworkID != "" {
		if admission.NetworkID != r.Invocation.InputAAD.NetworkID {
			return nil, ErrConflict
		}
	} else if admission.Kind != "representative" {
		return nil, ErrConflict
	}
	result := &CloudInvocationSourceResult{State: state, Ready: j.cloudReadiness.snapshot()}
	rows, e := tx.QueryContext(ctx, `SELECT sequence,logical_turn,native_generation,native_session,source_command,source_admission,input_kind,source_task,source_invocation FROM worker_turn_sources WHERE sequence=? AND source_command=? AND source_admission=? LIMIT 2`, r.Sequence, r.CommandID, r.AdmissionID)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	for rows.Next() {
		var source NativeTurnSource
		var task, invocation string
		if e = rows.Scan(&source.Sequence, &source.LogicalTurnID, &source.NativeGeneration, &source.NativeSessionID, &source.SourceCommandID, &source.SourceAdmissionID, &source.InputKind, &task, &invocation); e != nil {
			return nil, e
		}
		if result.Source != nil {
			return nil, ErrConflict
		} // No guessed "latest" realization.
		var original transport.NativeInvocationSource
		if source.InputKind != "invocation" || task != "" || json.Unmarshal([]byte(invocation), &original) != nil || original.Validate() != nil || original.InvocationID != r.Invocation.InvocationID || !bytes.Equal(original.InputAAD.CanonicalBytes(), r.Invocation.InputAAD.CanonicalBytes()) {
			return nil, ErrConflict
		}
		source.SourceInvocation = &original
		result.Source = &source
	}
	if e = rows.Err(); e != nil {
		return nil, e
	}
	if e = rows.Close(); e != nil {
		return nil, e
	}
	if result.Source == nil && state != "admitted" {
		return nil, errors.New("original invocation completed without retained native source")
	}
	if e = tx.Commit(); e != nil {
		return nil, e
	}
	return result, nil
}
