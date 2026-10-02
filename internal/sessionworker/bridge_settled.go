package sessionworker

import (
	"bytes"
	"context"
	"strings"

	"github.com/pagnet-code/pagnet/internal/session"
)

// A settled refusal is authenticated controller metadata saying that the tool
// handler did not run. Only the worker's own exact completed row can permit one
// fresh endpoint call; an unavailable or unbound source is not that proof.
func (o *SessionOwner) forwardBridgeCall(ctx context.Context, call BridgeCall) BridgeResult {
	result := o.relay.call(ctx, call)
	if result.OK || result.ErrorCode != "source_settled" || !result.Retryable || len(result.Result) != 0 || call.TurnSource == nil || call.TurnSource.SourceTask != nil || call.TurnSource.InputKind == "task" || o.spec.NetworkID == "" || o.spec.Kind == "representative" || !strings.HasPrefix(call.Tool, "network_") {
		return result
	}
	o.bridgeSourceMu.Lock()
	if err := o.proveCompletedBridgeSource(ctx, call); err != nil {
		o.bridgeSourceMu.Unlock()
		return result
	}
	call.TurnSource = nil
	// Enqueue allocates a new correlation ID; polling freshly captures the
	// current authenticated admission. No native input, journal entry or
	// previous response is replayed by this retry.
	ticket, denied := o.relay.enqueue(call)
	o.bridgeSourceMu.Unlock()
	if ticket == nil {
		return denied
	}
	return o.relay.await(ctx, ticket)
}

func (o *SessionOwner) proveCompletedBridgeSource(ctx context.Context, call BridgeCall) error {
	expected := call.TurnSource
	if expected == nil || expected.SourceTask != nil || expected.InputKind == "task" || expected.Sequence <= 0 || expected.NativeGeneration != call.NativeGeneration || expected.NativeSessionID != call.NativeSessionID || expected.LogicalTurnID != logicalWorkerTurn(expected.Sequence) || call.Scope != o.journal.scope {
		return ErrConflict
	}
	o.mu.Lock()
	candidate := o.candidateTurnSource
	valid := !o.closing && o.generation == call.NativeGeneration && bytes.Equal(o.origin, call.Origin) && candidate.Sequence == expected.Sequence && candidate.SourceCommandID == expected.SourceCommandID && candidate.SourceAdmissionID == expected.SourceAdmissionID && candidate.InputKind == expected.InputKind && candidate.SourceTask == nil
	o.mu.Unlock()
	if !valid {
		return ErrFenced
	}
	sid, known := o.manager.TryNativeID(call.Scope.InstanceID)
	if !known || sid != call.NativeSessionID {
		return ErrConflict
	}
	nativeState, present := o.manager.State(call.Scope.InstanceID)
	if !present || nativeState != session.StateIdle || o.manager.HasPendingInteraction(call.Scope.InstanceID) || o.driver == nil || !o.driver.Live(call.Scope.InstanceID) {
		return ErrConflict
	}
	j := o.journal
	j.mu.Lock()
	defer j.mu.Unlock()
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	actual, err := readNativeTurn(ctx, tx, call.NativeGeneration, expected.LogicalTurnID)
	if err != nil {
		return err
	}
	if actual != *expected {
		return ErrConflict
	}
	var started, completed int
	var state string
	if err = tx.QueryRowContext(ctx, `SELECT t.started,t.completed,COALESCE(w.state,'retired') FROM worker_turn_sources t LEFT JOIN worker_intent w ON w.sequence=t.sequence WHERE t.native_generation=? AND t.logical_turn=?`, call.NativeGeneration, expected.LogicalTurnID).Scan(&started, &completed, &state); err != nil {
		return err
	}
	if started != 1 || completed != 1 || (state != "admitted" && state != "completed" && state != "retired") {
		return ErrConflict
	}
	var active int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM worker_intent WHERE sequence<>? AND state='admitted' AND kind IN ('prompt','activate','restart','stop','hibernate')`, expected.Sequence).Scan(&active); err != nil {
		return err
	}
	if active != 0 {
		return ErrConflict
	}
	return nil
}
