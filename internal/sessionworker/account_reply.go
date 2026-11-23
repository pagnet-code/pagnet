package sessionworker

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/e2ee"
	hostcrypto "github.com/pagnet-code/pagnet/internal/crypto"
	"github.com/pagnet-code/pagnet/internal/session"
	"github.com/pagnet-code/pagnet/nativecontent"
	"github.com/pagnet-code/pagnet/transport"
)

func loadOriginalAccountKey(spec NativeSpec, aad e2ee.AAD) ([32]byte, bool) {
	if aad.ValidateScope() != nil || aad.BrowserAccountMessage == nil || aad.ObjectType != e2ee.ObjectTypeMessage || aad.ProtectedContext != nil || aad.TenantID != spec.NetworkTenantID || aad.NetworkID != spec.NetworkID || !filepath.IsAbs(spec.NetworkStateDir) {
		return [32]byte{}, false
	}
	ring, err := hostcrypto.LoadKeyring(spec.NetworkStateDir, aad.NetworkID)
	if err != nil {
		return [32]byte{}, false
	}
	epoch, found := ring.EpochByID(aad.KeyEpochID)
	if !found || (epoch.State != hostcrypto.EpochActive && epoch.State != hostcrypto.EpochRotated) {
		return [32]byte{}, false
	}
	key, err := epoch.KeyArray()
	return key, err == nil
}

// Load authority only from the immutable original admission, never the current
// controller or the native origin's birth admission.
func accountReplyProof(ctx context.Context, tx *sql.Tx, source NativeTurnSource) (transport.NativeDispatchProof, error) {
	var p transport.NativeDispatchProof
	if source.SourceAccountMessage == nil || source.LogicalTurnID != logicalWorkerTurn(source.Sequence) {
		return p, ErrConflict
	}
	var command string
	var stored, raw []byte
	if err := tx.QueryRowContext(ctx, `SELECT command_id,source,proof FROM worker_account_inputs WHERE sequence=?`, source.Sequence).Scan(&command, &stored, &raw); err != nil {
		return p, err
	}
	if json.Unmarshal(raw, &p) != nil || command != source.SourceCommandID || p.SourceCommandID != command || p.SourceAdmissionID != source.SourceAdmissionID || p.AccountMessageSource == nil || !transport.ValidNativeSourceUnion(source.SourceTask, source.SourceInvocation, source.SourceAccountMessage) || !transport.ValidNativeSourceUnion(p.TaskSource, p.InvocationSource, p.AccountMessageSource) || !bytes.Equal(stored, source.SourceAccountMessage.CanonicalJSON()) || !bytes.Equal(stored, p.AccountMessageSource.CanonicalJSON()) {
		return p, ErrConflict
	}
	return p, nil
}

func (o *SessionOwner) captureOriginalAccountReply(event session.SessionEvent, observation *NativeObservation) *nativecontent.Transfer {
	source := observation.TurnSource
	if event.Type != session.EventTurnCompleted {
		return nil
	}
	// A successful completion without the native versioned answer has no reply.
	observation.SourceContentUnavailable = true
	if !o.accountExecutionEnabled() || observation.SourceUnavailable || source == nil || source.SourceAccountMessage == nil || event.FinalOutput == nil || event.FinalOutput.Version != 1 || len(event.FinalOutput.TextBlocks) == 0 || event.SessionID != source.NativeSessionID || event.TurnID != source.LogicalTurnID || observation.NativeGeneration != source.NativeGeneration || observation.NativeSessionID != source.NativeSessionID || observation.ObservedAt.IsZero() {
		return nil
	}
	for _, block := range event.FinalOutput.TextBlocks {
		if !utf8.ValidString(block) {
			return nil
		}
	}
	key, available := o.originalTaskContentPin(source)
	if !available {
		return nil
	}
	defer clear(key[:])
	// Revocation or loss of the original epoch fails closed even after pinning.
	current, available := loadOriginalAccountKey(o.spec, source.SourceAccountMessage.InputAAD)
	defer clear(current[:])
	if !available || current != key {
		return nil
	}
	captureCtx, cancel := context.WithTimeout(context.WithoutCancel(o.ctx), 3*time.Second)
	defer cancel()
	o.journal.mu.Lock()
	tx, err := o.journal.db.BeginTx(captureCtx, nil)
	var proof transport.NativeDispatchProof
	if err == nil {
		proof, err = accountReplyProof(captureCtx, tx, *source)
		tx.Rollback()
	}
	o.journal.mu.Unlock()
	if err != nil {
		return nil
	}
	var origin struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(observation.Origin, &origin) != nil || origin.ID == "" {
		return nil
	}
	s := source.SourceAccountMessage
	d := s.Descriptor
	replyID := uuid.NewString()
	aad := e2ee.AAD{ProtocolVersion: 2, TenantID: d.TenantID, NetworkID: d.NetworkID, ObjectType: e2ee.ObjectTypeBrowserAccountReply, ObjectID: replyID, Sender: d.TargetInstanceID, Recipient: d.Sender.ID, CreatedAt: observation.ObservedAt.UTC().Format(time.RFC3339Nano), KeyEpochID: d.EpochID, BrowserAccountReply: &e2ee.BrowserAccountReplyBinding{Format: e2ee.BrowserAccountReplyBindingFormat, ReplyID: replyID, MessageID: s.MessageID, BindingDigest: s.BindingDigest, SealedDigest: s.SealedDigest, OwnerUserID: d.OwnerUserID, ConnectionID: d.ConnectionID, Delegate: e2ee.BrowserAccountDelegate{Kind: d.Sender.Kind, ID: d.Sender.ID}, SourceCommandID: proof.SourceCommandID, SourceAdmissionID: proof.SourceAdmissionID, OwnershipID: proof.OwnershipID, OwnershipGeneration: proof.OwnershipGeneration, DispatchSequence: proof.DispatchSequence, LogicalTurnID: source.LogicalTurnID, OriginalEpochID: d.EpochID}}
	binding := e2ee.NativeContentBinding{ContentID: uuid.NewString(), ObservationID: observation.ID, OriginID: origin.ID, InstanceID: d.TargetInstanceID, NativeGeneration: source.NativeGeneration, NativeSessionID: source.NativeSessionID, SubjectType: e2ee.ObjectTypeBrowserAccountReply, SubjectID: s.MessageID, Purpose: e2ee.ObjectTypeBrowserAccountReply, SourceCommandID: source.SourceCommandID, SourceAdmissionID: source.SourceAdmissionID, LogicalTurnID: source.LogicalTurnID}
	plain, err := canonicalNativeJSON(event.FinalOutput)
	if err != nil {
		return nil
	}
	defer clear(plain)
	transfer, err := nativecontent.Build(plain, key, aad, binding, "application/json")
	if err != nil || d.TargetInstanceID != o.journal.scope.InstanceID || s.ValidateReplyAAD(transfer.Reference.ManifestAAD, proof) != nil {
		return nil
	}
	observation.SourceContentUnavailable = false
	observation.OutputContent = &transfer.Reference
	return &transfer
}

func validateAccountReply(observation NativeObservation, ref transport.NativeContentReference, proof transport.NativeDispatchProof) error {
	source := observation.TurnSource
	b := ref.ManifestAAD.NativeContent
	var origin struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(observation.Origin, &origin) != nil || origin.ID == "" || ref.ObservationID != observation.ID || ref.OriginID != origin.ID || ref.NativeGeneration != observation.NativeGeneration || ref.NativeSessionID != observation.NativeSessionID || observation.SourceUnavailable || observation.SourceContentUnavailable {
		return errors.New("encrypted account reply differs from original observation")
	}
	if source == nil || source.SourceAccountMessage == nil || observation.Event.Type != session.EventTurnCompleted || observation.Event.SessionID != observation.NativeSessionID || observation.Event.TurnID != source.LogicalTurnID || source.NativeGeneration != observation.NativeGeneration || source.NativeSessionID != observation.NativeSessionID || source.LogicalTurnID != logicalWorkerTurn(source.Sequence) || b == nil || b.LogicalTurnID != source.LogicalTurnID || ref.InstanceID != source.SourceAccountMessage.Descriptor.TargetInstanceID || ref.ManifestAAD.CreatedAt != observation.ObservedAt.UTC().Format(time.RFC3339Nano) || source.SourceAccountMessage.ValidateReplyAAD(ref.ManifestAAD, proof) != nil {
		return errors.New("encrypted account reply differs from original source")
	}
	return nil
}
