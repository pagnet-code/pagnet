package sessionworker

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/internal/crypto"
	"github.com/pagnet-code/pagnet/internal/session"
	"github.com/pagnet-code/pagnet/transport"
)

type Inspection struct {
	InteractionID       string                            `json:"interactionId"`
	NativeGeneration    string                            `json:"nativeGeneration"`
	NativeSessionID     string                            `json:"nativeSessionId"`
	NativeInteractionID string                            `json:"nativeInteractionId"`
	Kind                string                            `json:"kind"`
	Options             []domain.RuntimeInteractionOption `json:"options"`
	DetailEnvelope      e2ee.EncryptedPayloadV1           `json:"detailEnvelope"`
	DetailAAD           e2ee.AAD                          `json:"detailAAD"`
}
type nativeApproval struct {
	inspection *Inspection
	secret     []byte
	native     json.RawMessage
	summary    string
	consumed   bool
	expires    time.Time
}

func (o *SessionOwner) prepareInspection(event session.SessionEvent, generation string) {
	native := event.Interaction
	if native == nil || native.NativeInteractionID == "" || native.Kind != "permission" || len(native.NativePayload) > 64<<10 || len(native.Summary) > 4096 || !domain.ValidRuntimeInteractionOptions(native.Options) || o.spec.ProtectedContext == nil {
		return
	}
	if policy, ok := o.driver.(session.RemoteResolvable); ok && !policy.SupportsRemoteResolve(native.Kind) {
		return
	}
	if !o.driver.Capabilities().RemoteInteractionResolve {
		return
	}
	o.mu.Lock()
	if o.generation != generation || len(o.pending) >= 64 {
		o.mu.Unlock()
		return
	}
	if current := o.pending[native.NativeInteractionID]; current != nil && bytes.Equal(current.native, native.NativePayload) && current.summary == native.Summary && current.inspection != nil && current.inspection.NativeSessionID == event.SessionID && current.inspection.Kind == native.Kind && slices.Equal(current.inspection.Options, native.Options) {
		o.mu.Unlock()
		return
	}
	o.mu.Unlock()
	// Reading the actual existing content authority is mandatory. No missing
	// key or unsupported context ever creates an epoch just to enable approval.
	ring, err := crypto.LoadContextKeyring(o.spec.ContextStateDir, *o.spec.ProtectedContext)
	if err != nil {
		return
	}
	epoch, err := ring.ActiveEpoch()
	if err != nil {
		return
	}
	key, err := epoch.KeyArray()
	if err != nil {
		return
	}
	defer clear(key[:])
	secret := make([]byte, 32)
	if _, err = rand.Read(secret); err != nil {
		return
	}
	record := &nativeApproval{secret: secret, native: append(json.RawMessage(nil), native.NativePayload...), summary: native.Summary, expires: time.Now().UTC().Add(24 * time.Hour)}
	id := uuid.NewString()
	detail := transport.OwnerInteractionDetail{Format: "pagnet.owner_interaction.v1", Summary: native.Summary, NativePayload: json.RawMessage(native.NativePayload), Inspection: transport.OwnerInspection{Secret: base64.StdEncoding.EncodeToString(secret), InstanceID: o.journal.scope.InstanceID, SessionID: event.SessionID, NativeInteractionID: native.NativeInteractionID}}
	plain, err := json.Marshal(detail)
	if err != nil || len(plain) > 64<<10 {
		clear(secret)
		return
	}
	defer clear(plain)
	aad := e2ee.AAD{ProtocolVersion: transport.ProtocolVersion, TenantID: o.spec.TenantID, ObjectType: e2ee.ObjectTypeRuntimeInteraction, ObjectID: id, Sender: o.journal.scope.InstanceID, Recipient: o.spec.ProtectedContext.OwnerUserID, CreatedAt: time.Now().UTC().Format(time.RFC3339), KeyEpochID: epoch.ID, ProtectedContext: o.spec.ProtectedContext}
	envelope, err := e2ee.Encrypt(plain, key, aad)
	if err != nil {
		clear(secret)
		return
	}
	record.inspection = &Inspection{InteractionID: id, NativeGeneration: generation, NativeSessionID: event.SessionID, NativeInteractionID: native.NativeInteractionID, Kind: native.Kind, Options: append([]domain.RuntimeInteractionOption(nil), native.Options...), DetailEnvelope: envelope, DetailAAD: aad}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.generation != generation {
		clear(secret)
		return
	}
	o.pending[native.NativeInteractionID] = record
}

func (o *SessionOwner) resolveApproval(op Operation) error {
	o.mu.Lock()
	record := o.pending[op.InteractionID]
	if record == nil || record.inspection == nil || record.consumed || !time.Now().Before(record.expires) || op.NativeGeneration == "" || op.NativeGeneration != o.generation || op.NativeGeneration != record.inspection.NativeGeneration || op.NativeSessionID != record.inspection.NativeSessionID {
		o.mu.Unlock()
		return errors.New("native inspected choice is no longer pending")
	}
	var optionKind string
	for _, option := range record.inspection.Options {
		if option.ID == op.OptionID {
			optionKind = option.Kind
		}
	}
	if optionKind == "" {
		o.mu.Unlock()
		return errors.New("native choice was not observed")
	}
	// Check exact proof for every choice, including rejection. Private IPC does
	// not grant permission to invent a browser's inspected native consent.
	proof, err := base64.StdEncoding.DecodeString(op.InspectionProof)
	expected, proofErr := e2ee.ApprovalProof(record.secret, record.inspection.DetailAAD, o.journal.scope.InstanceID, op.NativeSessionID, op.InteractionID, op.OptionID)
	if err != nil || proofErr != nil || len(proof) != 32 || !hmac.Equal(proof, expected) {
		o.mu.Unlock()
		return errors.New("native inspected choice proof is invalid")
	}
	epochID := record.inspection.DetailAAD.KeyEpochID
	o.mu.Unlock()
	ctx, cancel := context.WithTimeout(o.ctx, 15*time.Second)
	defer cancel()
	return crypto.WithContextKeyring(ctx, o.spec.ContextStateDir, *o.spec.ProtectedContext, func(ring *crypto.ContextKeyring) error {
		if _, valid := ring.EpochByID(epochID); !valid {
			return errors.New("native inspection authority was revoked")
		}
		o.mu.Lock()
		if o.pending[op.InteractionID] != record || record.consumed || o.generation != op.NativeGeneration {
			o.mu.Unlock()
			return errors.New("native inspected choice is no longer pending")
		}
		// Mark consumed BEFORE native delivery. An uncertain write must never be
		// retried through another command ID or a replacement controller.
		record.consumed = true
		o.mu.Unlock()
		err := o.manager.ResolvePendingInteraction(ctx, o.journal.scope.InstanceID, op.NativeSessionID, op.InteractionID, op.OptionID)
		if err != nil {
			return errors.Join(session.ErrTurnInterrupted, err)
		}
		return nil
	})
}
