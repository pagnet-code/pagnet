package sessionworker

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"slices"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/internal/crypto"
	"github.com/pagnet-code/pagnet/internal/session"
	"github.com/pagnet-code/pagnet/nativecontent"
	"github.com/pagnet-code/pagnet/transport"
)

type Inspection struct {
	DetailContent       *transport.NativeContentReference `json:"detailContent,omitempty"`
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
	committed     bool
	payloadDigest [32]byte
	summaryDigest [32]byte
	transfer      *nativecontent.Transfer
	inspection    *Inspection
	secret        []byte
	native        json.RawMessage
	summary       string
	consumed      bool
	expires       time.Time
}

func (o *SessionOwner) prepareInspection(event session.SessionEvent, generation string, original ...NativeObservation) {
	native := event.Interaction
	if native == nil || native.NativeInteractionID == "" || native.Kind != "permission" || len(native.NativePayload) > 16<<20 || !domain.ValidRuntimeInteractionOptions(native.Options) {
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
	if current := o.pending[native.NativeInteractionID]; current != nil && current.payloadDigest == sha256.Sum256(native.NativePayload) && current.summaryDigest == sha256.Sum256([]byte(native.Summary)) && current.inspection != nil && current.inspection.NativeSessionID == event.SessionID && current.inspection.Kind == native.Kind && slices.Equal(current.inspection.Options, native.Options) {
		o.mu.Unlock()
		return
	}
	o.mu.Unlock()
	// Reading the actual existing content authority is mandatory. No missing
	// key or unsupported context ever creates an epoch just to enable approval.
	var epoch crypto.KeyEpoch
	var err error
	if o.spec.ProtectedContext != nil {
		ring, loadErr := crypto.LoadContextKeyring(o.spec.ContextStateDir, *o.spec.ProtectedContext)
		if loadErr != nil {
			return
		}
		epoch, err = ring.ActiveEpoch()
	} else {
		if o.spec.NetworkID == "" || o.spec.NetworkTenantID == "" || !filepath.IsAbs(o.spec.NetworkStateDir) {
			return
		}
		ring, loadErr := crypto.LoadKeyring(o.spec.NetworkStateDir, o.spec.NetworkID)
		if loadErr != nil {
			return
		}
		epoch, err = ring.ActiveEpoch()
	}
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
	record := &nativeApproval{payloadDigest: sha256.Sum256(native.NativePayload), summaryDigest: sha256.Sum256([]byte(native.Summary)), secret: secret, native: append(json.RawMessage(nil), native.NativePayload...), summary: native.Summary, expires: time.Now().UTC().Add(24 * time.Hour)}
	o.mu.Lock()
	origin := append(json.RawMessage(nil), o.origin...)
	o.mu.Unlock()
	id := nativeInteractionIdentity(o.journal.scope, origin, generation, event.SessionID, native.NativeInteractionID)
	detail := transport.OwnerInteractionDetail{Format: "pagnet.owner_interaction.v1", Summary: native.Summary, NativePayload: json.RawMessage(native.NativePayload), Inspection: transport.OwnerInspection{Secret: base64.StdEncoding.EncodeToString(secret), InstanceID: o.journal.scope.InstanceID, SessionID: event.SessionID, NativeInteractionID: native.NativeInteractionID}}
	plain, err := canonicalNativeJSON(detail)
	if err != nil || len(plain) > transport.NativeContentMaxPlaintextBytes {
		clear(secret)
		return
	}
	defer clear(plain)
	aad := e2ee.AAD{ProtocolVersion: transport.ProtocolVersion, TenantID: o.spec.TenantID, ObjectType: e2ee.ObjectTypeRuntimeInteraction, ObjectID: id, Sender: o.journal.scope.InstanceID, CreatedAt: time.Now().UTC().Format(time.RFC3339), KeyEpochID: epoch.ID, ProtectedContext: o.spec.ProtectedContext}
	if o.spec.ProtectedContext != nil {
		aad.Recipient = o.spec.ProtectedContext.OwnerUserID
	} else {
		aad.TenantID = o.spec.NetworkTenantID
		aad.NetworkID = o.spec.NetworkID
	}

	if len(plain) > 64<<10 {
		if len(original) != 1 {
			clear(secret)
			return
		}
		transfer, buildErr := buildOriginalContent(original[0], id, "interaction_detail", "application/json", plain, key, aad)
		if buildErr != nil {
			clear(secret)
			return
		}
		record.transfer = &transfer
		record.inspection = &Inspection{InteractionID: id, NativeGeneration: generation, NativeSessionID: event.SessionID, NativeInteractionID: native.NativeInteractionID, Kind: native.Kind, Options: append([]domain.RuntimeInteractionOption(nil), native.Options...), DetailContent: &transfer.Reference, DetailAAD: transfer.Reference.ManifestAAD}
		o.mu.Lock()
		defer o.mu.Unlock()
		if o.generation != generation {
			clear(secret)
			return
		}
		o.pending[native.NativeInteractionID] = record
		return
	}
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
	return o.resolveApprovalWithSource(op, nil)
}
func (o *SessionOwner) resolveAuthenticatedApproval(op Operation, source *Admission) error {
	if op.SourceCommandID == "" && op.SourceAdmissionID == "" {
		return o.resolveApprovalWithSource(op, nil)
	}
	if source != nil && ValidateNativeResolveOperation(op) != nil {
		return errors.New("invalid authenticated native resolution")
	}
	return o.resolveApprovalWithSource(op, source)
}
func (o *SessionOwner) resolveApprovalWithSource(op Operation, source *Admission) error {
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
	// Permission grants require inspected content. An authenticated exact
	// observed rejection can safely decline even if content authority is lost.
	safeReject := (optionKind == "reject_once" || optionKind == "reject_always") && o.authenticatedResolutionSource(op, source)
	if !safeReject {
		proof, err := base64.StdEncoding.DecodeString(op.InspectionProof)
		expected, proofErr := e2ee.ApprovalProof(record.secret, record.inspection.DetailAAD, o.journal.scope.InstanceID, op.NativeSessionID, op.InteractionID, op.OptionID)
		if err != nil || proofErr != nil || len(proof) != 32 || !hmac.Equal(proof, expected) {
			o.mu.Unlock()
			return errors.New("native inspected choice proof is invalid")
		}
	}
	o.mu.Unlock()
	ctx, cancel := context.WithTimeout(o.ctx, 15*time.Second)
	defer cancel()
	deliver := func() error {
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
	}
	if safeReject {
		return deliver()
	}
	return o.withInspectionEpoch(ctx, record.inspection.DetailAAD, func(crypto.KeyEpoch) error { return deliver() })
}

// Resolution answers are distinct from the inspected permission payload. Read
// the actual accepted inspection epoch; do not create/rotate content authority.
// Large or currently unavailable answers remain complete in the private source
// capture for the purpose-specific content manifest path.
func (o *SessionOwner) encryptResolution(event session.SessionEvent, inspection *Inspection, observedAt time.Time) *NativeResolution {
	if inspection == nil || event.Interaction == nil || !event.Interaction.Resolved || len(event.Interaction.Answer) > 64<<10 {
		return nil
	}
	var resolution *NativeResolution
	_ = o.withInspectionEpoch(o.ctx, inspection.DetailAAD, func(epoch crypto.KeyEpoch) error {
		key, err := epoch.KeyArray()
		if err != nil {
			return err
		}
		defer clear(key[:])
		aad := inspection.DetailAAD
		aad.NativeContent = nil
		aad.CreatedAt = observedAt.UTC().Format(time.RFC3339)
		envelope, err := e2ee.Encrypt([]byte(event.Interaction.Answer), key, aad)
		if err != nil {
			return err
		}
		resolution = &NativeResolution{DetailEnvelope: envelope, DetailAAD: aad}
		return nil
	})
	return resolution
}

func (o *SessionOwner) encryptOriginalResolution(event session.SessionEvent, inspection *Inspection, observation NativeObservation) (*NativeResolution, *nativecontent.Transfer) {
	if event.Interaction == nil || len(event.Interaction.Answer) <= 64<<10 {
		return o.encryptResolution(event, inspection, observation.ObservedAt), nil
	}
	if inspection == nil || !event.Interaction.Resolved {
		return nil, nil
	}
	var result *NativeResolution
	var transfer *nativecontent.Transfer
	_ = o.withInspectionEpoch(o.ctx, inspection.DetailAAD, func(epoch crypto.KeyEpoch) error {
		key, err := epoch.KeyArray()
		if err != nil {
			return err
		}
		defer clear(key[:])
		built, err := buildOriginalContent(observation, inspection.InteractionID, "interaction_answer", "text/plain; charset=utf-8", []byte(event.Interaction.Answer), key, inspection.DetailAAD)
		if err != nil {
			return err
		}
		transfer = &built
		result = &NativeResolution{DetailContent: &built.Reference, DetailAAD: built.Reference.ManifestAAD}
		return nil
	})
	return result, transfer
}

// Preserve the original inspection scope and epoch through proof delivery and
// answer encryption; a fresh epoch never grants an old native capability.
func (o *SessionOwner) withInspectionEpoch(ctx context.Context, aad e2ee.AAD, fn func(crypto.KeyEpoch) error) error {
	if aad.ValidateScope() != nil || aad.KeyEpochID == "" {
		return errors.New("original inspection scope unavailable")
	}
	check := func(epoch crypto.KeyEpoch, found bool) error {
		if !found || epoch.State == crypto.EpochRevoked {
			return errors.New("native inspection authority was revoked")
		}
		return fn(epoch)
	}
	if aad.ProtectedContext != nil {
		if !reflect.DeepEqual(aad.ProtectedContext, o.spec.ProtectedContext) || !filepath.IsAbs(o.spec.ContextStateDir) {
			return errors.New("original inspection context differs")
		}
		return crypto.WithContextKeyring(ctx, o.spec.ContextStateDir, *aad.ProtectedContext, func(ring *crypto.ContextKeyring) error {
			epoch, found := ring.EpochByID(aad.KeyEpochID)
			return check(epoch, found)
		})
	}
	if o.spec.ProtectedContext != nil || aad.NetworkID == "" || aad.NetworkID != o.spec.NetworkID || aad.TenantID != o.spec.NetworkTenantID || !filepath.IsAbs(o.spec.NetworkStateDir) {
		return errors.New("original inspection network differs")
	}
	return crypto.WithNetworkKeyring(ctx, o.spec.NetworkStateDir, aad.NetworkID, func(ring *crypto.Keyring) error {
		epoch, found := ring.EpochByID(aad.KeyEpochID)
		return check(epoch, found)
	})
}
