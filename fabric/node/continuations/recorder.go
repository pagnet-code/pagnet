// Package continuations composes private durable claims with the extension engine.
// It does not implement approval policy or turn serialized identity assertions
// into authentication. Its ports are installed by trusted node composition.
package continuations

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/extension"
	"github.com/pagnet-code/pagnet/fabric/extension/continuation"
)

type PrincipalResolver func(context.Context, string) (fabric.Principal, error)

// HistoricalAdmission is emitted ONLY after a private store authenticates a
// fresh claim against its previously verified original admission. It is not a
// wire proof and cannot establish current endpoint permission. The restorer must
// explicitly endorse the issuer, original identity and provenance; final current
// target authorization is rerun by Engine.ResumeStage.
type HistoricalAdmission struct {
	SnapshotDigest string
	Principal      fabric.Principal
	Audience       string
	OriginalBytes  []byte
	Provenance     fabric.Provenance
	Claim          continuation.Receipt
}
type OriginalAdmissionRestorer func(context.Context, HistoricalAdmission) (fabric.ExecutionContext, error)

// PrivateNotificationSink delivers a capability out of band to authenticated
// allowed recipients. It must not put it into public events, prompts or results.
// Notification loss is recovered via explicit pending rotation, never by Create
// reissuing a secret on an ambiguous persistence retry.
type PrivateNotification struct {
	ID         string
	Capability continuation.Capability
	Revision   uint64
	ExpiresAt  time.Time
	Recipients []fabric.Principal
}
type PrivateNotificationSink func(context.Context, PrivateNotification) error

type EvidenceKind string

const (
	TargetUnary    EvidenceKind = "target-unary"
	TargetTerminal EvidenceKind = "target-terminal"
	TargetFailure  EvidenceKind = "target-failure"
	NoTarget       EvidenceKind = "engine-no-target"
	Abandoned      EvidenceKind = "abandoned"
)

// Evidence is adapter-private, not caller-controlled result JSON. A verifier
// confirms actual endpoint receipts/effect evidence; arbitrary successful output
// alone never establishes completed effects. NoTarget is a local engine fact.
type Evidence struct {
	Kind         EvidenceKind
	InvocationID string
	Frame        *fabric.InvocationFrame
	Response     []byte
	Failure      error
}
type EvidenceValidator func(context.Context, fabric.ExecutionContext, Evidence) (continuation.Outcome, error)
type Config struct {
	Store             *continuation.Store
	Audience          string
	Manifests         []extension.ExtensionManifest
	MaxInterceptors   int
	ResolvePrincipal  PrincipalResolver
	RestoreOriginal   OriginalAdmissionRestorer
	Notify            PrivateNotificationSink
	VerifyEvidence    EvidenceValidator
	SettlementTimeout time.Duration
	SnapshotLimits    fabric.WireLimits
}
type Recorder struct {
	config       Config
	planRevision string
	pipeline     []byte
}
type persistedState struct {
	Format       string                         `json:"format"`
	State        extension.PipelineState        `json:"state"`
	Deferral     extension.Deferral             `json:"deferral"`
	Registration extension.CompiledRegistration `json:"registration"`
	Provenance   fabric.Provenance              `json:"provenance"`
}

func invalid(message string) error { return fabric.NewError(fabric.CodeInvalidInput, message) }
func stale() error {
	return fabric.NewError(fabric.CodeStaleContinuation, "Continuation configuration or authority is stale")
}
func New(config Config) (*Recorder, error) {
	if config.Store == nil || config.Audience == "" || config.ResolvePrincipal == nil || config.RestoreOriginal == nil || config.Notify == nil || config.VerifyEvidence == nil || config.SettlementTimeout <= 0 || config.SettlementTimeout > time.Minute {
		return nil, invalid("Incomplete trusted continuation composition")
	}
	if config.SnapshotLimits == (fabric.WireLimits{}) {
		config.SnapshotLimits = fabric.WireLimits{MaxBytes: 8 << 20, MaxDepth: 64, MaxMembers: 65536}
	}
	if config.SnapshotLimits.MaxBytes <= 0 || config.SnapshotLimits.MaxDepth <= 0 || config.SnapshotLimits.MaxMembers <= 0 {
		return nil, invalid("Invalid private snapshot limits")
	}
	plan, e := extension.Compile(config.Manifests, config.MaxInterceptors)
	if e != nil {
		return nil, e
	}
	manifests := append([]extension.ExtensionManifest(nil), config.Manifests...)
	sort.Slice(manifests, func(i, j int) bool { return manifests[i].ID < manifests[j].ID })
	raw, e := json.Marshal(manifests)
	if e != nil || hash(raw) != plan.Revision() {
		return nil, invalid("Invalid immutable pipeline evidence")
	}
	// Only immutable canonical bytes/revision survive constructor input mutation.
	config.Manifests = nil
	return &Recorder{config: config, planRevision: plan.Revision(), pipeline: raw}, nil
}
func hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func (r *Recorder) Save(ctx context.Context, caller fabric.ExecutionContext, original []byte, state extension.PipelineState, deferral extension.Deferral, registration extension.CompiledRegistration) (string, error) {
	if ctx == nil {
		return "", invalid("Missing continuation context")
	}
	if len(deferral.ResumePrincipals) < 1 || len(deferral.ResumePrincipals) > 64 {
		return "", invalid("Invalid bounded resume principals")
	}
	if state.PlanRevision != r.planRevision || state.DeferralID == "" || !deferral.Durable {
		return "", stale()
	}
	if _, e := caller.DecodeVerifiedEnvelope(original, r.config.Audience); e != nil {
		return "", e
	}
	allowed := make([]fabric.Principal, 0, len(deferral.ResumePrincipals))
	for _, ref := range deferral.ResumePrincipals {
		p, e := r.config.ResolvePrincipal(ctx, ref)
		if e != nil || p.Ref != ref {
			return "", fabric.NewError(fabric.CodeUnauthenticated, "Resume identity resolution failed")
		}
		allowed = append(allowed, p)
	}
	body := persistedState{Format: "pagnet.node-continuation.v1", State: state, Deferral: deferral, Registration: registration, Provenance: caller.ProvenanceView()}
	raw, e := json.Marshal(body)
	var verified persistedState
	if e != nil || fabric.DecodeJSONWithLimits(raw, &verified, r.config.SnapshotLimits) != nil {
		return "", invalid("Invalid pipeline state")
	}
	snapshot := continuation.Snapshot{Format: 1, DeferralID: state.DeferralID, OriginalEnvelope: append([]byte(nil), original...), OriginalPrincipal: caller.PrincipalView(), AllowedResumePrincipals: allowed, PlanRevision: fabric.Revision(r.planRevision), PlanVersion: "pagnet.extension-plan.v1", PlanDigest: hash(r.pipeline), Pipeline: append([]byte(nil), r.pipeline...), State: raw}
	issued, e := r.config.Store.Create(ctx, caller, snapshot, deferral.ExpiresAt)
	if e != nil {
		return "", e
	}
	if issued.Created {
		e = r.config.Notify(ctx, PrivateNotification{ID: issued.ID, Capability: issued.Capability, Revision: issued.CapabilityRevision, ExpiresAt: deferral.ExpiresAt, Recipients: append([]fabric.Principal(nil), allowed...)})
		if e != nil {
			return issued.ID, fabric.NewError(fabric.CodeTargetUnavailable, "Private continuation delivery failed; pending capability can be rotated")
		}
	}
	return issued.ID, nil
}

// RotatePending delegates exact identity+capability revision CAS to the private
// store. The newly minted secret is returned only to this private delivery sink.
type RotationResult struct {
	ID        string `json:"id"`
	Revision  uint64 `json:"revision"`
	Delivered bool   `json:"delivered"`
}

func (r *Recorder) RotatePending(ctx context.Context, resumer fabric.ExecutionContext, id string, revision uint64) (RotationResult, error) {
	if ctx == nil {
		return RotationResult{}, invalid("Missing rotation context")
	}
	issued, e := r.config.Store.RotatePendingCapability(ctx, resumer, id, revision)
	if e != nil {
		return RotationResult{}, e
	}
	result := RotationResult{ID: id, Revision: issued.CapabilityRevision}
	if e = r.config.Notify(ctx, PrivateNotification{ID: id, Capability: issued.Capability, Revision: issued.CapabilityRevision, Recipients: []fabric.Principal{resumer.PrincipalView()}}); e != nil {
		return result, fabric.NewError(fabric.CodeTargetUnavailable, "Private pending capability delivery failed")
	}
	result.Delivered = true
	return result, nil
}

var _ extension.ContinuationRecorder = (*Recorder)(nil)
