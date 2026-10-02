package sessionworker

import (
	"encoding/base64"
	"errors"

	"github.com/pagnet-code/pagnet/domain"
)

// ValidateNativeResolveOperation is shared with typed dispatch admission. Only
// immutable public choice identity and an optional inspected proof are allowed.
func ValidateNativeResolveOperation(op Operation) error {
	if op.Input != "" || op.InputKind != "" || op.SourceTask != nil || len(op.Data) != 0 || op.Rows != 0 || op.Cols != 0 || op.NativeGeneration == "" || len(op.NativeGeneration) > 256 || op.NativeSessionID == "" || len(op.NativeSessionID) > 1024 || op.InteractionID == "" || len(op.InteractionID) > 1024 || op.OptionID == "" || len(op.OptionID) > 128 {
		return ErrConflict
	}
	if _, err := domain.ParseID(op.SourceCommandID); err != nil {
		return ErrConflict
	}
	if _, err := domain.ParseID(op.SourceAdmissionID); err != nil {
		return ErrConflict
	}
	if op.InspectionProof != "" {
		proof, err := base64.StdEncoding.DecodeString(op.InspectionProof)
		if err != nil || len(proof) != 32 {
			return errors.New("native inspection proof is invalid")
		}
	}
	return nil
}

// The original accepted operation admission comes from the durable journal,
// not caller-supplied labels. New delivery transport never replaces this scope.
func (o *SessionOwner) authenticatedResolutionSource(op Operation, source *Admission) bool {
	return source != nil && ValidateNativeResolveOperation(op) == nil && source.Scope == o.journal.scope && source.TenantID == o.journal.scope.TenantID && source.NetworkID == o.spec.NetworkID && source.Kind == o.spec.Kind && source.NativeAdmissionID == op.SourceAdmissionID && source.RunnerID != "" && source.BootID != "" && !source.RunnerEpoch.IsZero()
}
