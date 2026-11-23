//go:build linux || darwin

package daemon

import (
	"errors"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

// ValidateNativeShareBinding captures a closed-binding subject without creating
// keys, touching the filesystem, installing epochs, or authorizing execution.
// The caller must supply the endpoint and HostSession captured together from an
// authenticated NativeObservationConnection, and a record obtained from the
// authoritative NativeWorkerRegistry. request.Binding.PrincipalID is the authenticated
// server's selection; it is recorded only in the new binding, never inferred
// from or written into the worker registry. Owner authorization stays server-side.
func ValidateNativeShareBinding(request transport.NativeShareBindingPreparePayload, capturedServerURL string, session transport.HostSessionPayload, record NativeWorkerRecord) (transport.NativeShareBindingSubject, error) {
	invalid := errors.New("native share binding does not match local authority")
	if _, err := request.CanonicalBytes(); err != nil {
		return transport.NativeShareBindingSubject{}, err
	}
	scope := record.Scope
	if capturedServerURL != scope.ServerURL || scope.TenantID != session.TenantID || scope.AccountID != session.AccountID || scope.HostID != session.HostID || scope.InstanceID != string(request.Binding.InstanceID) || scope.Generation != request.Binding.NativeGeneration || record.Spec.TenantID != scope.TenantID || record.ProfileFingerprint != sessionworker.NativeProfileFingerprint(record.Spec) || session.RunnerEpoch.IsZero() {
		return transport.NativeShareBindingSubject{}, invalid
	}
	if session.OwnershipScope != "personal" && session.OwnershipScope != "organization" {
		return transport.NativeShareBindingSubject{}, invalid
	}
	if session.OwnershipScope == "organization" && session.AccountID != session.TenantID {
		return transport.NativeShareBindingSubject{}, invalid
	}
	if record.LaunchState != "reserved" && record.LaunchState != "launching" && record.LaunchState != "launched" {
		return transport.NativeShareBindingSubject{}, invalid
	}
	subject := transport.NativeShareBindingSubject{
		ServerURL: capturedServerURL, TenantID: domain.ID(scope.TenantID), AccountID: domain.ID(scope.AccountID), HostID: domain.ID(scope.HostID),
		NativeAdmissionID: domain.ID(session.NativeAdmissionID), RunnerID: domain.ID(session.RunnerID), RunnerEpoch: session.RunnerEpoch.UTC().Format(time.RFC3339Nano),
		BootID: session.BootID, ProfileFingerprint: record.ProfileFingerprint,
	}
	if _, err := subject.CanonicalBytes(); err != nil {
		return transport.NativeShareBindingSubject{}, err
	}
	return subject, nil
}
