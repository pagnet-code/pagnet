package daemon

import (
	"context"
	"encoding/json"

	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

// NativeWorkerAdmission returns only public authenticated connection metadata.
// The worker receives no host credential and cannot select another account.
func (c *NativeObservationConnection) NativeWorkerAdmission(scope sessionworker.Scope, networkID, kind string) (sessionworker.Admission, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return sessionworker.Admission{}, ErrNativeOriginAdmissionDeferred
	default:
	}
	if c.session == nil {
		return sessionworker.Admission{}, ErrNativeOriginAdmissionDeferred
	}
	if scope.HostID != c.hostID || scope.ServerURL == "" || scope.TenantID == "" || scope.AccountID == "" || scope.InstanceID == "" || scope.Generation == "" {
		return sessionworker.Admission{}, ErrNativeObservationConflict
	}
	if (kind == "worker" && networkID == "") || (kind != "worker" && kind != "representative") {
		return sessionworker.Admission{}, ErrNativeObservationConflict
	}
	return sessionworker.Admission{NativeAdmissionID: c.session.NativeAdmissionID, Scope: scope, TenantID: scope.TenantID, NetworkID: networkID, Kind: kind, RunnerID: c.session.RunnerID, RunnerEpoch: c.session.RunnerEpoch, BootID: c.session.BootID}, nil
}

// AuthorizeNativeWorkerActivation bridges the worker's prelaunch gate to the
// server's durable original admission. The caller pins expectedScope from its
// authenticated local worker, rather than trusting a polled request to choose
// an account or state directory. Transient errors keep that same gate pending.
func (c *NativeObservationConnection) AuthorizeNativeWorkerActivation(ctx context.Context, expectedScope sessionworker.Scope, request sessionworker.ActivationRequest) (sessionworker.ActivationOrigin, error) {
	if request.Scope != expectedScope || request.Admission.Scope != expectedScope || request.CurrentAdmission.Scope != expectedScope || request.Admission.TenantID != expectedScope.TenantID || request.CurrentAdmission.TenantID != expectedScope.TenantID || request.ID == "" || request.SourceCommandID == "" || request.NativeGeneration == "" {
		return sessionworker.ActivationOrigin{}, ErrNativeObservationConflict
	}
	current, err := c.NativeWorkerAdmission(expectedScope, request.NetworkID, request.CurrentAdmission.Kind)
	if err != nil {
		return sessionworker.ActivationOrigin{}, err
	}
	if current != request.CurrentAdmission || request.Admission.Kind != current.Kind || request.Admission.NetworkID != current.NetworkID {
		return sessionworker.ActivationOrigin{}, ErrNativeObservationConflict
	}
	sourceTenant := expectedScope.TenantID
	if current.Kind == "worker" {
		if request.NetworkTenantID == "" {
			return sessionworker.ActivationOrigin{}, ErrNativeObservationConflict
		}
		sourceTenant = request.NetworkTenantID
	} else if request.NetworkID != "" || request.NetworkTenantID != "" {
		return sessionworker.ActivationOrigin{}, ErrNativeObservationConflict
	}
	source := transport.HostSessionPayload{NativeAdmissionID: request.Admission.NativeAdmissionID, HostID: expectedScope.HostID, RunnerID: request.Admission.RunnerID, RunnerEpoch: request.Admission.RunnerEpoch, BootID: request.Admission.BootID}
	origin, err := c.RegisterOriginForSource(ctx, source, request.SourceCommandID, expectedScope.InstanceID, string(request.ActualRuntime), request.NativeGeneration)
	if err != nil {
		return sessionworker.ActivationOrigin{}, err
	}
	if origin.TenantID != sourceTenant {
		return sessionworker.ActivationOrigin{}, ErrNativeObservationConflict
	}
	// Fresh metadata must still match B when the reply leaves this adapter.
	currentAfter, err := c.NativeWorkerAdmission(expectedScope, request.NetworkID, current.Kind)
	if err != nil {
		return sessionworker.ActivationOrigin{}, err
	}
	if currentAfter != current {
		return sessionworker.ActivationOrigin{}, ErrNativeObservationConflict
	}
	raw, err := json.Marshal(origin)
	if err != nil {
		return sessionworker.ActivationOrigin{}, err
	}
	return sessionworker.ActivationOrigin{ID: request.ID, NativeGeneration: request.NativeGeneration, Origin: raw}, nil
}
