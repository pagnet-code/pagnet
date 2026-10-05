package daemon

import (
	"context"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
)

// HostedInvocationSource consults the original worker's indexed FULL journal,
// never the server's last session ID or a present-day runtime snapshot. The
// caller must additionally verify its current local Fabric dispatch association.
func (p *NativeWorkerProxy) HostedInvocationSource(ctx context.Context, request sessionworker.CloudInvocationSourceRequest) (*sessionworker.CloudInvocationSourceResult, error) {
	response, err := p.call(ctx, sessionworker.Request{Type: "invocation_source", InvocationSource: &request})
	if err != nil {
		return nil, err
	}
	if response.InvocationSource == nil {
		return nil, ErrNativeObservationConflict
	}
	return response.InvocationSource, nil
}

// WaitHostedInvocationSource has no polling timer or effect RPC. Abandoning a
// reader closes only its auxiliary socket; the original paid turn and primary
// controller remain alive. Server current admission is checked on both sides.
func (p *NativeWorkerProxy) WaitHostedInvocationSource(ctx context.Context, directory string, last sessionworker.ReadinessToken) (sessionworker.ReadinessToken, error) {
	if p == nil {
		return sessionworker.ReadinessToken{}, ErrNativeOriginAdmissionDeferred
	}
	if _, err := p.connection.NativeWorkerAdmission(p.scope, p.bootstrap.Native.NetworkID, p.bootstrap.Native.Kind); err != nil {
		return sessionworker.ReadinessToken{}, err
	}
	bootstrap, key, err := sessionworker.LoadControllerBootstrap(directory, p.scope)
	if err != nil {
		return sessionworker.ReadinessToken{}, err
	}
	defer clear(key)
	if sessionworker.NativeProfileFingerprint(bootstrap.Native) != p.profile {
		return sessionworker.ReadinessToken{}, ErrNativeObservationConflict
	}
	token, err := p.controller.WaitCloudReady(ctx, directory, p.scope, key, last)
	if err != nil {
		return sessionworker.ReadinessToken{}, err
	}
	if _, err = p.connection.NativeWorkerAdmission(p.scope, p.bootstrap.Native.NetworkID, p.bootstrap.Native.Kind); err != nil {
		return sessionworker.ReadinessToken{}, err
	}
	return token, nil
}
