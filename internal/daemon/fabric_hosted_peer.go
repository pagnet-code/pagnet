package daemon

import (
	"context"

	"github.com/pagnet-code/pagnet/internal/localpeer"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
)

// HostedPeer verifies a kernel-captured Fabric socket against the ORIGINAL
// cloud worker's private activation. It never changes its native scope, launch
// profile, controller lease, session, or invocation provenance.
func (p *NativeWorkerProxy) HostedPeer(ctx context.Context, request sessionworker.HostedPeerVerificationRequest) (*sessionworker.HostedPeerVerificationResult, error) {
	response, err := p.call(ctx, sessionworker.Request{Type: "hosted_peer_verify", HostedPeer: &request})
	if err != nil {
		return nil, err
	}
	proof := response.HostedPeer
	if proof == nil || proof.Scope != p.scope || proof.Peer != request.Peer || proof.NativeGeneration != request.NativeGeneration || proof.RootPID <= 0 || proof.RootStart == "" || proof.NativeSessionID == "" || request.NativeSessionID != "" && proof.NativeSessionID != request.NativeSessionID {
		return nil, ErrNativeObservationConflict
	}
	return proof, nil
}

// HostedOwnerProcess is the original authenticated worker process incarnation,
// suitable for the mandatory owner-mode guard before vendor children launch.
// Closing a proxy does not kill this process; guards must retain a live kernel
// incarnation until the worker really exits, rather than freeing on disconnect.
func (p *NativeWorkerProxy) HostedOwnerProcess() (localpeer.ProcessSnapshot, error) {
	if p == nil || p.controller == nil {
		return localpeer.ProcessSnapshot{}, ErrNativeOriginAdmissionDeferred
	}
	return p.controller.OwnerProcess()
}
