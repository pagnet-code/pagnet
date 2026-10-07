package sessionworker

import (
	"context"
	"crypto/subtle"
	"strconv"

	"github.com/pagnet-code/pagnet/internal/localpeer"
)

// These types are private authenticated controller IPC, never cloud messages,
// descriptors, network envelopes or telemetry. Peer is captured by the node's
// actual kernel socket, not accepted as an agent-supplied network identity.
type HostedPeerVerificationRequest struct {
	Peer             localpeer.ProcessSnapshot `json:"peer"`
	Nonce            string                    `json:"nonce"`
	NativeGeneration string                    `json:"nativeGeneration"`
	NativeSessionID  string                    `json:"nativeSessionId,omitempty"`
}
type HostedPeerVerificationResult struct {
	Peer             localpeer.ProcessSnapshot `json:"peer"`
	Scope            Scope                     `json:"scope"`
	NativeGeneration string                    `json:"nativeGeneration"`
	NativeSessionID  string                    `json:"nativeSessionId"`
	RootPID          int                       `json:"rootPid"`
	RootStart        string                    `json:"rootStart"`
}

func (o *SessionOwner) verifyHostedPeer(ctx context.Context, lease int64, r HostedPeerVerificationRequest) (*HostedPeerVerificationResult, error) {
	if o == nil || ctx == nil || o.journal.isLocal() || r.Peer.PID <= 0 || r.Peer.Start <= 0 || r.Nonce == "" || len(r.Nonce) > 512 || r.NativeGeneration == "" || len(r.NativeGeneration) > 256 || len(r.NativeSessionID) > 4096 {
		return nil, ErrFenced
	}
	if _, e := o.relay.authorizeNativeEffect(lease); e != nil {
		return nil, e
	}
	o.mu.Lock()
	nonce, generation := o.nonce, o.generation
	o.mu.Unlock()
	// The generation is the STABLE sideport identity: the signed scope
	// generation the association pinned (immutable per bootstrap). Only the
	// nonce is the per-activation fence.
	if nonce == "" || o.journal.scope.Generation != r.NativeGeneration || subtle.ConstantTimeCompare([]byte(nonce), []byte(r.Nonce)) != 1 {
		return nil, ErrFenced
	}
	snapshot := o.physicalSnapshot()
	if snapshot.IdentityPending || snapshot.PID <= 0 || snapshot.NativeStartIdentity == "" || snapshot.NativeGeneration != generation || snapshot.NativeSessionID == "" || r.NativeSessionID != "" && r.NativeSessionID != snapshot.NativeSessionID {
		return nil, ErrFenced
	}
	read := func(pid int) (localpeer.ProcessSnapshot, error) {
		process, e := localpeer.ReadProcess(pid)
		if e != nil {
			return process, e
		}
		if pid == r.Peer.PID && process != r.Peer {
			return process, ErrFenced
		}
		if pid == snapshot.PID && strconv.FormatInt(process.Start, 10) != snapshot.NativeStartIdentity {
			return process, ErrFenced
		}
		return process, nil
	}
	if e := localpeer.VerifyProcessTree(r.Peer.PID, snapshot.PID, r.Peer.UID, read); e != nil {
		return nil, ErrFenced
	}
	o.mu.Lock()
	unchanged := o.generation == generation && o.nonce == nonce
	o.mu.Unlock()
	if !unchanged {
		return nil, ErrFenced
	}
	if _, e := o.relay.authorizeNativeEffect(lease); e != nil {
		return nil, e
	}
	return &HostedPeerVerificationResult{r.Peer, o.journal.scope, o.journal.scope.Generation, snapshot.NativeSessionID, snapshot.PID, snapshot.NativeStartIdentity}, nil
}
