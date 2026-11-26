//go:build linux || darwin

package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"sync"
	"sync/atomic"

	"github.com/pagnet-code/pagnet/transport"
)

// These factories only capture an already admitted subscription. They install
// no transport or coordinator and never select a replacement subscription.
func newDirectSourceReconcileOperation(d *Daemon, captured ManagedEndpointPrepareScope, s *DirectEndpointSubscription, issue transport.DirectManagedSourceCredentialIssueV2) (directEndpointMaterialOperation, error) {
	raw, err := issue.CanonicalBytes()
	if err != nil {
		return nil, errDirectEndpointOperationRejected
	}
	owned, err := transport.DecodeDirectManagedSourceCredentialIssueV2(raw)
	if err != nil {
		return nil, errDirectEndpointOperationRejected
	}
	captured, err = ownDirectReconcileOperationScope(d, captured, s, raw, "S", string(owned.PoP.ACK.Reservation.InstallationID))
	if err != nil {
		return nil, err
	}
	return directReconcileOperation(s, func(ctx context.Context, use func(context.Context, endpointMaterial) error) error {
		snapshot, err := transport.DecodeDirectManagedSourceCredentialIssueV2(raw)
		if err != nil {
			return errDirectEndpointOperationRejected
		}
		return d.operateDirectManagedSourceEndpointV2(ctx, captured, s, snapshot, use)
	}), nil
}

func newDirectTargetReconcileOperation(d *Daemon, captured ManagedEndpointPrepareScope, s *DirectEndpointSubscription, issue transport.ManagedDirectCredentialIssue) (directEndpointMaterialOperation, error) {
	raw, err := issue.CanonicalBytes()
	if err != nil {
		return nil, errDirectEndpointOperationRejected
	}
	owned, err := transport.DecodeManagedDirectCredentialIssue(raw)
	if err != nil {
		return nil, errDirectEndpointOperationRejected
	}
	captured, err = ownDirectReconcileOperationScope(d, captured, s, raw, "P", string(owned.PoP.ACK.Reservation.InstallationID))
	if err != nil {
		return nil, err
	}
	return directReconcileOperation(s, func(ctx context.Context, use func(context.Context, endpointMaterial) error) error {
		snapshot, err := transport.DecodeManagedDirectCredentialIssue(raw)
		if err != nil {
			return errDirectEndpointOperationRejected
		}
		return d.operateManagedTargetEndpoint(ctx, captured, s, snapshot, use)
	}), nil
}

func ownDirectReconcileOperationScope(d *Daemon, captured ManagedEndpointPrepareScope, s *DirectEndpointSubscription, raw []byte, role, installation string) (ManagedEndpointPrepareScope, error) {
	if d == nil || s == nil || s.owner != &d.directSubscriptions || captured.Socket == nil || captured.Connection == nil || !s.operationCurrentContext(context.Background()) {
		return ManagedEndpointPrepareScope{}, errDirectEndpointOperationRejected
	}
	session, err := json.Marshal(captured.Session)
	if err != nil || string(session) != s.binding.sessionIdentity || captured.Socket != s.binding.socket || captured.Connection != s.binding.native || sha256.Sum256(raw) != s.binding.issueDigest || s.binding.metadata.Role != role || string(s.binding.metadata.InstallationID) != installation {
		return ManagedEndpointPrepareScope{}, errDirectEndpointOperationRejected
	}
	// Decode into a new value so every negotiated feature slice belongs to us.
	var owned transport.HostSessionPayload
	if json.Unmarshal(session, &owned) != nil {
		return ManagedEndpointPrepareScope{}, errDirectEndpointOperationRejected
	}
	captured.Session = owned
	return captured, nil
}

// A factory may be reused for fresh attempts after return. Each invocation is
// synchronous and has one callback dispatch; concurrent or reentrant attempts
// fail immediately. Custody remains owned by the matching role operation.
func directReconcileOperation(s *DirectEndpointSubscription, operate directEndpointMaterialOperation) directEndpointMaterialOperation {
	var active sync.Mutex
	return func(ctx context.Context, use func(context.Context, endpointMaterial) error) error {
		if ctx == nil || use == nil || !active.TryLock() {
			return errDirectEndpointOperationRejected
		}
		defer active.Unlock()
		var dispatched atomic.Bool
		err := operate(ctx, func(opctx context.Context, material endpointMaterial) error {
			if !dispatched.CompareAndSwap(false, true) {
				return errDirectEndpointOperationRejected
			}
			return use(opctx, material)
		})
		if err != nil {
			return err
		}
		if !dispatched.Load() {
			return errDirectEndpointOperationRejected
		}
		if !s.operationCurrentContext(ctx) {
			return errDirectEndpointOperationUnknown
		}
		return nil
	}
}
