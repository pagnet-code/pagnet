package daemon

import (
	"context"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

func (c *NativeObservationConnection) pendingCountLocked() int {
	return len(c.pending) + len(c.pendingSessions) + len(c.pendingContent) + len(c.pendingObservations) + len(c.pendingOwnership) + len(c.pendingTaskInputs) + len(c.pendingCancellations)
}

func (c *NativeObservationConnection) OwnershipDisposition(p transport.NativeOwnershipRegisteredPayload) {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return
	default:
	}
	if reply := c.pendingOwnership[p.RequestID]; reply != nil {
		select {
		case reply <- p:
		default:
		}
	}
}

func (c *NativeObservationConnection) ownershipExchange(ctx context.Context, requestID, typ string, payload any) (*transport.NativeWorkerOwnership, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	ch := make(chan transport.NativeOwnershipRegisteredPayload, 1)
	c.mu.Lock()
	if err := c.deliveryReadyLocked(false); err != nil {
		c.mu.Unlock()
		return nil, err
	}
	negotiated := false
	for _, feature := range c.session.ProtocolFeatures {
		if feature == transport.NativeWorkerOwnershipProtocol {
			negotiated = true
		}
	}
	if !negotiated {
		c.mu.Unlock()
		return nil, ErrNativeSourceUnsupported
	}
	if c.pendingCountLocked() >= 64 {
		c.mu.Unlock()
		return nil, ErrNativeObservationCapacity
	}
	if c.pendingOwnership == nil {
		c.pendingOwnership = make(map[string]chan transport.NativeOwnershipRegisteredPayload)
	}
	c.pendingOwnership[requestID] = ch
	c.mu.Unlock()
	defer func() { c.mu.Lock(); delete(c.pendingOwnership, requestID); c.mu.Unlock() }()
	if err := c.send(ctx, typ, payload); err != nil {
		return nil, err
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.closed:
		return nil, ErrNativeOriginAdmissionDeferred
	case p := <-ch:
		if _, err := c.AuthenticatedNativeHostSession(); err != nil {
			return nil, err
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if p.PublicError != "" || p.Ownership == nil {
			if p.Retryable {
				return nil, ErrNativeOriginAdmissionDeferred
			}
			return nil, ErrNativeOriginAdmissionRejected
		}
		return p.Ownership, nil
	}
}

func validateOwnership(scope sessionworker.Scope, spec sessionworker.NativeSpec, profile string, o *transport.NativeWorkerOwnership) error {
	if o == nil || o.InstanceID != scope.InstanceID || o.OwnershipGeneration != scope.Generation || o.Runtime != string(spec.Runtime) || o.Profile != profile || o.ProfileFingerprint != sessionworker.NativeProfileFingerprint(spec) || o.LastDispatchSequence < 0 || o.RetiredFloor < 0 || o.RetiredFloor > o.LastDispatchSequence {
		return ErrNativeObservationConflict
	}
	for _, id := range []string{o.ID, o.OriginalAdmissionID} {
		if _, err := domain.ParseID(id); err != nil {
			return ErrNativeObservationConflict
		}
	}
	return nil
}

func (c *NativeObservationConnection) RegisterNativeWorkerOwnership(ctx context.Context, scope sessionworker.Scope, spec sessionworker.NativeSpec, profile, previous string) (*transport.NativeWorkerOwnership, error) {
	admission, err := c.NativeWorkerAdmission(scope, spec.NetworkID, spec.Kind)
	if err != nil {
		return nil, err
	}
	id := domain.NewID().String()
	p := transport.NativeOwnershipRegisterPayload{RequestID: id, NativeAdmissionID: admission.NativeAdmissionID, InstanceID: scope.InstanceID, OwnershipGeneration: scope.Generation, Runtime: string(spec.Runtime), Profile: profile, PreviousOwnershipID: previous, ProfileFingerprint: sessionworker.NativeProfileFingerprint(spec)}
	o, err := c.ownershipExchange(ctx, id, transport.MsgNativeOwnershipRegister, p)
	if err != nil {
		return nil, err
	}
	if err = validateOwnership(scope, spec, profile, o); err != nil {
		return nil, err
	}
	if o.State != "active" {
		return nil, ErrNativeObservationConflict
	}
	after, err := c.NativeWorkerAdmission(scope, spec.NetworkID, spec.Kind)
	if err != nil {
		return nil, err
	}
	if after != admission {
		return nil, ErrNativeObservationConflict
	}
	return o, nil
}

// RetireNativeWorkerOwnership must commit remotely before the controller asks
// the private worker to advance its replay floor or replace its ownership.
func (c *NativeObservationConnection) RetireNativeWorkerOwnership(ctx context.Context, scope sessionworker.Scope, spec sessionworker.NativeSpec, profile string, o transport.NativeWorkerOwnership, floor int64, uncertain []int64, retire bool) (*transport.NativeWorkerOwnership, error) {
	if err := validateOwnership(scope, spec, profile, &o); err != nil {
		return nil, err
	}
	if floor < o.RetiredFloor || floor > o.LastDispatchSequence || len(uncertain) > 128 {
		return nil, ErrNativeObservationConflict
	}
	previous := floor
	for _, ordinal := range uncertain {
		if ordinal <= previous || ordinal > o.LastDispatchSequence {
			return nil, ErrNativeObservationConflict
		}
		previous = ordinal
	}
	admission, err := c.NativeWorkerAdmission(scope, spec.NetworkID, spec.Kind)
	if err != nil {
		return nil, err
	}
	id := domain.NewID().String()
	p := transport.NativeOwnershipRetirePayload{RequestID: id, OwnershipID: o.ID, OwnershipGeneration: scope.Generation, RetiredDispatchSequence: floor, UncertainDispatchSequences: append([]int64(nil), uncertain...), Retire: retire}
	result, err := c.ownershipExchange(ctx, id, transport.MsgNativeOwnershipRetire, p)
	if err != nil {
		return nil, err
	}
	if err = validateOwnership(scope, spec, profile, result); err != nil {
		return nil, err
	}
	expectedState := "active"
	if retire {
		expectedState = "retired"
	}
	if result.ID != o.ID || result.OriginalAdmissionID != o.OriginalAdmissionID || result.RetiredFloor < floor || result.State != expectedState {
		return nil, ErrNativeObservationConflict
	}
	after, err := c.NativeWorkerAdmission(scope, spec.NetworkID, spec.Kind)
	if err != nil {
		return nil, err
	}
	if after != admission {
		return nil, ErrNativeObservationConflict
	}
	return result, nil
}
