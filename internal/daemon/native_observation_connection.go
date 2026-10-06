package daemon

import (
	"context"
	"errors"
	"net/url"
	"sync"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
)

var ErrNativeOriginAdmissionDeferred = errors.New("native activation admission must retry")
var ErrNativeOriginAdmissionRejected = errors.New("native activation admission rejected")

// NativeObservationConnection belongs to one authenticated WebSocket only.
// Its writer must never select a replacement connection behind this object's
// back: registration and replies are fenced to the same runner admission.
type NativeObservationConnection struct {
	mu                   sync.Mutex
	hostID, bootID       string
	serverURL            string
	session              *transport.HostSessionPayload
	pending              map[string]chan transport.NativeOriginRegisteredPayload
	pendingSessions      map[string]chan transport.NativeOriginSessionConfirmedPayload
	pendingContent       map[string]chan transport.NativeContentStagedPayload
	pendingObservations  map[string]chan transport.NativeObservationReceiptPayload
	// pendingHostedFabric carries the in-flight FabricHosted* request ids to
	// their raw reply channel: both the publish/invoke result and the
	// catalog page reply correlate on the same lane (the typed exchanges
	// assert the reply type, so a mixed correlation is a conflict).
	pendingHostedFabric  map[string]chan any
	pendingOwnership     map[string]chan transport.NativeOwnershipRegisteredPayload
	pendingTaskInputs    map[string]chan transport.NativeTaskInputReadPayload
	pendingCancellations map[string]chan transport.Envelope
	closed               chan struct{}
	send                 func(context.Context, string, any) error
}

func NewNativeObservationConnection(serverURL, hostID, bootID string, send func(context.Context, string, any) error) *NativeObservationConnection {
	return &NativeObservationConnection{serverURL: serverURL, hostID: hostID, bootID: bootID, send: send, pending: make(map[string]chan transport.NativeOriginRegisteredPayload), pendingSessions: make(map[string]chan transport.NativeOriginSessionConfirmedPayload), closed: make(chan struct{})}
}

func (c *NativeObservationConnection) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return
	default:
		close(c.closed)
	}
	c.session = nil
}

func (c *NativeObservationConnection) Admit(p transport.HostSessionPayload) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return ErrNativeOriginAdmissionDeferred
	default:
	}
	endpoint, err := url.Parse(c.serverURL)
	if err != nil || (endpoint.Scheme != "https" && endpoint.Scheme != "http") || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return ErrNativeObservationConflict
	}
	if p.HostID != c.hostID || p.BootID != c.bootID || p.RunnerEpoch.IsZero() {
		return ErrNativeObservationConflict
	}
	if p.OwnershipScope != "personal" && p.OwnershipScope != "organization" {
		return ErrNativeObservationConflict
	}
	if _, err := domain.ParseID(p.TenantID); err != nil {
		return ErrNativeObservationConflict
	}
	if _, err := domain.ParseID(p.AccountID); err != nil {
		return ErrNativeObservationConflict
	}
	if p.OwnershipScope == "organization" && p.AccountID != p.TenantID {
		return ErrNativeObservationConflict
	}
	if _, err := domain.ParseID(p.NativeAdmissionID); err != nil {
		return ErrNativeObservationConflict
	}
	if _, err := domain.ParseID(p.RunnerID); err != nil {
		return ErrNativeObservationConflict
	}
	negotiated := false
	for _, feature := range p.ProtocolFeatures {
		if feature == transport.NativeObservationReceiptProtocol {
			negotiated = true
		}
	}
	if !negotiated {
		return errors.New("native observation receipts unavailable")
	}
	if c.session != nil {
		if c.session.TenantID != p.TenantID || c.session.AccountID != p.AccountID || c.session.OwnershipScope != p.OwnershipScope || c.session.NativeAdmissionID != p.NativeAdmissionID || c.session.RunnerID != p.RunnerID || !c.session.RunnerEpoch.Equal(p.RunnerEpoch) {
			return ErrNativeObservationConflict
		}
		return nil
	}
	copy := p
	copy.ProtocolFeatures = append([]string(nil), p.ProtocolFeatures...)
	c.session = &copy
	return nil
}

func (c *NativeObservationConnection) RegisterOrigin(ctx context.Context, commandID, instanceID, runtime, nativeGeneration string) (*transport.NativeObservationOrigin, error) {
	c.mu.Lock()
	if c.session == nil {
		c.mu.Unlock()
		return nil, ErrNativeOriginAdmissionDeferred
	}
	source := *c.session
	c.mu.Unlock()
	return c.RegisterOriginForSource(ctx, source, commandID, instanceID, runtime, nativeGeneration)
}

// RegisterOriginForSource keeps the activation's original source admission
// immutable while this connection supplies fresh controller authorization.
func (c *NativeObservationConnection) RegisterOriginForSource(ctx context.Context, source transport.HostSessionPayload, commandID, instanceID, runtime, nativeGeneration string) (*transport.NativeObservationOrigin, error) {
	if source.HostID != c.hostID || source.RunnerEpoch.IsZero() || source.BootID == "" {
		return nil, ErrNativeObservationConflict
	}
	if _, err := domain.ParseID(source.NativeAdmissionID); err != nil {
		return nil, ErrNativeObservationConflict
	}
	if _, err := domain.ParseID(source.RunnerID); err != nil {
		return nil, ErrNativeObservationConflict
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	request := domain.NewID().String()
	reply := make(chan transport.NativeOriginRegisteredPayload, 1)
	c.mu.Lock()
	select {
	case <-c.closed:
		c.mu.Unlock()
		return nil, ErrNativeOriginAdmissionDeferred
	default:
	}
	if c.session == nil {
		c.mu.Unlock()
		return nil, ErrNativeOriginAdmissionDeferred
	}
	if source.TenantID != c.session.TenantID || source.AccountID != c.session.AccountID {
		c.mu.Unlock()
		return nil, ErrNativeObservationConflict
	}
	if c.pendingCountLocked() >= 64 {
		c.mu.Unlock()
		return nil, ErrNativeObservationCapacity
	}
	expected := source
	c.pending[request] = reply
	c.mu.Unlock()
	defer func() { c.mu.Lock(); delete(c.pending, request); c.mu.Unlock() }()
	if err := c.send(ctx, transport.MsgNativeOriginRegister, transport.NativeOriginRegisterPayload{NativeAdmissionID: source.NativeAdmissionID, RequestID: request, CommandID: commandID, InstanceID: instanceID, Runtime: runtime, NativeGeneration: nativeGeneration}); err != nil {
		return nil, err
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.closed:
		return nil, ErrNativeOriginAdmissionDeferred
	case response := <-reply:
		c.mu.Lock()
		select {
		case <-c.closed:
			c.mu.Unlock()
			return nil, ErrNativeOriginAdmissionDeferred
		default:
		}
		c.mu.Unlock()
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if response.PublicError != "" || response.Origin == nil {
			if response.Retryable {
				return nil, ErrNativeOriginAdmissionDeferred
			}
			return nil, ErrNativeOriginAdmissionRejected
		}
		o := response.Origin
		// Existing same-boot origins retain their original epoch on reconnect.
		if o.NativeAdmissionID != source.NativeAdmissionID || o.NativeGeneration != nativeGeneration || o.HostID != expected.HostID || o.RunnerID != expected.RunnerID || o.BootID != expected.BootID || o.CommandID != commandID || o.InstanceID != instanceID || o.Runtime != runtime || o.RunnerEpoch.IsZero() || !o.RunnerEpoch.Equal(expected.RunnerEpoch) || o.CreatedAt.IsZero() {
			return nil, ErrNativeObservationConflict
		}
		if _, err := domain.ParseID(o.ID); err != nil {
			return nil, ErrNativeObservationConflict
		}
		return o, nil
	}
}

func (c *NativeObservationConnection) OriginRegistered(p transport.NativeOriginRegisteredPayload) {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return
	default:
	}
	reply := c.pending[p.RequestID]
	if reply == nil {
		return
	}
	select {
	case reply <- p:
	default:
	}
}

// ConfirmSession requires a fresh read of the actual authenticated worker's
// live driver and captured kernel birth identity before it may renew transport
// authority. Saved origin descriptors and journal rows are never live proof.
func (c *NativeObservationConnection) ConfirmSession(ctx context.Context, origin transport.NativeObservationOrigin, sessionID string, verifyLive func(context.Context) error) error {
	if verifyLive == nil || origin.NativeGeneration == "" || sessionID == "" {
		return ErrNativeOriginAdmissionRejected
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := verifyLive(ctx); err != nil {
		return err
	}
	request := domain.NewID().String()
	reply := make(chan transport.NativeOriginSessionConfirmedPayload, 1)
	c.mu.Lock()
	select {
	case <-c.closed:
		c.mu.Unlock()
		return ErrNativeOriginAdmissionDeferred
	default:
	}
	if c.session == nil {
		c.mu.Unlock()
		return ErrNativeOriginAdmissionDeferred
	}
	if origin.HostID != c.hostID {
		c.mu.Unlock()
		return ErrNativeObservationConflict
	}
	if c.pendingCountLocked() >= 64 {
		c.mu.Unlock()
		return ErrNativeObservationCapacity
	}
	admitted := *c.session
	c.pendingSessions[request] = reply
	c.mu.Unlock()
	defer func() { c.mu.Lock(); delete(c.pendingSessions, request); c.mu.Unlock() }()
	p := transport.NativeOriginSessionPayload{RequestID: request, OriginID: origin.ID, InstanceID: origin.InstanceID, Runtime: origin.Runtime, NativeGeneration: origin.NativeGeneration, SessionID: sessionID, RunnerID: admitted.RunnerID, RunnerEpoch: admitted.RunnerEpoch, BootID: admitted.BootID}
	if err := c.send(ctx, transport.MsgNativeOriginSession, p); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.closed:
		return ErrNativeOriginAdmissionDeferred
	case response := <-reply:
		c.mu.Lock()
		select {
		case <-c.closed:
			c.mu.Unlock()
			return ErrNativeOriginAdmissionDeferred
		default:
		}
		c.mu.Unlock()
		if err := ctx.Err(); err != nil {
			return err
		}
		if response.OriginID != origin.ID || response.NativeGeneration != origin.NativeGeneration || response.SessionID != sessionID || response.RunnerID != admitted.RunnerID || !response.RunnerEpoch.Equal(admitted.RunnerEpoch) {
			return ErrNativeObservationConflict
		}
		if response.PublicError != "" {
			if response.Retryable {
				return ErrNativeOriginAdmissionDeferred
			}
			return ErrNativeOriginAdmissionRejected
		}
		// The worker may have changed while the commit receipt was in flight.
		return verifyLive(ctx)
	}
}

func (c *NativeObservationConnection) SessionConfirmed(p transport.NativeOriginSessionConfirmedPayload) {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return
	default:
	}
	reply := c.pendingSessions[p.RequestID]
	if reply == nil {
		return
	}
	select {
	case reply <- p:
	default:
	}
}

// AuthenticatedNativeHostSession returns an immutable copy of the authority
// supplied by this exact authenticated server connection. Local CLI account
// labels and cached worker journals cannot supply host account identities.
func (c *NativeObservationConnection) AuthenticatedNativeHostSession() (transport.HostSessionPayload, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return transport.HostSessionPayload{}, ErrNativeOriginAdmissionDeferred
	default:
	}
	if c.session == nil {
		return transport.HostSessionPayload{}, ErrNativeOriginAdmissionDeferred
	}
	result := *c.session
	result.ProtocolFeatures = append([]string(nil), c.session.ProtocolFeatures...)
	return result, nil
}
