package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"sync"

	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

// NativeWorkerProxy reconnects a controller to a worker it already owns. It
// never launches/adopts a PID or changes an execution profile. Production
// command routing still requires durable intent mapping and source delivery.
type NativeWorkerProxy struct {
	connection   *NativeObservationConnection
	controller   *sessionworker.Controller
	scope        sessionworker.Scope
	profile      string
	bootstrap    sessionworker.Bootstrap
	done         chan struct{}
	closeOnce    sync.Once
	sourceMu     sync.Mutex
	sourceCursor int64
}

func AttachNativeWorker(ctx context.Context, connection *NativeObservationConnection, dir string, expected sessionworker.Scope, controllerID string) (*NativeWorkerProxy, error) {
	if connection == nil {
		return nil, ErrNativeOriginAdmissionDeferred
	}
	b, key, err := sessionworker.LoadControllerBootstrap(dir, expected)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	// A disconnected or differently scoped control-plane connection cannot
	// acquire a local controller lease and evict the existing controller.
	if _, err := connection.NativeWorkerAdmission(expected, b.Native.NetworkID, b.Native.Kind); err != nil {
		return nil, err
	}
	c, err := sessionworker.DialOwnerController(ctx, dir, expected, key, controllerID)
	if err != nil {
		return nil, err
	}
	p := &NativeWorkerProxy{connection: connection, controller: c, scope: expected, profile: sessionworker.NativeProfileFingerprint(b.Native), bootstrap: b, done: make(chan struct{})}
	if _, err := p.Snapshot(ctx); err != nil {
		_ = p.Close()
		return nil, err
	}
	if err := p.RefreshAdmission(ctx); err != nil {
		_ = p.Close()
		return nil, err
	}
	go func() {
		select {
		case <-connection.closed:
			_ = p.Close()
		case <-p.done:
		}
	}()
	return p, nil
}

// Close relinquishes the controller and fresh admission, leaving the worker
// and its independently owned native session running.
func (p *NativeWorkerProxy) Close() error {
	var err error
	p.closeOnce.Do(func() {
		close(p.done)
		err = p.controller.Close()
	})
	return err
}

func (p *NativeWorkerProxy) call(ctx context.Context, request sessionworker.Request) (sessionworker.Response, error) {
	select {
	case <-p.done:
		return sessionworker.Response{}, ErrNativeOriginAdmissionDeferred
	default:
	}
	if _, err := p.connection.NativeWorkerAdmission(p.scope, p.bootstrap.Native.NetworkID, p.bootstrap.Native.Kind); err != nil {
		return sessionworker.Response{}, err
	}
	response, err := p.controller.Call(ctx, request)
	if err != nil {
		_ = p.Close()
		return sessionworker.Response{}, err
	}
	if response.Error != "" {
		if response.Retryable {
			return sessionworker.Response{}, errors.Join(ErrNativeOriginAdmissionDeferred, errors.New(response.Error))
		}
		return sessionworker.Response{}, errors.New(response.Error)
	}
	// Do not expose observations/inspection after the authenticated remote
	// connection disappears while the owner-local RPC is in flight.
	if _, err := p.connection.NativeWorkerAdmission(p.scope, p.bootstrap.Native.NetworkID, p.bootstrap.Native.Kind); err != nil {
		return sessionworker.Response{}, err
	}
	return response, nil
}

// DrainSources keeps the authenticated journal scan cursor for this proxy's
// lifetime. An error retains the returned cursor, so a later page never makes
// an unsupported prefix starve valid evidence behind it.
func (p *NativeWorkerProxy) DrainSources(ctx context.Context) error {
	p.sourceMu.Lock()
	defer p.sourceMu.Unlock()
	next, err := p.connection.DrainNativeWorkerSourcesPage(ctx, p.SourceCall, p.sourceCursor)
	p.sourceCursor = next
	return err
}

func (p *NativeWorkerProxy) RefreshAdmission(ctx context.Context) error {
	admission, err := p.connection.NativeWorkerAdmission(p.scope, p.bootstrap.Native.NetworkID, p.bootstrap.Native.Kind)
	if err != nil {
		return err
	}
	_, err = p.call(ctx, sessionworker.Request{Type: "admission", Admission: &admission})
	return err
}

func (p *NativeWorkerProxy) Snapshot(ctx context.Context) (sessionworker.NativeSnapshot, error) {
	response, err := p.call(ctx, sessionworker.Request{Type: "snapshot"})
	if err != nil {
		return sessionworker.NativeSnapshot{}, err
	}
	if response.Snapshot == nil || response.Snapshot.Scope != p.scope || response.Snapshot.ProfileFingerprint != p.profile || response.Snapshot.ActualRuntime != p.bootstrap.Native.Runtime {
		_ = p.Close()
		return sessionworker.NativeSnapshot{}, ErrNativeObservationConflict
	}
	return *response.Snapshot, nil
}

// SourceCall is the lease-fenced journal lane for durable source delivery. The
// drain verifies an exact backend commit receipt before observation_ack. This
// lane cannot submit native intents, resolve an approval, or relay a tool.
func (p *NativeWorkerProxy) SourceCall(ctx context.Context, request sessionworker.Request) (sessionworker.Response, error) {
	switch request.Type {
	case "observations", "content_fragment", "source_capture", "observation_ack":
		return p.call(ctx, request)
	default:
		return sessionworker.Response{}, errors.New("unsupported native source journal request")
	}
}

// Reconcile authorizes a pending original activation or confirms the exact
// live session under this connection. Repeated calls are safe across transient
// server failure; original source admission is supplied by the worker.
func (p *NativeWorkerProxy) Reconcile(ctx context.Context) error {
	if err := p.RefreshAdmission(ctx); err != nil {
		return err
	}
	response, err := p.call(ctx, sessionworker.Request{Type: "activation_poll"})
	if err != nil {
		return err
	}
	if response.Activation != nil {
		request := *response.Activation
		if request.ActualRuntime != p.bootstrap.Native.Runtime || request.NetworkID != p.bootstrap.Native.NetworkID || request.NetworkTenantID != p.bootstrap.Native.NetworkTenantID {
			return ErrNativeObservationConflict
		}
		origin, err := p.connection.AuthorizeNativeWorkerActivation(ctx, p.scope, request)
		if err != nil {
			return err
		}
		_, err = p.call(ctx, sessionworker.Request{Type: "activation_origin", ActivationOrigin: &origin})
		return err
	}
	snapshot, err := p.Snapshot(ctx)
	if err != nil {
		return err
	}
	if snapshot.PID == 0 || snapshot.NativeSessionID == "" {
		return nil // inactive or still materializing; this is not live proof.
	}
	var origin transport.NativeObservationOrigin
	if json.Unmarshal(snapshot.Origin, &origin) != nil {
		return ErrNativeObservationConflict
	}
	return p.connection.ConfirmNativeWorkerSession(ctx, p.scope, origin, p.profile, p.Snapshot)
}
