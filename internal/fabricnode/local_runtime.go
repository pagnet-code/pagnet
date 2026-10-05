package fabricnode

import (
	"context"
	"sync"
	"time"

	"github.com/pagnet-code/pagnet/fabric/registry"
)

// LocalRuntimeConfig explicitly chooses the local installation trust boundary.
// Operator and CleanupCaller come from the SAME protected installation, never
// wire assertions or independently constructed historical principal contexts.
type LocalRuntimeConfig struct {
	Native          NativeRuntimeConfig
	Operator        LocalOperator
	BoundaryTimeout time.Duration
}

type LocalRuntime struct {
	*NativeRuntime
	Boundary  *LocalBoundary
	closeOnce sync.Once
}

// NewLocalRuntime keeps the constructor cycle private: startup can use only the
// protected operator, current caller callbacks deny until the genuine peer
// authority is sealed, and no listener/ports escape before that seal completes.
func NewLocalRuntime(ctx context.Context, store *registry.Store, c LocalRuntimeConfig) (*LocalRuntime, error) {
	if c.Native.CleanupCaller == nil || c.Native.Fence != nil || c.Native.Admission != nil || c.Native.Policy != nil || c.Native.StartupPolicy != nil {
		return nil, localDenied()
	}
	boundary, err := newLocalBoundary(ctx, store, c.Native.Owner, c.Operator, c.BoundaryTimeout)
	if err != nil {
		return nil, err
	}
	c.Native.Fence = boundary
	c.Native.Admission = boundary
	c.Native.Policy = boundary
	c.Native.StartupPolicy = boundary
	native, err := NewNativeRuntime(ctx, store, c.Native)
	if err != nil {
		return nil, err
	}
	if err = native.Authenticator.VerifyRetainedRoot(ctx, boundary.root); err != nil {
		_ = native.Close()
		return nil, err
	}
	boundary.mu.Lock()
	boundary.sessions = native.Authenticator
	boundary.mu.Unlock()
	return &LocalRuntime{NativeRuntime: native, Boundary: boundary}, nil
}
func (r *LocalRuntime) Ports() Ports {
	p := r.NativeRuntime.Ports()
	p.Close = r
	return p
}
func (r *LocalRuntime) CloseContext(ctx context.Context) error {
	if r == nil {
		return nil
	}
	r.closeOnce.Do(func() { r.Boundary.mu.Lock(); r.Boundary.closed = true; r.Boundary.mu.Unlock() })
	return r.NativeRuntime.CloseContext(ctx)
}
func (r *LocalRuntime) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return r.CloseContext(ctx)
}
