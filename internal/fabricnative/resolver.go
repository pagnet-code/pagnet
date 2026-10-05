package fabricnative

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"
	"unicode/utf8"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/identity"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/nativeauthority"
)

// ResolverPolicy holds an independent current operator/caller authorization
// fence, not the registry SQLite lock, across this bounded infrastructure action.
// It must not use historical signed admission as current authorization.
type ResolverPolicy interface {
	WithCurrent(context.Context, fabric.ExecutionContext, fabric.EndpointDescriptor, func(context.Context) error) error
}
type CredentialProvider func(context.Context, []string) ([]string, error)
type ResolverConfig struct {
	Authority        *identity.Authority
	Owner            fabric.ExecutionContext
	Profiles         *ProfileStore
	Launcher         *Launcher
	ControllerBootID string
	MaxWorkers       int
	Credentials      CredentialProvider
	Policy           ResolverPolicy
}
type resolverEntry struct {
	gate       chan struct{}
	connection *WorkerConnection
	original   nativeauthority.Scope
}

// Resolver never replaces uncertain physical ownership. Its target gates are
// bounded, cancellation-aware, and retained until Close to avoid reset races.
type Resolver struct {
	config   ResolverConfig
	mu       sync.Mutex
	closed   bool
	active   int
	lifetime context.Context
	cancel   context.CancelFunc
	done     chan struct{}
	entries  map[fabric.EndpointRef]*resolverEntry
}

func NewResolver(c ResolverConfig) (*Resolver, error) {
	if c.Authority == nil || c.Profiles == nil || c.Launcher == nil || c.Policy == nil || c.Credentials == nil || c.MaxWorkers < 1 || c.MaxWorkers > 4096 || c.ControllerBootID == "" || len(c.ControllerBootID) > 128 || !utf8.ValidString(c.ControllerBootID) {
		return nil, checkpointDenied()
	}
	root := c.Authority.Identity()
	if c.Owner.VerifyAuthenticated(root.Namespace) != nil || c.Owner.PrincipalView() != root.Owner || c.Profiles.store != c.Launcher.config.Checkpoints.store || c.Profiles.store != c.Launcher.config.Peers.store || c.Profiles.root.StoreID != root.StoreID {
		return nil, checkpointDenied()
	}
	lifetime, cancel := context.WithCancel(context.Background())
	return &Resolver{config: c, entries: make(map[fabric.EndpointRef]*resolverEntry), lifetime: lifetime, cancel: cancel, done: make(chan struct{})}, nil
}
func (r *Resolver) entry(ctx context.Context, ref fabric.EndpointRef) (*resolverEntry, error) {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil, launchDenied()
	}
	e := r.entries[ref]
	if e == nil {
		if len(r.entries) >= r.config.MaxWorkers {
			r.mu.Unlock()
			return nil, launchDenied()
		}
		e = &resolverEntry{gate: make(chan struct{}, 1)}
		e.gate <- struct{}{}
		r.entries[ref] = e
	}
	r.active++
	r.mu.Unlock()
	select {
	case <-ctx.Done():
		r.finished()
		return nil, ctx.Err()
	case <-e.gate:
		return e, nil
	}
}
func (r *Resolver) descriptor(ctx context.Context, ref fabric.EndpointRef, rev fabric.Revision) (fabric.EndpointDescriptor, identity.Scope, error) {
	d, err := r.config.Profiles.store.GetEndpoint(ctx, ref, rev)
	if err != nil {
		return d, identity.Scope{}, err
	}
	var id string
	for _, b := range d.Bindings {
		if b.Protocol == "local.native" && b.Version == "1" {
			if id != "" {
				return d, identity.Scope{}, fabric.NewError(fabric.CodeInvalidInput, "Native endpoint needs one selected execution binding")
			}
			id = b.ID
		}
	}
	if id == "" {
		return d, identity.Scope{}, fabric.NewError(fabric.CodeUnsupported, "Native execution binding absent")
	}
	return d, identity.Scope{Endpoint: d.Ref, DescriptorRevision: d.Revision, BindingID: id}, nil
}
func (r *Resolver) Resolve(ctx context.Context, caller fabric.ExecutionContext, d fabric.EndpointDescriptor) (WorkerHandle, error) {
	return r.resolve(ctx, caller, d.Ref, d.Revision, nativeauthority.Scope{}, true)
}
func (r *Resolver) Refresh(ctx context.Context, caller fabric.ExecutionContext, original nativeauthority.Scope) (WorkerHandle, error) {
	local, ok := original.Local()
	if !ok || original.Validate() != nil {
		return WorkerHandle{}, checkpointDenied()
	}
	return r.resolve(ctx, caller, local.Endpoint, "", original, false)
}
func (r *Resolver) resolve(ctx context.Context, caller fabric.ExecutionContext, ref fabric.EndpointRef, revision fabric.Revision, expected nativeauthority.Scope, allowLaunch bool) (result WorkerHandle, err error) {
	if r == nil || ctx == nil || caller.VerifyAuthenticated(r.config.Authority.Identity().Namespace) != nil {
		return result, checkpointDenied()
	}
	successful := false
	defer func() {
		if !successful {
			clear(result.ControlKey)
		}
	}()
	bounded, cancel := context.WithTimeout(ctx, r.config.Launcher.config.StartupTimeout)
	stop := context.AfterFunc(r.lifetime, cancel)
	defer func() { stop(); cancel() }()
	ctx = bounded
	e, err := r.entry(ctx, ref)
	if err != nil {
		return result, err
	}
	defer func() { e.gate <- struct{}{}; r.finished() }()
	d, scope, err := r.descriptor(ctx, ref, revision)
	if err != nil {
		return result, err
	}
	err = onceCurrentPolicy(ctx, func(next func(context.Context) error) error { return r.config.Policy.WithCurrent(ctx, caller, d, next) }, func(current context.Context) error {
		if current == nil || current.Err() != nil {
			return checkpointDenied()
		}
		// Re-read after entering policy: changed descriptor is never authorized by
		// the earlier snapshot passed to the policy port.
		actual, _, err := r.descriptor(current, ref, d.Revision)
		if err != nil {
			return err
		}
		if !equalNativeValue(actual, d) {
			return checkpointDenied()
		}
		profile, _, err := r.config.Profiles.Get(current, registry.DescriptorBatchScope{Endpoint: ref, ExpectedEndpointRevision: d.Revision, BindingID: scope.BindingID})
		if err != nil {
			return err
		}
		control, binding, err := r.config.Authority.RetainedNativeControl(current, r.config.Owner, scope)
		if err != nil {
			return err
		}
		if binding.Worker != profile.Worker {
			return fabric.NewError(fabric.CodeStaleReference, "Private profile differs from retained physical worker")
		}
		if control.ControllerID != r.config.ControllerBootID || control.Scope != scope {
			raw, _ := json.Marshal(struct {
				Boot  string
				Scope identity.Scope
				Epoch uint64
			}{r.config.ControllerBootID, scope, control.Epoch()})
			digest := sha256.Sum256(raw)
			control, err = r.config.Authority.AcquireController(current, r.config.Owner, scope, control.Epoch(), "resolver-"+hex.EncodeToString(digest[:]), r.config.ControllerBootID)
			if err != nil {
				return err
			}
		}
		binding, err = r.config.Authority.RenewWorkerBinding(current, r.config.Owner, control, binding)
		if err != nil {
			return err
		}
		physical, err := nativeauthority.NewLocalScope(r.config.Authority.Identity(), binding)
		if err != nil {
			return err
		}
		claim, err := r.config.Launcher.config.Checkpoints.LookupLaunch(current, physical)
		original, exists := claim.Ownership, claim.Exists
		if exists && claim.Directory != profile.Directory {
			return fabric.NewError(fabric.CodeStaleReference, "Original physical worker directory differs from current profile")
		}
		if err != nil {
			return err
		}
		if expected.Kind() != nativeauthority.Kind("") && (!exists || original != expected) {
			return checkpointDenied()
		}
		if e.original.Kind() != nativeauthority.Kind("") && (!exists || e.original != original) {
			return checkpointDenied()
		}
		if !exists {
			if !allowLaunch {
				return launchDenied()
			}
			env, err := r.config.Credentials(current, append([]string(nil), profile.Native.CredentialEnvKeys...))
			if err != nil {
				return err
			}
			key := make([]byte, 32)
			defer clear(key)
			if _, err = rand.Read(key); err != nil {
				return err
			}
			connection, err := r.config.Launcher.Launch(current, LaunchSpec{Directory: profile.Directory, Ownership: physical, Native: profile.Native, ControlKey: key, RuntimeEnvironment: env, Attempt: "launch-" + control.RequestID, ControllerID: r.config.ControllerBootID})
			if err != nil {
				return err
			}
			e.connection = connection
			e.original = physical
		} else {
			e.original = original
			healthy := false
			if e.connection != nil && e.connection.Ownership == original && e.connection.Directory == claim.Directory {
				p, err := e.connection.Client.OwnerProcess()
				healthy = err == nil && p == e.connection.Process
			}
			if !healthy {
				connection, err := r.config.Launcher.Adopt(current, claim.Directory, original, r.config.ControllerBootID)
				if err != nil {
					return err
				}
				e.connection = connection
			}
		}
		key := e.connection.KeyCopy()
		if len(key) != 32 {
			clear(key)
			return launchDenied()
		}
		result = WorkerHandle{InputBindingProfile: profile.Native.InputBindingProfile, Current: control, Binding: binding, Ownership: e.original, Directory: profile.Directory, ControlKey: key, Client: e.connection.Client}
		return nil
	})
	if err != nil {
		clear(result.ControlKey)
		return WorkerHandle{}, err
	}
	successful = true
	return result, nil
}

// onceCurrentPolicy owns the callback admission lifetime. The mutex joins any
// admitted callback before returning; escaped/repeated callbacks cannot access
// released target state. Policy implementations must hold their independent
// authorization fence synchronously through the callback and honor its context.
func onceCurrentPolicy(ctx context.Context, policy func(func(context.Context) error) error, step func(context.Context) error) error {
	var mu sync.Mutex
	active, calls, misused := true, 0, false
	defer func() { mu.Lock(); active = false; mu.Unlock() }()
	var stepError error
	outer := policy(func(current context.Context) error {
		mu.Lock()
		defer mu.Unlock()
		if !active || calls != 0 || current == nil || ctx.Err() != nil || current.Err() != nil {
			misused = true
			return checkpointDenied()
		}
		calls++
		bounded, cancel := context.WithCancel(current)
		stop := context.AfterFunc(ctx, cancel)
		defer func() { stop(); cancel() }()
		if deadline, ok := ctx.Deadline(); ok {
			withDeadline, finish := context.WithDeadline(bounded, deadline)
			defer finish()
			bounded = withDeadline
		}
		stepError = step(bounded)
		return stepError
	})
	mu.Lock()
	defer mu.Unlock()
	active = false
	if stepError != nil {
		return stepError
	}
	if outer != nil {
		return outer
	}
	if calls != 1 || misused {
		return checkpointDenied()
	}
	return nil
}

// Close prevents new resolutions and relinquishes controller IPC. It does not
// stop native owners or erase launch uncertainty/vendor history.
func (r *Resolver) finished() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.active--
	if r.closed && r.active == 0 {
		close(r.done)
	}
}
func (r *Resolver) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	if !r.closed {
		r.closed = true
		r.cancel()
		if r.active == 0 {
			close(r.done)
		}
	}
	r.mu.Unlock()
	return r.config.Launcher.Close()
}

// CloseContext joins genuine in-flight infrastructure actions before the caller
// closes the retained registry. A cancellation-ignoring policy can delay joining;
// the supplied deadline bounds the wait, never pretends that callback stopped.
func (r *Resolver) CloseContext(ctx context.Context) error {
	if ctx == nil {
		return checkpointDenied()
	}
	if r == nil {
		return nil
	}
	err := r.Close()
	select {
	case <-r.done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}
