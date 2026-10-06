package fabricnode

import (
	"context"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/events/durable"
	"github.com/pagnet-code/pagnet/fabric/identity"
	"github.com/pagnet-code/pagnet/fabric/node/dispatch"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/fabricauth"
	"github.com/pagnet-code/pagnet/internal/fabrichost"
	"github.com/pagnet-code/pagnet/internal/fabricnative"
)

// NativeRuntimeConfig is private operator configuration. Owner must already be
// authenticated against this retained root. Protector keys and runtime
// credentials are supplied by the operator, never generated or persisted here.
type NativeRuntimeConfig struct {
	CleanupCaller                                            func(context.Context) (fabric.ExecutionContext, error)
	Owner                                                    fabric.ExecutionContext
	Fence                                                    identity.AdmissionFence
	Protector                                                durable.DataProtector
	Admission                                                dispatch.Admission
	Policy                                                   fabricnative.ResolverPolicy
	StartupPolicy                                            fabricnative.StartupPolicy
	Credentials                                              fabricnative.CredentialProvider
	Binary, AuthorityDirectory, SocketPath, ControllerBootID string
	MaxWorkers, MaxStartupMetadataBytes                      int
	StartupTimeout, MaxInvocationDuration, CleanupTimeout    time.Duration
	// OwnerValidator overrides the authenticator's owner guard. Nil = the
	// local managed peers' owner validator (the default). The installed hosted
	// product supplies the chained original-worker guard here.
	OwnerValidator fabricauth.OwnerValidator
	// HostedValidator / HostedFacts enable hosted-socket authentication on the
	// node's private listener. Both must be set together (the fabricauth
	// contract); nil = no hosted capability (the default). The installed
	// hosted product supplies fail-closed closures over the deferred runtime
	// bindings, so SupportsHosted holds at fabrichost.Start while the socket
	// denies until the bindings are wired.
	HostedValidator fabricauth.HostedValidator
	HostedFacts     fabricauth.HostedFactsProvider
}

// NativeRuntime uses the one Store supplied to Open.Compose. It neither owns
// that Store nor opens a listener. Successful construction means every retained
// original worker has been authenticated and classified before owner sessions
// can be admitted. Missing workers are errors, including retired endpoints.
type NativeRuntime struct {
	Authority       *identity.Authority
	Profiles        *fabricnative.ProfileStore
	Checkpoints     *fabricnative.Checkpoints
	Peers           *fabricnative.ManagedPeers
	Resolver        *fabricnative.Resolver
	Adapter         *fabricnative.Adapter
	Authenticator   *fabricauth.Authority
	BindingProvider *NativeBindingProvider
	router          *Router
	admission       dispatch.Admission
	closing         atomic.Bool
	executionPaths  NativeExecutionPaths
}

// NativeExecutionPaths are immutable host-private launcher selections.
// They are never descriptor fields or request-selected execution authority.
type NativeExecutionPaths struct{ Binary, AuthorityDirectory, SocketPath string }

func (r *NativeRuntime) ExecutionPaths() NativeExecutionPaths {
	if r == nil {
		return NativeExecutionPaths{}
	}
	return r.executionPaths
}

func NewNativeRuntime(ctx context.Context, store *registry.Store, c NativeRuntimeConfig) (_ *NativeRuntime, err error) {
	if ctx == nil || store == nil || c.Fence == nil || c.Protector == nil || c.Admission == nil || c.Policy == nil || c.StartupPolicy == nil || c.Credentials == nil || !filepath.IsAbs(c.AuthorityDirectory) || filepath.Clean(c.AuthorityDirectory) != c.AuthorityDirectory || !filepath.IsAbs(c.SocketPath) || filepath.Clean(c.SocketPath) != c.SocketPath {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Missing genuine native runtime composition")
	}
	// Native processes are denied access to the authority directory. Their
	// direct authenticated socket must be outside it, not an exception exposing
	// the registry/signing/configuration filesystem to the runtime.
	relative, pathError := filepath.Rel(c.AuthorityDirectory, c.SocketPath)
	if pathError != nil || relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Native peer socket must be outside the authority directory")
	}
	root, err := store.CurrentAuthorityIdentity(ctx)
	if err != nil {
		return nil, err
	}
	if c.Owner.VerifyAuthenticated(root.Namespace) != nil || c.Owner.PrincipalView() != root.Owner {
		return nil, fabric.NewError(fabric.CodeUnauthenticated, "Current retained root owner required")
	}
	r := &NativeRuntime{admission: c.Admission, executionPaths: NativeExecutionPaths{c.Binary, c.AuthorityDirectory, c.SocketPath}}
	var launcher *fabricnative.Launcher
	defer func() {
		if err != nil {
			if r.Resolver != nil {
				_ = r.Close()
			} else if launcher != nil {
				_ = launcher.Close()
			}
		}
	}()
	r.Authority, err = identity.New(store, c.Fence)
	if err != nil {
		return nil, err
	}
	r.Profiles, err = fabricnative.NewProfileStore(ctx, store, c.Owner, c.Protector)
	if err != nil {
		return nil, err
	}
	r.Checkpoints, err = fabricnative.NewCheckpoints(store, r.Authority, c.Owner, c.Protector)
	if err != nil {
		return nil, err
	}
	r.Peers, err = fabricnative.NewManagedPeers(store, r.Authority, c.Owner)
	if err != nil {
		return nil, err
	}
	launcher, err = fabricnative.NewLauncher(fabricnative.LauncherConfig{Checkpoints: r.Checkpoints, Peers: r.Peers, Binary: c.Binary, AuthorityDirectory: c.AuthorityDirectory, StartupTimeout: c.StartupTimeout, MaxWorkers: c.MaxWorkers})
	if err != nil {
		return nil, err
	}
	r.Resolver, err = fabricnative.NewResolver(fabricnative.ResolverConfig{Authority: r.Authority, Owner: c.Owner, Profiles: r.Profiles, Launcher: launcher, ControllerBootID: c.ControllerBootID, MaxWorkers: c.MaxWorkers, Credentials: c.Credentials, Policy: c.Policy})
	if err != nil {
		return nil, err
	}
	r.Adapter, err = fabricnative.NewAdapter(fabricnative.AdapterConfig{CleanupCaller: c.CleanupCaller, Authority: r.Authority, Owner: c.Owner, Checkpoints: r.Checkpoints, ManagedPeers: r.Peers, Workers: r.Resolver, MaxWorkers: c.MaxWorkers, MaxInvocationDuration: c.MaxInvocationDuration, CleanupTimeout: c.CleanupTimeout})
	if err != nil {
		return nil, err
	}
	_, err = fabricnative.RecoverStartup(ctx, fabricnative.StartupConfig{Checkpoints: r.Checkpoints, Launcher: launcher, ControllerBootID: c.ControllerBootID, MaxWorkers: c.MaxWorkers, MaxMetadataBytes: c.MaxStartupMetadataBytes, Policy: c.StartupPolicy})
	if err != nil {
		return nil, err
	}
	ownerValidator := r.Peers.ValidateOwner
	if c.OwnerValidator != nil {
		ownerValidator = c.OwnerValidator
	}
	if (c.HostedValidator == nil) != (c.HostedFacts == nil) {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Hosted validator and facts must be composed together")
	}
	r.Authenticator, err = fabricauth.New(fabricauth.Config{Root: root, RootOwner: root.Owner, Audience: root.Namespace, SocketPath: c.SocketPath, CurrentRoot: func(ctx context.Context) (registry.AuthorityIdentity, error) {
		if r.closing.Load() {
			return registry.AuthorityIdentity{}, fabric.NewError(fabric.CodeTargetUnavailable, "Native runtime is closing")
		}
		return store.CurrentAuthorityIdentity(ctx)
	}, OwnerValidator: ownerValidator, ManagedValidator: r.Peers.ValidateManaged, ManagedFacts: r.Peers.CurrentCallerFacts, HostedValidator: c.HostedValidator, HostedFacts: c.HostedFacts})
	if err != nil {
		return nil, err
	}
	r.BindingProvider = &NativeBindingProvider{Profiles: r.Profiles, Adapter: r.Adapter}
	r.router, err = NewRouter(map[BindingProtocol]BindingProvider{{Protocol: "local.native", Version: "1"}: r.BindingProvider})
	if err != nil {
		return nil, err
	}
	return r, nil
}

// Ports supplies actual kernel authentication, exact native routing and the
// explicitly injected dispatch admission. Assign these in Open.Compose; the
// node closes this runtime before releasing its Store. Transport sessions must
// be joined first, as required by Node.Close.
func (r *NativeRuntime) Ports() Ports {
	return Ports{Authenticator: r.Authenticator, Bindings: r.router, Admission: r.admission, Close: r}
}

// ManagedResolver is for the direct private host socket, not a worker proxy.
func (r *NativeRuntime) ManagedResolver() fabrichost.ManagedResolver { return r.Peers.ResolveManaged }

// CloseContext prevents new kernel authentication and joins resolver actions.
// A deadline error means joining is incomplete: the caller must not close the
// Store yet. Detached original workers and their vendor history are preserved.
func (r *NativeRuntime) CloseContext(ctx context.Context) error {
	if ctx == nil {
		return fabric.NewError(fabric.CodeInvalidInput, "Missing shutdown context")
	}
	if r == nil {
		return nil
	}
	r.closing.Store(true)
	return r.Resolver.CloseContext(ctx)
}

// Close performs a genuine join before Node.Close releases the registry writer.
// Cancellation-ignoring operator policy may delay it; no forced completion is
// claimed. Call CloseContext for a bounded attempt without releasing the Store.
func (r *NativeRuntime) Close() error { return r.CloseContext(context.Background()) }
