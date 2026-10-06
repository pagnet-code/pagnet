package fabricnode

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/events/httpbinding"
	"github.com/pagnet-code/pagnet/fabric/extension"
	"github.com/pagnet-code/pagnet/fabric/localinstallation"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/fabric/search"
	"github.com/pagnet-code/pagnet/fabric/telemetry"
	"github.com/pagnet-code/pagnet/internal/daemon"
	"github.com/pagnet-code/pagnet/internal/fabricadmin"
	"github.com/pagnet-code/pagnet/internal/fabrichost"
	"github.com/pagnet-code/pagnet/internal/fabricmcp"
	"github.com/pagnet-code/pagnet/internal/fabricnative"
	"github.com/pagnet-code/pagnet/internal/fabricservices"
)

// InstalledConfig loads one explicitly initialized local trust boundary. Native
// credentials are an explicit private provider; nil permits credential-free
// profiles only, and never scrapes environment/provider configuration.
type InstalledConfig struct {
	Directory   string
	Binary      string
	Credentials fabricnative.CredentialProvider
	Tracing     telemetry.Provider
	// Services optionally supplies the explicitly retained operator.private provider.
	// Persisted limits must match; startup never initializes infrastructure.
	Services *ServiceRuntimeConfig
	// ServiceProviders resolves only the explicitly retained provider selector.
	ServiceProviders map[string]fabricservices.CredentialProvider
	// EventProviders resolve only explicitly retained private observer selectors.
	EventProviders map[string]httpbinding.CredentialProvider
	// ExtensionCredentials serves only explicitly configured private slots.
	// Starting a node never installs extensions or initializes their state.
	ExtensionCredentials extension.CredentialProvider
	// ExtensionPaging selects explicit finite private disclosure budgets.
	ExtensionPaging *ExtensionPagerOptions
	// ObserveIndexPublication is trusted bounded observation, never authorization.
	ObserveIndexPublication func(bool, error)
	// Hosted is the explicit installed hosted product. Nil = the product is
	// unavailable (explicit, never implicit). When set, OpenInstalled composes
	// the actual owner guard, runtime bindings, invocation guard, sideports,
	// catalog and admin over the loaded installation. A non-nil Hosted on a
	// platform without the daemon's native worker lane is a startup error, not
	// a silent skip.
	Hosted *InstalledHostedConfig
}

// InstalledNode is the actual local socket/product composition. The installation
// owns the only writer and key; transport joins before runtime, key and Store.
type InstalledNode struct {
	Installation   *localinstallation.Installation
	Node           *Node
	Runtime        *LocalRuntime
	Services       *ServiceRuntime
	Events         *EventRuntime
	Extensions     *ExtensionRuntime
	Publisher      *IndexPublisher
	Hosted         *InstalledHosted
	Host           *fabrichost.Host
	server         *fabricmcp.Server
	admin          *fabricadmin.Server
	extensionAdmin *InstalledExtensionAdministration
	incomplete     *CompositionError
	mu             sync.Mutex
}

type InstalledOpenError struct {
	cause    error
	retained *InstalledNode
}

func (e *InstalledOpenError) Error() string {
	return "Local node could not start; original resources remain held until cleanup completes"
}
func (e *InstalledOpenError) Unwrap() error { return e.cause }
func (e *InstalledOpenError) CloseContext(ctx context.Context) error {
	return e.retained.CloseContext(ctx)
}

// OpenInstalled never initializes, installs software, contacts the cloud or
// launches a native turn. Startup authenticates retained workers before exposing
// the direct owner/managed MCP listener with exactly three network operations.
func OpenInstalled(ctx context.Context, c InstalledConfig) (_ *InstalledNode, err error) {
	if ctx == nil || c.Binary == "" {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Explicit installed node and binary required")
	}
	installation, err := localinstallation.Load(ctx, c.Directory, registry.DefaultOptions())
	if err != nil {
		return nil, err
	}
	result := &InstalledNode{Installation: installation}
	notices := make(chan struct{}, 1)
	notice := func() {
		select {
		case notices <- struct{}{}:
		default:
		}
	}
	var resources *installedRuntimes
	keep := false
	defer func() {
		if !keep {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if cleanupErr := result.CloseContext(cleanupCtx); cleanupErr != nil {
				err = &InstalledOpenError{cause: errors.Join(err, cleanupErr), retained: result}
			}
		}
	}()
	owner, err := installation.Operator(ctx)
	if err != nil {
		return nil, err
	}
	retained, err := LoadInstalledServiceSettings(ctx, installation)
	if err != nil {
		return nil, err
	}
	serviceConfig, err := selectedInstalledServiceConfig(retained, c)
	if err != nil {
		return nil, err
	}
	settings := installation.Configuration().Settings
	boot := make([]byte, 32)
	if _, err = rand.Read(boot); err != nil {
		return nil, err
	}
	credentials := c.Credentials
	if credentials == nil {
		credentials = func(ctx context.Context, slots []string) ([]string, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if len(slots) != 0 {
				return nil, fabric.NewError(fabric.CodeUnsupported, "Configure a private credential provider for this runtime profile")
			}
			return nil, nil
		}
	}
	// The installed hosted product is explicit, never implicit. The owner guard
	// is composed before the native runtime because the runtime's authenticator
	// uses it as the owner validator (chaining the original-worker roots over
	// the local managed-owner gate). Its `next` is fail-closed until the native
	// runtime exists and is wired to the local owner validator below. The
	// bindings, publisher and daemon references are wired post-daemon.
	var (
		hostedDeferred   *hostedDeferred
		hostedOwnerGuard *daemon.HostedOwnerGuard
		hostedSearch     *search.Backend
	)
	if c.Hosted != nil {
		if !HostedNativeLaneAvailable() {
			return nil, fabric.NewError(fabric.CodeUnsupported, "Installed hosted product requires the daemon native worker lane")
		}
		hostedDeferred = newHostedDeferred()
		if hostedOwnerGuard, err = daemon.NewHostedOwnerGuard(hostedDeferred.ownerValidator()); err != nil {
			return nil, err
		}
	}
	result.Node, err = ComposeRetained(ctx, installation.Store, func(ctx context.Context, store *registry.Store, index *search.Backend) (Ports, error) {
		if c.Hosted != nil {
			hostedSearch = index
		}
		nativeCfg := NativeRuntimeConfig{
			Owner: owner, Protector: installation.Keys, Credentials: credentials, CleanupCaller: installation.Operator,
			Binary: c.Binary, AuthorityDirectory: c.Directory, SocketPath: settings.SocketPath,
			ControllerBootID: hex.EncodeToString(boot), MaxWorkers: settings.MaxWorkers,
			MaxStartupMetadataBytes: settings.MaxStartupMetadataBytes, StartupTimeout: time.Duration(settings.StartupTimeoutMillis) * time.Millisecond,
		}
		if c.Hosted != nil {
			nativeCfg.OwnerValidator = hostedOwnerGuard.Validate
			nativeCfg.HostedValidator = hostedDeferred.hostedValidator()
			nativeCfg.HostedFacts = hostedDeferred.hostedFacts()
		}
		result.Runtime, err = NewLocalRuntime(ctx, store, LocalRuntimeConfig{Operator: installation, Native: nativeCfg})
		if err != nil {
			return Ports{}, err
		}
		if c.Hosted != nil {
			// The native runtime now exists: the owner guard's `next` is the
			// local node's owner validator (the installed node's local
			// owner/managed gate).
			hostedDeferred.setNext(result.Runtime.Peers.ValidateOwner)
		}
		ports := result.Runtime.Ports()
		resources = &installedRuntimes{native: result.Runtime}
		ports.Close = resources
		if serviceConfig != nil {
			selected := *serviceConfig
			operatorHook := selected.OnDescriptorsCommitted
			selected.OnDescriptorsCommitted = func() {
				notice()
				if operatorHook != nil {
					operatorHook()
				}
			}
			result.Services, err = NewServiceRuntime(ctx, installation, result.Runtime.Boundary, selected)
			if err != nil {
				return Ports{}, err
			}
			providers := result.Services.Bindings()
			providers[BindingProtocol{Protocol: "local.native", Version: "1"}] = result.Runtime.BindingProvider
			router, e := NewRouter(providers)
			if e != nil {
				return Ports{}, e
			}
			ports.Bindings = router
			ports.ReplayVerifier = result.Services.Invocations
			resources.services = result.Services
		}
		var originalServices *fabricservices.Invocations
		if result.Services != nil {
			originalServices = result.Services.Invocations
		}
		result.Extensions, err = NewExtensionRuntime(ctx, installation, result.Runtime.Boundary, ExtensionRuntimeConfig{Lifetime: ctx, Credentials: c.ExtensionCredentials, Bindings: ports.Bindings, VerifyOriginalPhase: NewOriginalExtensionPhaseVerifier(result.Runtime.Adapter, originalServices)})
		if err != nil {
			return Ports{}, fmt.Errorf("opening configured extension execution: %w", err)
		}
		if result.Extensions != nil {
			resources.extensions = result.Extensions
			ports.Interceptors = result.Extensions
			ports.ResumeDispatchVerifier = result.Extensions.authority
		}
		result.Events, err = OpenInstalledEvents(ctx, installation, c.EventProviders)
		if err != nil {
			var held *EventRuntimeOpenError
			if errors.As(err, &held) {
				resources.events = held.retained
			}
			return Ports{}, fmt.Errorf("opening configured event delivery: %w", err)
		}
		if result.Events != nil {
			resources.events = result.Events
			ports.Events = result.Events
		}
		ports.Tracing = c.Tracing
		return ports, nil
	})
	if err != nil {
		errors.As(err, &result.incomplete)
		return nil, err
	}
	result.Publisher, err = NewIndexPublisher(ctx, result.Node, notices, c.ObserveIndexPublication)
	if err != nil {
		return nil, err
	}
	resources.mu.Lock()
	resources.publisher = result.Publisher
	resources.mu.Unlock()
	// The installed hosted product over the loaded installation and composed
	// native runtime. A composition failure with an explicit Hosted config is a
	// startup failure (the retained-cleanup path above handles the join).
	if c.Hosted != nil {
		result.Hosted, err = newInstalledHosted(ctx, result, *c.Hosted, hostedDeferred, hostedOwnerGuard, hostedSearch)
		if err != nil {
			return nil, err
		}
	}
	result.server, err = fabricmcp.New(fabricmcp.Config{Executor: result.Node.Service})
	if err != nil {
		return nil, err
	}
	handlers := result.AgentAdministration(result.Publisher.Notify)
	for operation, handler := range result.ServiceAdministration() {
		if handlers[operation] != nil {
			return nil, fabric.NewError(fabric.CodeInvalidInput, "Duplicate local administration operation")
		}
		handlers[operation] = handler
	}
	if result.Extensions != nil {
		paging := DefaultExtensionPagerOptions()
		if c.ExtensionPaging != nil {
			paging = *c.ExtensionPaging
		}
		result.extensionAdmin, err = NewInstalledExtensionAdministration(result, paging)
		if err != nil {
			return nil, err
		}
		resources.mu.Lock()
		resources.extensionAdmin = result.extensionAdmin
		resources.mu.Unlock()
		for operation, handler := range result.extensionAdmin.Handlers() {
			if handlers[operation] != nil {
				return nil, fabric.NewError(fabric.CodeInvalidInput, "Duplicate local administration operation")
			}
			handlers[operation] = handler
		}
	}
	if result.Hosted != nil {
		for operation, handler := range result.Hosted.Administration() {
			if handlers[operation] != nil {
				return nil, fabric.NewError(fabric.CodeInvalidInput, "Duplicate local administration operation")
			}
			handlers[operation] = handler
		}
	}
	result.admin, err = fabricadmin.New(fabricadmin.Config{Handlers: handlers})
	if err != nil {
		return nil, err
	}
	hostCfg := fabrichost.Config{Protocols: map[string]fabrichost.VerifiedSessionServer{fabrichost.AdminProtocol: result.admin}, SocketPath: settings.SocketPath, Authority: result.Runtime.Authenticator, Server: result.server, ResolveManaged: result.Runtime.ManagedResolver()}
	if result.Hosted != nil {
		// The node's private listener authenticates hosted peers: the resolver
		// is fail-closed until the runtime bindings are wired post-daemon.
		hostCfg.ResolveHosted = result.Hosted.ResolveHosted()
	}
	result.Host, err = fabrichost.Start(ctx, hostCfg)
	if err != nil {
		return nil, err
	}
	keep = true
	return result, nil
}

// CloseContext retains the installation on an incomplete join and is retryable.
// Ending a transport does not mean a native/business turn completed.
func (n *InstalledNode) CloseContext(ctx context.Context) error {
	if n == nil {
		return nil
	}
	if ctx == nil {
		return fabric.NewError(fabric.CodeInvalidInput, "Missing local node shutdown context")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.Host != nil {
		if err := n.Host.CloseContext(ctx); err != nil {
			return err
		}
	} else {
		if n.admin != nil {
			if err := n.admin.CloseContext(ctx); err != nil {
				return err
			}
		}
		if n.server != nil {
			if err := n.server.CloseContext(ctx); err != nil {
				return err
			}
		}
	}
	if n.incomplete != nil {
		if err := n.incomplete.CloseContext(ctx); err != nil {
			return err
		}
		n.incomplete = nil
	}
	if n.Node != nil {
		if err := n.Node.CloseContext(ctx); err != nil {
			return err
		}
	} else {
		if n.Publisher != nil {
			if err := n.Publisher.CloseContext(ctx); err != nil {
				return err
			}
		}
		if n.extensionAdmin != nil {
			if err := n.extensionAdmin.CloseContext(ctx); err != nil {
				return err
			}
		}
		if n.Extensions != nil {
			if err := n.Extensions.Close(ctx); err != nil {
				return err
			}
		}
		if n.Services != nil {
			if err := n.Services.CloseContext(ctx); err != nil {
				return err
			}
		}
		if n.Events != nil {
			if err := n.Events.CloseContext(ctx); err != nil {
				return err
			}
		}
		if n.Runtime != nil {
			if err := n.Runtime.CloseContext(ctx); err != nil {
				return err
			}
		}
	}
	return n.Installation.CloseContext(ctx)
}
func (n *InstalledNode) Close() error { return n.CloseContext(context.Background()) }

// DefaultInstalledServiceConfig selects finite SDK connection infrastructure
// limits, not a provider/account. Credentials must be explicitly supplied and
// remain private; nil is rejected by service setup/open, never scraped from env.
func DefaultInstalledServiceConfig(credentials fabricservices.CredentialProvider) ServiceRuntimeConfig {
	return ServiceRuntimeConfig{Credentials: credentials, InvocationConfig: fabricservices.DefaultInvocationConfig(), MaxConnections: 128, SetupTimeout: 10 * time.Second, SetupConcurrency: 4}
}

// installedRuntimes owns the dependency order without reacquiring InstalledNode
// locks. An incomplete join never releases the installation key or Store.
type installedRuntimes struct {
	native         *LocalRuntime
	publisher      *IndexPublisher
	services       *ServiceRuntime
	events         *EventRuntime
	extensions     *ExtensionRuntime
	extensionAdmin *InstalledExtensionAdministration
	mu             sync.Mutex
}

func (r *installedRuntimes) CloseContext(ctx context.Context) error {
	if ctx == nil {
		return fabric.NewError(fabric.CodeInvalidInput, "Missing installed runtime shutdown context")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.publisher != nil {
		if e := r.publisher.CloseContext(ctx); e != nil {
			return e
		}
	}
	if r.extensionAdmin != nil {
		if e := r.extensionAdmin.CloseContext(ctx); e != nil {
			return e
		}
	}
	if r.extensions != nil {
		if e := r.extensions.Close(ctx); e != nil {
			return e
		}
	}
	if r.events != nil {
		if e := r.events.CloseContext(ctx); e != nil {
			return e
		}
	}
	if r.services != nil {
		if e := r.services.CloseContext(ctx); e != nil {
			return e
		}
	}
	if r.native != nil {
		return r.native.CloseContext(ctx)
	}
	return nil
}
func (r *installedRuntimes) Close() error { return r.CloseContext(context.Background()) }
