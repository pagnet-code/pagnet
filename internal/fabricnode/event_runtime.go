package fabricnode

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/cloudevents/sdk-go/v2/event"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/events/durable"
	"github.com/pagnet-code/pagnet/fabric/events/httpbinding"
)

// EventRuntime owns observation delivery only. It cannot authorize, invoke or
// modify an endpoint. Its private settings are selected explicitly by the owner.
type EventRuntime struct {
	Store     *durable.Store
	Ingress   *durable.Ingress
	workers   *durable.Workers
	observers []*httpbinding.Observer
	statuses  []EventObserverStatus
	closeMu   sync.Mutex
	closed    bool
}

// EventObserverStatus is private operator diagnostics, never discovery metadata.
// Configured means only a selected credential provider exists, not sink health.
type EventObserverStatus struct {
	ID                        string
	MissingCredentialProvider bool
	ErrorCode                 fabric.ErrorCode
}

func (r *EventRuntime) ObserverStatus() []EventObserverStatus {
	if r == nil {
		return nil
	}
	return append([]EventObserverStatus(nil), r.statuses...)
}

type unavailableEventCredentials struct{}

func (unavailableEventCredentials) Authorization(context.Context, string) (string, error) {
	return "", fabric.NewError(fabric.CodeUnsupported, "Selected private event credential provider is not configured")
}

// ObserverSettings contains a provider selector, never a credential value.
// This is private retained infrastructure configuration, not a descriptor.
type ObserverSettings struct {
	ID                 string   `json:"id"`
	Types              []string `json:"types"`
	Endpoint           string   `json:"endpoint"`
	CredentialSelector string   `json:"credentialSelector"`
	AllowPlainHTTP     bool     `json:"allowPlainHTTP"`
}

type EventSettings struct {
	Observers       []ObserverSettings    `json:"observers"`
	Queue           durable.Config        `json:"queue"`
	Ingress         durable.IngressConfig `json:"ingress"`
	DeliveryTimeout time.Duration         `json:"deliveryTimeout"`
	PollInterval    time.Duration         `json:"pollInterval"`
}

func DefaultEventSettings(observers []ObserverSettings) EventSettings {
	subs := make([]durable.Subscription, len(observers))
	owned := make([]ObserverSettings, len(observers))
	for n, o := range observers {
		owned[n] = o
		owned[n].Types = append([]string(nil), o.Types...)
		subs[n] = durable.Subscription{ID: o.ID, Types: append([]string(nil), o.Types...)}
	}
	return EventSettings{Observers: owned, Queue: durable.DefaultConfig(subs), Ingress: durable.IngressConfig{QueueDepth: 128, MaxBytes: 8 << 20, MaxEventBytes: 1 << 20, WriteTimeout: 5 * time.Second}, DeliveryTimeout: 5 * time.Second, PollInterval: time.Second}
}

// openEventRuntime consumes an already verified private retained configuration.
// It never bootstraps the event store, discovers a sink or installs software.
func openEventRuntime(ctx context.Context, directory string, scope durable.Scope, settings EventSettings, keys durable.DataProtector, providers map[string]httpbinding.CredentialProvider) (_ *EventRuntime, err error) {
	settings, err = validateEventSettings(ctx, settings)
	if err != nil {
		return nil, err
	}
	r := &EventRuntime{}
	defer func() {
		if err != nil {
			closeCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if closeErr := r.CloseContext(closeCtx); closeErr != nil {
				err = &EventRuntimeOpenError{cause: errors.Join(err, closeErr), retained: r}
			}
		}
	}()
	known := make(map[string]durable.Subscription, len(settings.Queue.Subscriptions))
	for _, s := range settings.Queue.Subscriptions {
		if _, ok := known[s.ID]; ok {
			return nil, localDenied()
		}
		known[s.ID] = s
	}
	handlers := make(map[string]durable.Handler, len(settings.Observers))
	for _, o := range settings.Observers {
		s, ok := known[o.ID]
		if !ok || len(o.Types) != len(s.Types) || o.CredentialSelector == "" {
			return nil, localDenied()
		}
		seen := make(map[string]bool, len(s.Types))
		for _, kind := range s.Types {
			seen[kind] = true
		}
		for _, kind := range o.Types {
			if !seen[kind] {
				return nil, localDenied()
			}
			delete(seen, kind)
		}
		if _, duplicate := handlers[o.ID]; duplicate {
			return nil, localDenied()
		}
		var provider httpbinding.CredentialProvider
		missingProvider := false
		if o.CredentialSelector != "credentials.none" {
			provider = providers[o.CredentialSelector]
			if provider == nil {
				// Observation availability never grants authority and must not block
				// unrelated local calls. Retain the original queue; absent credentials
				// cannot become unauthenticated disclosure or an ACK.
				provider = unavailableEventCredentials{}
				missingProvider = true
			}
		}
		observer, e := httpbinding.New(httpbinding.Config{Endpoint: o.Endpoint, Binding: o.ID, AllowPlainHTTP: o.AllowPlainHTTP, Concurrency: 1, MaxEventBytes: settings.Queue.MaxEventBytes, Timeout: settings.DeliveryTimeout, Credentials: provider})
		if e != nil {
			return nil, e
		}
		r.observers = append(r.observers, observer)
		status := EventObserverStatus{ID: o.ID, MissingCredentialProvider: missingProvider}
		if missingProvider {
			status.ErrorCode = fabric.CodeUnsupported
			handlers[o.ID] = func(ctx context.Context, _ event.Event) error {
				_, e := (unavailableEventCredentials{}).Authorization(ctx, "")
				return e
			}
		} else {
			handlers[o.ID] = observer.Deliver
		}
		r.statuses = append(r.statuses, status)
	}
	r.Store, err = durable.Open(ctx, directory, scope, settings.Queue, keys)
	if err != nil {
		return nil, err
	}
	r.Ingress, err = durable.NewIngress(ctx, r.Store, settings.Ingress)
	if err != nil {
		return nil, err
	}
	r.workers, err = durable.StartWorkers(ctx, r.Store, durable.WorkerConfig{Handlers: handlers, Timeout: settings.DeliveryTimeout, PollInterval: settings.PollInterval})
	if err != nil {
		return nil, err
	}
	return r, nil
}

type EventRuntimeOpenError struct {
	cause    error
	retained *EventRuntime
}

func (e *EventRuntimeOpenError) Error() string {
	return "Event delivery could not start; original resources remain held until cleanup completes"
}
func (e *EventRuntimeOpenError) Unwrap() error { return e.cause }
func (e *EventRuntimeOpenError) CloseContext(ctx context.Context) error {
	return e.retained.CloseContext(ctx)
}

func (r *EventRuntime) TryPublish(ctx context.Context, e event.Event) error {
	if r.Ingress == nil {
		return fabric.NewError(fabric.CodeTargetUnavailable, "Event observation unavailable")
	}
	return r.Ingress.TryPublish(ctx, e)
}

func (r *EventRuntime) CloseContext(ctx context.Context) error {
	if ctx == nil {
		return localDenied()
	}
	r.closeMu.Lock()
	defer r.closeMu.Unlock()
	if r.closed {
		return nil
	}
	// No key/store release follows an incomplete callback join. Retrying Close
	// joins the same actual resources, never reopens/replaces their identities.
	if r.Ingress != nil {
		if err := r.Ingress.Close(ctx); err != nil {
			return err
		}
	}
	if r.workers != nil {
		if err := r.workers.Close(ctx); err != nil {
			return err
		}
	}
	for _, o := range r.observers {
		if err := o.CloseContext(ctx); err != nil {
			return err
		}
	}
	if r.Store != nil {
		if err := r.Store.Close(); err != nil {
			return err
		}
	}
	r.closed = true
	return nil
}
