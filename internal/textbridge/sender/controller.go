package sender

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"

	"github.com/pagnet-code/pagnet/sdk"
)

// ControllerConfig supplies the current owner/session dispatch gate. A nil
// Enabled fences all dispatch. OnError reports unresolved operations and must
// return promptly; errors never cause a new ASK or new preparation attempt.
type ControllerConfig struct {
	Enabled func(string) bool
	OnError func(error)
}

// Controller multiplexes saved ASKs on one authenticated, authorized connection.
// The caller owns the connection and holds the Store's external profile lock
// until Run and all callers have joined. It installs the connection callbacks.
type Controller struct {
	store     *Store
	conn      Connection
	principal string
	config    ControllerConfig
	wake      chan struct{}
	mu        sync.Mutex
	ready     map[string]bool
	running   atomic.Bool
}

func NewController(store *Store, conn Connection, principal string, config ControllerConfig) *Controller {
	return &Controller{store: store, conn: conn, principal: principal, config: config, wake: make(chan struct{}, 1), ready: make(map[string]bool)}
}

// Wake requests a recovery scan. Signals coalesce and never schedule idle polls.
func (c *Controller) Wake() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

// Reserve persists a new stable ASK before waking the controller. A successful
// return exposes its ID even if preparation or admission later remains unresolved.
func (c *Controller) Reserve(ctx context.Context, project, recipient, prompt string) (Operation, error) {
	if ctx.Err() != nil {
		return Operation{}, ctx.Err()
	}
	if !c.running.Load() || c.config.Enabled == nil || !c.config.Enabled(project) {
		return Operation{}, ErrDisabled
	}
	o, err := c.store.Reserve(ctx, project, recipient, prompt)
	if err == nil {
		c.Wake()
	}
	return o, err
}

// HandleMessage commits only authenticated correlated replies before SDK ACK.
func (c *Controller) HandleMessage(ctx context.Context, message sdk.SharingProjectMessage) error {
	if message.Header.Kind != "REPLY" {
		return nil
	}
	_, err := RecordReply(ctx, c.store, c.principal, message)
	if err == nil {
		c.Wake()
	}
	return err
}

// Run recovers saved work at startup and on readiness or explicit wakes. The
// caller must prove the pinned SDK installation before invoking Run. Per-ASK
// failures remain durable and await a wake; one failure does not block other ASKs.
func (c *Controller) Run(ctx context.Context) error {
	if !c.running.CompareAndSwap(false, true) {
		return errors.New("sender controller already running")
	}
	defer c.running.Store(false)
	identity, err := c.conn.WhoAmI(ctx)
	if err != nil || identity == nil || identity.Kind != "service" || identity.PrincipalID != c.principal {
		return errors.New("sender authenticated identity does not match saved service")
	}
	c.conn.OnSharingProjectMessage(c.HandleMessage)
	c.conn.OnSharingProjectReady(func(project string) {
		c.mu.Lock()
		c.ready[project] = true
		c.mu.Unlock()
		c.Wake()
	})
	c.conn.EnableSharingProjects()
	c.Wake()
	conn := controllerConnection{Connection: c.conn, controller: c, ctx: ctx}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-c.conn.Done():
			return errors.New("sender connection ended; saved ASKs remain recoverable")
		case <-c.wake:
		}
		operations, err := c.store.List(ctx, Reserved, Preparing, Prepared)
		if err != nil {
			return err
		}
		for _, o := range operations {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			// Historical admission evidence survives SDK ciphertext retirement and is
			// reconciled even before this connection receives project readiness.
			if o.Phase == Prepared {
				if receipt, err := c.conn.SharingProjectMessageReceipt(ctx, o.ProjectID, o.AskID); err == nil {
					_, err = c.store.MarkAdmitted(ctx, o.ProjectID, o.AskID, receipt)
					c.report(err)
					continue
				}
			}
			c.mu.Lock()
			ready := c.ready[o.ProjectID]
			c.mu.Unlock()
			if !ready || !conn.enabled(o.ProjectID) {
				continue
			}
			_, err := Reconcile(ctx, conn, c.store, o)
			c.report(err)
		}
	}
}

func (c *Controller) report(err error) {
	if err != nil && c.config.OnError != nil {
		c.config.OnError(err)
	}
}

// Check authority immediately at the SDK boundary as well as before each pass:
// status/receipt lookups can block while the pinned endpoint or host is fenced.
type controllerConnection struct {
	Connection
	controller *Controller
	ctx        context.Context
}

func (c controllerConnection) enabled(project string) bool {
	select {
	case <-c.Connection.Done():
		return false
	default:
	}
	return c.ctx.Err() == nil && c.controller.config.Enabled != nil && c.controller.config.Enabled(project)
}
func (c controllerConnection) PrepareSharingProjectMessageWithID(project, to, kind, id string, input, predecessor []byte) (sdk.PreparedSharingProjectMessage, error) {
	if !c.enabled(project) {
		return sdk.PreparedSharingProjectMessage{}, ErrDisabled
	}
	return c.Connection.PrepareSharingProjectMessageWithID(project, to, kind, id, input, predecessor)
}
func (c controllerConnection) SendPreparedSharingProjectMessage(ctx context.Context, project, id string) (sdk.SharingProjectMessageReceipt, error) {
	if !c.enabled(project) {
		return sdk.SharingProjectMessageReceipt{}, ErrDisabled
	}
	return c.Connection.SendPreparedSharingProjectMessage(ctx, project, id)
}
