package sender

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/sdk"
)

// ControllerConfig supplies the current owner/session dispatch gate. A nil
// Enabled fences all dispatch. OnError reports unresolved operations and must
// return promptly; errors never cause a new ASK or new preparation attempt.
// OnReady publishes the live controller and returns cleanup that unpublishes and
// joins its callers. Shutdown wakes waiters before invoking that cleanup.
type ControllerConfig struct {
	Enabled func(string) bool
	OnError func(error)
	OnReady func(*Controller) func()
}

// Controller multiplexes saved ASKs on one authenticated, authorized connection.
// The caller owns the connection and holds the Store's external profile lock
// until Run and all callers have joined. It installs the connection callbacks.
type Controller struct {
	store         *Store
	conn          Connection
	principal     string
	config        ControllerConfig
	wake          chan struct{}
	mu            sync.Mutex
	ready         map[string]bool
	changed       chan struct{}
	revision      uint64
	live          bool
	runContext    context.Context
	running       atomic.Bool
	retryDelay    time.Duration
	retryMaxDelay time.Duration
}

func NewController(store *Store, conn Connection, principal string, config ControllerConfig) *Controller {
	return &Controller{store: store, conn: conn, principal: principal, config: config, wake: make(chan struct{}, 1), retryDelay: time.Second, retryMaxDelay: 30 * time.Second, ready: make(map[string]bool), changed: make(chan struct{})}
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
	id, err := uuid.NewV7()
	if err != nil {
		return Operation{}, err
	}
	return c.ReserveWithID(ctx, project, recipient, id.String(), prompt)
}

func (c *Controller) authority(ctx context.Context, project string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !c.live || c.runContext.Err() != nil || c.config.Enabled == nil || !c.config.Enabled(project) {
		return ErrDisabled
	}
	select {
	case <-c.conn.Done():
		return ErrDisabled
	default:
		return nil
	}
}

func (c *Controller) notifyLocked() {
	c.revision++
	close(c.changed)
	c.changed = make(chan struct{})
}

func (c *Controller) notify() {
	c.mu.Lock()
	c.notifyLocked()
	c.mu.Unlock()
}

func (c *Controller) ReserveWithID(ctx context.Context, project, recipient, ask, prompt string) (Operation, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.authority(ctx, project); err != nil {
		return Operation{}, err
	}
	o, err := c.store.ReserveWithID(ctx, project, recipient, ask, prompt)
	if err == nil {
		c.notifyLocked()
		c.Wake()
	}
	return o, err
}

func (c *Controller) Get(ctx context.Context, project, ask string) (Operation, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.authority(ctx, project); err != nil {
		return Operation{}, err
	}
	return c.store.Get(ctx, project, ask)
}

func (c *Controller) Resume(ctx context.Context, project, ask string) (Operation, error) {
	o, err := c.Get(ctx, project, ask)
	if err == nil {
		c.Wake()
	}
	return o, err
}

// Wait snapshots the notification before reading, so a concurrent persisted
// transition cannot be lost between the read and waiting for its notification.
func (c *Controller) Wait(ctx context.Context, project, ask string) (Operation, error) {
	for {
		c.mu.Lock()
		changed := c.changed
		if err := c.authority(ctx, project); err != nil {
			c.mu.Unlock()
			return Operation{}, err
		}
		runDone := c.runContext.Done()
		o, err := c.store.Get(ctx, project, ask)
		c.mu.Unlock()
		if err != nil || (o.Phase == Admitted && o.Reply != nil) {
			return o, err
		}
		select {
		case <-ctx.Done():
			return Operation{}, ctx.Err()
		case <-runDone:
			return Operation{}, ErrDisabled
		case <-c.conn.Done():
			return Operation{}, ErrDisabled
		case <-changed:
		}
	}
}

// List returns a bounded page in stable ASK ID order within one project.
func (c *Controller) List(ctx context.Context, project, after string, limit int) ([]Operation, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if limit < 1 || limit > 100 || !validID(project, false) || (after != "" && !validID(after, true)) {
		return nil, ErrInvalid
	}
	if err := c.authority(ctx, project); err != nil {
		return nil, err
	}
	all, err := c.store.List(ctx)
	if err != nil {
		return nil, err
	}
	result := []Operation{}
	for _, operation := range all {
		if operation.ProjectID == project && operation.AskID > after {
			result = append(result, operation)
			if len(result) == limit {
				break
			}
		}
	}
	return result, nil
}

// Revision snapshots the event-driven change counter for this live controller.
func (c *Controller) Revision(ctx context.Context, project string) (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.authority(ctx, project); err != nil {
		return 0, err
	}
	return c.revision, nil
}

// WaitRevision returns on a persisted transition or runtime fencing. It never
// polls, and a revision belongs only to this controller's lifetime.
func (c *Controller) WaitRevision(ctx context.Context, project string, after uint64) (uint64, error) {
	for {
		c.mu.Lock()
		if err := c.authority(ctx, project); err != nil {
			c.mu.Unlock()
			return 0, err
		}
		revision, changed, done := c.revision, c.changed, c.runContext.Done()
		c.mu.Unlock()
		if revision != after {
			return revision, nil
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-done:
			return 0, ErrDisabled
		case <-c.conn.Done():
			return 0, ErrDisabled
		case <-changed:
		}
	}
}

// HandleMessage commits only authenticated correlated replies before SDK ACK.
func (c *Controller) HandleMessage(ctx context.Context, message sdk.SharingProjectMessage) error {
	if message.Header.Kind != "REPLY" {
		return nil
	}
	_, err := RecordReply(ctx, c.store, c.principal, message)
	if err == nil {
		c.notify()
		c.Wake()
	}
	return err
}

// Run recovers saved work at startup and on readiness or explicit wakes. The
// caller must prove the pinned SDK installation before invoking Run. Per-ASK
// failures retain their durable identity. Transient outstanding work retries
// with capped backoff; idle or ambiguous unspooled work has no timer.
func (c *Controller) Run(ctx context.Context) error {
	if !c.running.CompareAndSwap(false, true) {
		return errors.New("sender controller already running")
	}
	var cleanup func()
	defer func() {
		c.mu.Lock()
		c.live = false
		c.notifyLocked()
		c.mu.Unlock()
		if cleanup != nil {
			cleanup()
		}
		c.running.Store(false)
	}()
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
	c.mu.Lock()
	c.live, c.runContext = true, ctx
	c.mu.Unlock()
	if c.config.OnReady != nil {
		cleanup = c.config.OnReady(c)
	}
	c.conn.EnableSharingProjects()
	c.Wake()
	conn := controllerConnection{Connection: c.conn, controller: c, ctx: ctx}
	var timer *time.Timer
	var retry <-chan time.Time
	delay := c.retryDelay
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-c.conn.Done():
			return errors.New("sender connection ended; saved ASKs remain recoverable")
		case <-c.wake:
			delay = c.retryDelay
		case <-retry:
		}
		if timer != nil {
			timer.Stop()
		}
		retry = nil
		retryNeeded := false
		operations, err := c.store.List(ctx, Reserved, Preparing, Prepared)
		if err != nil {
			return err
		}
		for _, o := range operations {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			receiptRetry := false
			// Historical admission evidence survives SDK ciphertext retirement and is
			// reconciled even before this connection receives project readiness.
			if o.Phase == Prepared {
				receipt, receiptErr := c.conn.SharingProjectMessageReceipt(ctx, o.ProjectID, o.AskID)
				if receiptErr == nil {
					_, err = c.store.MarkAdmitted(ctx, o.ProjectID, o.AskID, receipt)
					c.report(err)
					if err == nil {
						c.notify()
					}
					continue
				}
				if retryableSDKError(receiptErr) {
					c.report(receiptErr)
					receiptRetry = true
				}
			}
			c.mu.Lock()
			ready := c.ready[o.ProjectID]
			c.mu.Unlock()
			if !ready || !conn.enabled(o.ProjectID) {
				retryNeeded = retryNeeded || (receiptRetry && conn.enabled(o.ProjectID))
				continue
			}
			_, err := Reconcile(ctx, conn, c.store, o)
			c.notify()
			c.report(err)
			var transient retryableError
			var terminal terminalError
			retryNeeded = retryNeeded || (err != nil && conn.enabled(o.ProjectID) && !errors.As(err, &terminal) && (receiptRetry || errors.As(err, &transient)))
		}
		if retryNeeded {
			timer = time.NewTimer(delay)
			retry = timer.C
			delay = min(delay*2, c.retryMaxDelay)
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
