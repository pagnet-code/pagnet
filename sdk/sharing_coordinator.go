package sdk

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/pagnet-code/pagnet/transport"
)

const sharingPairWakeType = "endpoint.sharing_pair_wake"
const sharingPairWakeCap = 256

// sharingCoordinator is client-level: one worker serializes handlers even when
// a replacement connection becomes live while an old callback is cancelling.
// All fields except notify are protected by Client.sharingMu.
type sharingCoordinator struct {
	notify                chan struct{}
	pending               map[string]sharingPairWake
	pendingOrder          []string
	blocked               map[string]bool
	full                  bool
	handler               func(context.Context, SharingMessage) error
	ready                 func()
	pairsEnabled          bool
	projectsEnabled       bool
	projectHandler        func(context.Context, SharingProjectMessage) error
	projectReady          func(string)
	ownerTextInstallation string
	ownerTextReady        func(string)
	ownerTextHandler      func(context.Context, OwnerTextProjectMessage) error
	ctx                   context.Context
	cancel                context.CancelFunc
	connection            int64
	revision              uint64
	fullRevision          uint64
	grantRevision         map[string]uint64
}

type sharingPairWake struct {
	GrantID    string `json:"grantId"`
	Generation int64  `json:"generation"`
	Kind       string `json:"kind"`
}

// OnSharingMessage opts into event-driven pair enrollment and inbox replay,
// replacing the single pair handler. Return nil only after successful handling;
// failure/panic leaves the message pending until a new wake or reconnect.
// Handlers must honor ctx cancellation. A callback that ignores cancellation
// can delay coordinator shutdown and outlive Close's bounded drain timeout.
func (c *Client) OnSharingMessage(handler func(context.Context, SharingMessage) error) {
	c.sharingMu.Lock()
	defer c.sharingMu.Unlock()
	if c.closed.Load() {
		return
	}
	coordinator := c.ensureSharingCoordinatorLocked()
	coordinator.pairsEnabled = true
	coordinator.handler = handler
	c.kickSharingCoordinatorLocked(coordinator)
}

// EnableSharingPairs opts into pair enrollment for send-only clients. It also
// explicitly requests reconciliation and retries previously failed handlers.
// No idle polling occurs; later work comes from wakes or reconnection.
func (c *Client) EnableSharingPairs() {
	c.sharingMu.Lock()
	defer c.sharingMu.Unlock()
	if c.closed.Load() {
		return
	}
	s := c.ensureSharingCoordinatorLocked()
	s.pairsEnabled = true
	c.kickSharingCoordinatorLocked(s)
}

// OnSharingPairReady registers a nonblocking local wake after pair authority is
// ready, including reconnect reconciliation. It performs no idle polling.
func (c *Client) OnSharingPairReady(handler func()) {
	c.sharingMu.Lock()
	defer c.sharingMu.Unlock()
	if c.closed.Load() {
		return
	}
	s := c.ensureSharingCoordinatorLocked()
	s.pairsEnabled = true
	s.ready = handler
	c.kickSharingCoordinatorLocked(s)
}
func (c *Client) notifySharingPairReady(s *sharingCoordinator, job sharingReconcileJob) {
	c.sharingMu.Lock()
	ready := s.ready
	current := s.ctx == job.ctx && s.connection == job.connection
	c.sharingMu.Unlock()
	if current && ready != nil && job.ctx.Err() == nil {
		func() { defer func() { _ = recover() }(); ready() }()
	}
}

func (c *Client) ensureSharingCoordinatorLocked() *sharingCoordinator {
	if c.sharingCoordinator == nil {
		c.sharingCoordinator = &sharingCoordinator{notify: make(chan struct{}, 1), pending: map[string]sharingPairWake{}, blocked: map[string]bool{}}
		c.wg.Add(1)
		go c.runSharingCoordinator(c.sharingCoordinator)
	}
	return c.sharingCoordinator
}
func signalSharingCoordinator(s *sharingCoordinator) {
	select {
	case s.notify <- struct{}{}:
	default:
	}
}
func (c *Client) kickSharingCoordinatorLocked(s *sharingCoordinator) {
	if c.connected.Load() && (s.ctx == nil || s.connection != c.connGeneration.Load()) {
		c.startSharingSessionLocked(s)
	}
	s.full = true
	s.revision++
	s.fullRevision = s.revision
	s.blocked = map[string]bool{}
	signalSharingCoordinator(s)
}
func (c *Client) startSharingSessionLocked(s *sharingCoordinator) {
	if s.cancel != nil {
		s.cancel()
	}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.connection = c.connGeneration.Load()
	s.pending = map[string]sharingPairWake{}
	s.pendingOrder = nil
	s.blocked = map[string]bool{}
	s.grantRevision = map[string]uint64{}
	s.revision++
	s.fullRevision = s.revision
	s.full = true
}
func (c *Client) sharingPairLive() {
	c.sharingMu.Lock()
	defer c.sharingMu.Unlock()
	if s := c.sharingCoordinator; s != nil && !c.closed.Load() {
		c.startSharingSessionLocked(s)
		signalSharingCoordinator(s)
	}
}
func (c *Client) sharingPairDisconnected(connection int64) {
	c.sharingMu.Lock()
	defer c.sharingMu.Unlock()
	if s := c.sharingCoordinator; s != nil && s.connection == connection {
		if s.cancel != nil {
			s.cancel()
		}
		s.ctx = nil
		s.pending = map[string]sharingPairWake{}
		s.pendingOrder = nil
		s.full = true
		signalSharingCoordinator(s)
	}
}
func (c *Client) stopSharingCoordinator() {
	// This lock also fences wg.Add in opt-in registration against Close's Wait.
	c.sharingMu.Lock()
	defer c.sharingMu.Unlock()
	if s := c.sharingCoordinator; s != nil && s.cancel != nil {
		s.cancel()
	}
}

func (c *Client) handleSharingPairWake(pc *conn, env transport.Envelope) {
	c.connMu.Lock()
	current := c.cur == pc
	c.connMu.Unlock()
	if !current {
		return
	}
	var wake sharingPairWake
	decoder := json.NewDecoder(bytes.NewReader(env.Payload))
	decoder.DisallowUnknownFields()
	err := decoder.Decode(&wake)
	var extra any
	if err != nil || decoder.Decode(&extra) != io.EOF || !validPairPathID(wake.GrantID) || wake.Generation < 1 || (wake.Kind != "state" && wake.Kind != "message") {
		// A malformed hint might be the only notification for durable work.
		// Reconnect catch-up must recover it rather than silently dropping it.
		c.sharingPairDisconnected(c.connGeneration.Load())
		if pc != nil {
			_ = pc.ws.Close()
		}
		return
	}
	c.queueSharingPairWake(wake)
}
func (c *Client) queueSharingPairWake(wake sharingPairWake) {
	c.queueSharingWake(wake, false)
}
func (c *Client) queueSharingWake(wake sharingPairWake, project bool) {
	c.queueSharingWakeDomain(wake, project, false)
}
func (c *Client) queueSharingWakeDomain(wake sharingPairWake, project, ownerProject bool) {
	c.sharingMu.Lock()
	s := c.sharingCoordinator
	if s == nil || s.ctx == nil || c.closed.Load() || !c.connected.Load() || s.connection != c.connGeneration.Load() {
		c.sharingMu.Unlock()
		return
	}
	if (ownerProject && s.ownerTextInstallation == "") || (project && !s.projectsEnabled) || (!project && !ownerProject && !s.pairsEnabled) {
		c.sharingMu.Unlock()
		return
	}
	key := wake.GrantID
	if project {
		key = sharingProjectJobKey(key)
	} else if ownerProject {
		key = ownerTextProjectJobKey(key)
	}
	if _, exists := s.pending[key]; !exists && len(s.pending) >= sharingPairWakeCap {
		// An overflow cannot silently lose work. Cancel this session and close its
		// socket; onLive's full rescan reconstructs state and pending inboxes.
		if s.cancel != nil {
			s.cancel()
		}
		s.ctx = nil
		s.pending = map[string]sharingPairWake{}
		s.pendingOrder = nil
		s.full = true
		c.sharingMu.Unlock()
		c.connMu.Lock()
		pc := c.cur
		c.connMu.Unlock()
		if pc != nil {
			_ = pc.ws.Close()
		}
		return
	}
	old, exists := s.pending[key]
	merged := wake
	if exists && old.Generation > wake.Generation {
		merged = old
	}
	if old.Kind == "state" || wake.Kind == "state" {
		merged.Kind = "state"
	}
	enqueueSharingPendingLocked(s, key, merged)
	s.revision++
	s.grantRevision[key] = s.revision
	delete(s.blocked, key)
	signalSharingCoordinator(s)
	c.sharingMu.Unlock()
}

type sharingReconcileJob struct {
	grant        string
	project      bool
	ownerProject bool
	key          string
	kind         string
	full         bool
	ctx          context.Context
	connection   int64
}

func (c *Client) nextSharingJob(s *sharingCoordinator) (sharingReconcileJob, bool) {
	c.sharingMu.Lock()
	defer c.sharingMu.Unlock()
	if s.ctx == nil || !c.connected.Load() || s.connection != c.connGeneration.Load() {
		return sharingReconcileJob{}, false
	}
	job := sharingReconcileJob{ctx: s.ctx, connection: s.connection}
	if s.full {
		s.full = false
		job.full = true
		return job, true
	}
	for len(s.pendingOrder) > 0 {
		key := s.pendingOrder[0]
		s.pendingOrder = s.pendingOrder[1:]
		wake, exists := s.pending[key]
		if !exists {
			continue
		}
		delete(s.pending, key)
		job.grant, job.key, job.kind = wake.GrantID, key, wake.Kind
		job.project = key == sharingProjectJobKey(wake.GrantID)
		job.ownerProject = key == ownerTextProjectJobKey(wake.GrantID)
		return job, true
	}
	return job, false
}
func (c *Client) runSharingCoordinator(s *sharingCoordinator) {
	defer c.wg.Done()
	attempt := 0
	for {
		select {
		case <-c.closeCh:
			return
		case <-c.terminalCh:
			return
		default:
		}
		job, ok := c.nextSharingJob(s)
		if !ok {
			select {
			case <-c.closeCh:
				return
			case <-c.terminalCh:
				return
			case <-s.notify:
			}
			continue
		}
		err := c.runSharingReconcile(s, job)
		if err == nil || !retrySharingReconcile(err) || job.ctx.Err() != nil {
			attempt = 0
			continue
		}
		delay := 100 * time.Millisecond
		for n := 0; n < attempt && delay < 5*time.Second; n++ {
			delay *= 2
		}
		if delay > 5*time.Second {
			delay = 5 * time.Second
		}
		if attempt < 6 {
			attempt++
		}
		timer := time.NewTimer(delay)
		select {
		case <-c.closeCh:
			timer.Stop()
			return
		case <-c.terminalCh:
			timer.Stop()
			return
		case <-job.ctx.Done():
			timer.Stop()
			continue
		case <-timer.C:
		}
		c.sharingMu.Lock()
		if s.ctx == job.ctx && s.connection == job.connection {
			if job.full {
				s.full = true
			} else if !s.blocked[job.key] {
				if _, queued := s.pending[job.key]; !queued {
					enqueueSharingPendingLocked(s, job.key, sharingPairWake{GrantID: job.grant, Kind: job.kind})
				}
			}
			signalSharingCoordinator(s)
		}
		c.sharingMu.Unlock()
	}
}
func retrySharingReconcile(err error) bool {
	if errors.Is(err, context.Canceled) {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var re *restError
	if errors.As(err, &re) {
		return re.status == http.StatusRequestTimeout || re.status == http.StatusTooManyRequests || re.status >= 500
	}
	var ne net.Error
	return errors.As(err, &ne) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) || errors.Is(err, ErrNotConnected)
}
func (c *Client) runSharingReconcile(s *sharingCoordinator, job sharingReconcileJob) error {
	if !job.full {
		if job.ownerProject {
			c.sharingMu.Lock()
			installation := s.ownerTextInstallation
			c.sharingMu.Unlock()
			return c.reconcileOwnerTextProject(s, job, job.grant, installation)
		}
		if job.project {
			return c.reconcileSharingProject(s, job, job.grant)
		}
		return c.reconcileSharingGrant(s, job, job.grant)
	}
	c.sharingMu.Lock()
	pairs, projects, installation := s.pairsEnabled, s.projectsEnabled, s.ownerTextInstallation
	c.sharingMu.Unlock()
	if installation != "" {
		if err := c.reconcileOwnerTextProjects(s, job, installation); err != nil {
			return err
		}
	}
	if projects {
		if err := c.reconcileSharingProjects(s, job); err != nil {
			return err
		}
	}
	if !pairs {
		return nil
	}
	cursor := ""
	for {
		if err := job.ctx.Err(); err != nil {
			return err
		}
		page, next, err := c.ListSharingPairs(job.ctx, cursor)
		if err != nil {
			return err
		}
		for _, status := range page {
			if err := c.reconcileSharingGrant(s, job, status.GrantID); err != nil && retrySharingReconcile(err) {
				return err
			}
		}
		if next == "" {
			return nil
		}
		if next <= cursor {
			return errors.New("sdk: invalid sharing reconciliation cursor")
		}
		cursor = next
	}
}
func (c *Client) reconcileSharingGrant(s *sharingCoordinator, job sharingReconcileJob, grant string) error {
	if err := job.ctx.Err(); err != nil {
		return err
	}
	c.sharingMu.Lock()
	blocked := s.blocked[grant]
	handler := s.handler
	current := s.ctx == job.ctx && s.connection == job.connection
	c.sharingMu.Unlock()
	if blocked || !current {
		return nil
	}
	if !job.full && job.kind == "message" {
		var err error
		if handler != nil {
			err = c.drainSharingGrant(s, job, grant)
		} else {
			_, err = c.sharingMessageSession(job.ctx, grant)
		}
		if !errors.Is(err, errSharingConnectionProofRequired) || job.ctx.Err() != nil {
			if err == nil {
				c.notifySharingPairReady(s, job)
			}
			return err
		}
	}
	result, err := c.EnrollSharingPair(job.ctx, grant)
	if err != nil {
		return err
	}
	if result.Pending || job.ctx.Err() != nil {
		return job.ctx.Err()
	}
	c.notifySharingPairReady(s, job)
	c.sharingMu.Lock()
	handler = s.handler
	current = s.ctx == job.ctx && s.connection == job.connection
	c.sharingMu.Unlock()
	if handler == nil || !current {
		return nil
	}
	return c.drainSharingGrant(s, job, grant)
}
func (c *Client) drainSharingGrant(s *sharingCoordinator, job sharingReconcileJob, grant string) error {
	failed := false
	var fullRevision, grantRevision uint64
	err := c.ReceiveSharingMessages(job.ctx, grant, func(ctx context.Context, m SharingMessage) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		c.sharingMu.Lock()
		handler := s.handler
		current := s.ctx == job.ctx && s.connection == job.connection
		fullRevision, grantRevision = s.fullRevision, s.grantRevision[grant]
		c.sharingMu.Unlock()
		if !current || handler == nil {
			return errors.New("sdk: sharing handler or connection changed")
		}
		handlerErr := invokeSharingHandler(ctx, handler, m)
		if handlerErr != nil {
			failed = true
		}
		return handlerErr
	})
	if failed {
		c.sharingMu.Lock()
		// Suppress this failed attempt only. New handler/manual/wake triggers
		// received while the callback ran must retain their queued reconciliation.
		if s.ctx == job.ctx && s.fullRevision == fullRevision && s.grantRevision[grant] == grantRevision {
			s.blocked[grant] = true
			delete(s.pending, grant)
		}
		c.sharingMu.Unlock()
		return nil
	}
	return err
}

// enqueueSharingPendingLocked keeps coalesced work FIFO across protocol domains.
// Drop stale ordering entries before requeueing previously blocked work.
func enqueueSharingPendingLocked(s *sharingCoordinator, key string, wake sharingPairWake) {
	if _, exists := s.pending[key]; !exists {
		order := s.pendingOrder[:0]
		for _, queued := range s.pendingOrder {
			if _, live := s.pending[queued]; live && queued != key {
				order = append(order, queued)
			}
		}
		s.pendingOrder = append(order, key)
	}
	s.pending[key] = wake
}
