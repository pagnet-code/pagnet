package sdk

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/pagnet-code/pagnet/transport"
	"io"
)

// EnableOwnerTextProjects opts this bridge into enrollment for its exact
// installation. Connect and reconnect list projects once; no idle polling runs.
// Call again after replacing a claim, or use WakeOwnerTextProjects.
func (c *Client) EnableOwnerTextProjects(installationID string) error {
	if !projectUUID(installationID, false) {
		return errors.New("sdk: invalid owner text installation ID")
	}
	c.sharingMu.Lock()
	defer c.sharingMu.Unlock()
	if c.closed.Load() {
		return ErrClosed
	}
	s := c.ensureSharingCoordinatorLocked()
	s.ownerTextInstallation = installationID
	c.kickSharingCoordinatorLocked(s)
	return nil
}

// WakeOwnerTextProjects requests one reconciliation after an installation claim
// or project state hint. It is safe before enablement and after disconnect.
func (c *Client) WakeOwnerTextProjects() {
	c.sharingMu.Lock()
	defer c.sharingMu.Unlock()
	if s := c.sharingCoordinator; s != nil && s.ownerTextInstallation != "" && !c.closed.Load() {
		c.kickSharingCoordinatorLocked(s)
	}
}

// OnOwnerTextProjectReady sets a callback on the serialized sharing worker.
// EnableOwnerTextProjects must supply the bridge installation before enrollment.
// With a message handler, readiness runs after a successful drain or committed
// ACKs, so a durable outbox can send replies after releasing maxInFlight slots.
func (c *Client) OnOwnerTextProjectReady(handler func(projectID string)) {
	c.sharingMu.Lock()
	defer c.sharingMu.Unlock()
	if c.closed.Load() {
		return
	}
	s := c.ensureSharingCoordinatorLocked()
	s.ownerTextReady = handler
	c.kickSharingCoordinatorLocked(s)
}

const ownerTextProjectWakeType = "endpoint.owner_text_project_wake"

type ownerTextProjectWake struct {
	ProjectID string `json:"projectId"`
	Kind      string `json:"kind"`
}

func ownerTextProjectJobKey(project string) string { return "owner-project:" + project }

// OnOwnerTextProjectMessage registers the serialized owner-text message handler.
// EnableOwnerTextProjects must supply the exact bridge installation. Return nil
// only after durable processing; failure or panic waits for a fresh wake,
// reconnect or explicit WakeOwnerTextProjects before redelivery. Handlers must
// honor ctx. With maxInFlight=1, schedule REPLY sends after the ASK ACK rather
// than sending synchronously inside the callback; no reply is sent automatically.
func (c *Client) OnOwnerTextProjectMessage(handler func(context.Context, OwnerTextProjectMessage) error) {
	c.sharingMu.Lock()
	defer c.sharingMu.Unlock()
	if c.closed.Load() {
		return
	}
	s := c.ensureSharingCoordinatorLocked()
	s.ownerTextHandler = handler
	c.kickSharingCoordinatorLocked(s)
}
func (c *Client) handleOwnerTextProjectWake(pc *conn, env transport.Envelope) {
	if env.Type != ownerTextProjectWakeType {
		return
	}
	c.connMu.Lock()
	current := c.cur == pc
	c.connMu.Unlock()
	if !current {
		return
	}
	var wake ownerTextProjectWake
	decoder := json.NewDecoder(bytes.NewReader(env.Payload))
	decoder.DisallowUnknownFields()
	err := decoder.Decode(&wake)
	var extra any
	if err != nil || decoder.Decode(&extra) != io.EOF || !projectUUID(wake.ProjectID, false) || (wake.Kind != "state" && wake.Kind != "message") {
		c.sharingPairDisconnected(c.connGeneration.Load())
		if pc != nil {
			_ = pc.ws.Close()
		}
		return
	}
	c.queueOwnerTextProjectWake(wake)
}
func (c *Client) queueOwnerTextProjectWake(wake ownerTextProjectWake) {
	c.queueSharingWakeDomain(sharingPairWake{GrantID: wake.ProjectID, Kind: wake.Kind}, false, true)
}
func (c *Client) reconcileOwnerTextProjects(s *sharingCoordinator, job sharingReconcileJob, installation string) error {
	projects, err := c.ListOwnerTextProjects(job.ctx)
	if err != nil {
		return err
	}
	for _, status := range projects {
		if err := c.reconcileOwnerTextProject(s, job, status.ProjectID, installation); err != nil && retrySharingReconcile(err) {
			return err
		}
	}
	return job.ctx.Err()
}
func (c *Client) reconcileOwnerTextProject(s *sharingCoordinator, job sharingReconcileJob, project, installation string) error {
	if err := job.ctx.Err(); err != nil {
		return err
	}
	key := ownerTextProjectJobKey(project)
	c.sharingMu.Lock()
	blocked := s.blocked[key]
	current := s.ctx == job.ctx && s.connection == job.connection && s.ownerTextInstallation == installation && installation != "" && c.connGeneration.Load() == job.connection
	c.sharingMu.Unlock()
	if blocked || !current {
		return nil
	}
	result, err := c.EnrollOwnerTextProject(job.ctx, project, installation)
	if err != nil {
		return err
	}
	// Only the current caller's proof is required; an offline peer may leave
	// readiness false while durable inbox transport remains authorized.
	if !result.Status.EndpointProved || result.Status.State != "active" || job.ctx.Err() != nil {
		return job.ctx.Err()
	}
	c.sharingMu.Lock()
	handler := s.ownerTextHandler
	current = s.ctx == job.ctx && s.connection == job.connection && s.ownerTextInstallation == installation && c.connGeneration.Load() == job.connection
	c.sharingMu.Unlock()
	if !current || job.ctx.Err() != nil {
		return job.ctx.Err()
	}
	if handler == nil {
		c.notifyOwnerTextProjectReady(s, job, project, installation)
		return nil
	}
	failed := false
	var fullRevision, projectRevision uint64
	committedACKs := 0
	err = c.receiveOwnerTextProjectMessages(job.ctx, project, func(ctx context.Context, m OwnerTextProjectMessage) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		c.sharingMu.Lock()
		handler := s.ownerTextHandler
		current := s.ctx == job.ctx && s.connection == job.connection && s.ownerTextInstallation == installation && c.connGeneration.Load() == job.connection
		fullRevision, projectRevision = s.fullRevision, s.grantRevision[key]
		c.sharingMu.Unlock()
		if !current || handler == nil {
			return errors.New("sdk: owner text handler or connection changed")
		}
		handlerErr := invokeOwnerTextProjectHandler(ctx, handler, m)
		if handlerErr != nil {
			failed = true
		}
		return handlerErr
	}, func() { committedACKs++ })
	if err == nil || errors.Is(err, ErrOwnerTextProjectReceiveLimit) || committedACKs > 0 {
		c.notifyOwnerTextProjectReady(s, job, project, installation)
	}
	if errors.Is(err, ErrOwnerTextProjectReceiveLimit) {
		c.sharingMu.Lock()
		if s.ctx == job.ctx && s.connection == job.connection && !s.blocked[key] {
			wake := sharingPairWake{GrantID: project, Kind: "message"}
			if queued, exists := s.pending[key]; exists && queued.Kind == "state" {
				wake.Kind = "state"
			}
			// A capped project yields to all queued work, including wakes that
			// arrived while its handlers were running.
			delete(s.pending, key)
			enqueueSharingPendingLocked(s, key, wake)
			signalSharingCoordinator(s)
		}
		c.sharingMu.Unlock()
		return nil
	}
	if failed {
		c.sharingMu.Lock()
		if s.ctx == job.ctx && s.fullRevision == fullRevision && s.grantRevision[key] == projectRevision {
			s.blocked[key] = true
			delete(s.pending, key)
		}
		c.sharingMu.Unlock()
		return nil
	}
	return err
}

func (c *Client) notifyOwnerTextProjectReady(s *sharingCoordinator, job sharingReconcileJob, project, installation string) {
	c.sharingMu.Lock()
	ready := s.ownerTextReady
	current := s.ctx == job.ctx && s.connection == job.connection && s.ownerTextInstallation == installation && c.connGeneration.Load() == job.connection
	c.sharingMu.Unlock()
	if current && ready != nil && job.ctx.Err() == nil {
		func() { defer func() { _ = recover() }(); ready(project) }()
	}
}
