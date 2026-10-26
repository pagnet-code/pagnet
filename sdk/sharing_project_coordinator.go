package sdk

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"

	"github.com/pagnet-code/pagnet/transport"
)

const sharingProjectWakeType = "endpoint.sharing_project_wake"

type sharingProjectWake struct {
	ProjectID string `json:"projectId"`
	Kind      string `json:"kind"`
}

func sharingProjectJobKey(project string) string { return "project:" + project }

// OnSharingProjectMessage opts into event-driven enrollment and inbox replay.
// Return nil only after successful processing. Failure or panic waits for a new
// wake, reconnect, or explicit EnableSharingProjects call before redelivery.
// Callbacks share one serialized worker with pair callbacks and must honor ctx.
func (c *Client) OnSharingProjectMessage(handler func(context.Context, SharingProjectMessage) error) {
	c.sharingMu.Lock()
	defer c.sharingMu.Unlock()
	if c.closed.Load() {
		return
	}
	s := c.ensureSharingCoordinatorLocked()
	s.projectsEnabled, s.projectHandler = true, handler
	c.kickSharingCoordinatorLocked(s)
}

// EnableSharingProjects enrolls send-only clients and explicitly requests a full
// reconciliation, including retrying failed handlers. There is no idle polling.
func (c *Client) EnableSharingProjects() {
	c.sharingMu.Lock()
	defer c.sharingMu.Unlock()
	if c.closed.Load() {
		return
	}
	s := c.ensureSharingCoordinatorLocked()
	s.projectsEnabled = true
	c.kickSharingCoordinatorLocked(s)
}

// OnSharingProjectReady registers a local wake after project authority is ready,
// including after reconnect. The callback runs on the serialized sharing worker.
func (c *Client) OnSharingProjectReady(handler func(projectID string)) {
	c.sharingMu.Lock()
	defer c.sharingMu.Unlock()
	if c.closed.Load() {
		return
	}
	s := c.ensureSharingCoordinatorLocked()
	s.projectsEnabled, s.projectReady = true, handler
	c.kickSharingCoordinatorLocked(s)
}

func (c *Client) handleSharingProjectWake(pc *conn, env transport.Envelope) {
	c.connMu.Lock()
	current := c.cur == pc
	c.connMu.Unlock()
	if !current {
		return
	}
	var wake sharingProjectWake
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
	c.queueSharingProjectWake(wake)
}

func (c *Client) queueSharingProjectWake(wake sharingProjectWake) {
	c.queueSharingWake(sharingPairWake{GrantID: wake.ProjectID, Kind: wake.Kind}, true)
}

func (c *Client) reconcileSharingProjects(s *sharingCoordinator, job sharingReconcileJob) error {
	projects, err := c.ListSharingProjects(job.ctx)
	if err != nil {
		return err
	}
	for _, status := range projects {
		if err := c.reconcileSharingProject(s, job, status.ProjectID); err != nil && retrySharingReconcile(err) {
			return err
		}
	}
	return job.ctx.Err()
}

func (c *Client) reconcileSharingProject(s *sharingCoordinator, job sharingReconcileJob, project string) error {
	if err := job.ctx.Err(); err != nil {
		return err
	}
	key := sharingProjectJobKey(project)
	c.sharingMu.Lock()
	blocked := s.blocked[key]
	current := s.ctx == job.ctx && s.connection == job.connection
	c.sharingMu.Unlock()
	if blocked || !current {
		return nil
	}
	// Enrollment is idempotent and reestablishes the endpoint proof on reconnect.
	result, err := c.EnrollSharingProject(job.ctx, project)
	if err != nil {
		return err
	}
	if result.Pending || job.ctx.Err() != nil {
		return job.ctx.Err()
	}
	c.sharingMu.Lock()
	ready, handler := s.projectReady, s.projectHandler
	current = s.ctx == job.ctx && s.connection == job.connection
	c.sharingMu.Unlock()
	if !current || job.ctx.Err() != nil {
		return job.ctx.Err()
	}
	if ready != nil {
		func() { defer func() { _ = recover() }(); ready(project) }()
	}
	if handler == nil {
		return nil
	}
	failed := false
	var fullRevision, projectRevision uint64
	err = c.ReceiveSharingProjectMessages(job.ctx, project, func(ctx context.Context, m SharingProjectMessage) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		c.sharingMu.Lock()
		handler := s.projectHandler
		current := s.ctx == job.ctx && s.connection == job.connection
		fullRevision, projectRevision = s.fullRevision, s.grantRevision[key]
		c.sharingMu.Unlock()
		if !current || handler == nil {
			return errors.New("sdk: sharing project handler or connection changed")
		}
		handlerErr := invokeSharingProjectHandler(ctx, handler, m)
		if handlerErr != nil {
			failed = true
		}
		return handlerErr
	})
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
