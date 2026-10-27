package sdk

import "errors"

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

func (c *Client) reconcileOwnerTextProjects(s *sharingCoordinator, job sharingReconcileJob, installation string) error {
	projects, err := c.ListOwnerTextProjects(job.ctx)
	if err != nil {
		return err
	}
	for _, status := range projects {
		if err := job.ctx.Err(); err != nil {
			return err
		}
		result, err := c.EnrollOwnerTextProject(job.ctx, status.ProjectID, installation)
		if err != nil {
			if retrySharingReconcile(err) {
				return err
			}
			continue
		}
		if result.Pending {
			continue
		}
		c.sharingMu.Lock()
		ready := s.ownerTextReady
		current := s.ctx == job.ctx && s.connection == job.connection && s.ownerTextInstallation == installation
		c.sharingMu.Unlock()
		if current && ready != nil && job.ctx.Err() == nil {
			func() { defer func() { _ = recover() }(); ready(status.ProjectID) }()
		}
	}
	return job.ctx.Err()
}
