package main

import (
	"errors"
	"fmt"
	"time"
)

type workerAvailabilityView struct {
	State      string     `json:"state"`
	ObservedAt *time.Time `json:"observedAt,omitempty"`
	ExpiresAt  *time.Time `json:"expiresAt,omitempty"`
}

func instanceStatus(status string, availability *workerAvailabilityView) string {
	if availability == nil || (availability.State != "unavailable" && availability.State != "unknown") {
		return status
	}
	switch status {
	case "stopped", "stopped_by_host", "failed":
		return status
	case "hibernated", "blocked", "auth_required", "rate_limited":
		return fmt.Sprintf("%s (worker %s)", status, availability.State)
	}
	return fmt.Sprintf("worker %s (last state: %s)", availability.State, status)
}

var errStopPending = errors.New("stopping is not confirmed")

type stopPendingError struct{ unavailable bool }

func (e *stopPendingError) Error() string {
	if e.unavailable {
		return "stop pending: worker unavailable; stopping is not confirmed"
	}
	return "stop pending: stopping is not confirmed"
}

func (e *stopPendingError) Unwrap() error { return errStopPending }

// This wait belongs only to a foreground lifecycle command. A successful POST
// admits the command; only the resulting instance state confirms completion.
func (c *cliCtx) performInstanceAction(path, action string, timeout, interval time.Duration) (string, error) {
	var admission struct {
		CommandID          string                  `json:"commandId"`
		Status             string                  `json:"status"`
		WorkerAvailability *workerAvailabilityView `json:"workerAvailability"`
	}
	if err := c.post(path+"/"+action, map[string]any{}, &admission); err != nil {
		return "", err
	}
	if action == "stop" && admission.WorkerAvailability != nil && admission.WorkerAvailability.State == "unavailable" {
		return "", &stopPendingError{unavailable: true}
	}
	settle := stopSettle
	if action == "restart" {
		settle = restartSettle
	}
	native := admission.WorkerAvailability != nil
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		var cur struct {
			Instance agentInstanceView `json:"instance"`
		}
		if err := c.get(path, &cur); err == nil {
			native = native || cur.Instance.WorkerAvailability != nil
			settled := settle[cur.Instance.Status]
			if action == "stop" && native {
				// A sleeping native instance is not evidence that this stop
				// completed; retain that compatibility only for legacy views.
				settled = cur.Instance.Status == "stopped"
			}
			if settled {
				return cur.Instance.displayStatus(), nil
			}
			if action == "stop" && cur.Instance.WorkerAvailability != nil && cur.Instance.WorkerAvailability.State == "unavailable" {
				return "", &stopPendingError{unavailable: true}
			}
		}
		if remaining := time.Until(deadline); remaining < interval {
			time.Sleep(remaining)
		} else {
			time.Sleep(interval)
		}
	}
	if action == "stop" {
		return "", &stopPendingError{}
	}
	return "(dispatched)", nil
}
