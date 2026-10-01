package proc

import (
	"context"
	"errors"
)

// OwnedStartIdentity returns the immutable kernel birth marker captured at
// successful launch. A native bridge can arrive before the ownership record
// fsync finishes; wait for publication rather than trusting a provisional PID.
func (s *Supervisor) OwnedStartIdentity(ctx context.Context, pid int) (string, error) {
	if pid <= 0 {
		return "", errors.New("missing activation process")
	}
	s.mu.Lock()
	var found *managedTurn
	for _, candidate := range s.turns {
		if int(candidate.pid.Load()) == pid {
			found = candidate
			break
		}
	}
	s.mu.Unlock()
	if found == nil {
		return "", errors.New("activation process is not owned")
	}
	select {
	case <-found.launchSettled:
	case <-ctx.Done():
		return "", ctx.Err()
	}
	if !found.ownershipPublished || found.identity == "" || found.reaped.Load() || found.state.Load() != stRunning {
		return "", errors.New("activation process ownership is not live")
	}
	return found.identity, nil
}
