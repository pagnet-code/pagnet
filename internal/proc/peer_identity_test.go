//go:build linux || darwin

package proc

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestOwnedStartIdentityRequiresPublishedLiveActivation(t *testing.T) {
	cfg := DefaultConfig()
	cfg.StateDir = t.TempDir()
	s := newTestSupervisor(t, cfg)
	if _, err := s.OwnedStartIdentity(context.Background(), os.Getpid()); err == nil {
		t.Fatal("unowned process accepted")
	}
	h, err := s.Launch(context.Background(), LaunchRequest{InstanceID: "owned-peer", TurnID: "endpoint", Runtime: "fake", Class: ClassEndpoint, Cmd: exec.Command("sleep", "30")})
	if err != nil {
		t.Fatal(err)
	}
	marker, err := s.OwnedStartIdentity(context.Background(), h.PID())
	if err != nil || marker == "" {
		t.Fatalf("published native ownership unavailable: %q %v", marker, err)
	}
	actual, err := StartIdentity(h.PID())
	if err != nil || actual != marker {
		t.Fatalf("ownership marker not captured native generation: %q %q %v", marker, actual, err)
	}
	terminateAndReap(t, h)
	if _, err = s.OwnedStartIdentity(context.Background(), h.PID()); err == nil {
		t.Fatal("reaped activation accepted")
	}
}

func TestOwnedStartIdentityWaitsForPublication(t *testing.T) {
	s := newTestSupervisor(t, DefaultConfig())
	turn := &managedTurn{launchSettled: make(chan struct{})}
	turn.pid.Store(12345)
	s.mu.Lock()
	s.turns[Key{InstanceID: "pending", TurnID: "endpoint"}] = turn
	s.mu.Unlock()
	// Provisional PID alone is never enough, even if the record is about to
	// become durable. A bounded caller can fail rather than weakening auth.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := s.OwnedStartIdentity(ctx, 12345); err == nil {
		t.Fatal("unpublished activation accepted")
	}
	close(turn.launchSettled)
	if _, err := s.OwnedStartIdentity(context.Background(), 12345); err == nil {
		t.Fatal("failed publication accepted")
	}
	s.mu.Lock()
	delete(s.turns, Key{InstanceID: "pending", TurnID: "endpoint"})
	s.mu.Unlock()
}
