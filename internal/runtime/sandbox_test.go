package runtime

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/pagnet-code/pagnet/internal/sandbox"
)

// TestDriverSandbox_DeniedContainment pins F-CFG-1 at the driver level:
// a driver's spec carries the daemon's state dir as the Denied containment
// set, and a $HOME-style workspace (one that CONTAINS the state dir) makes
// the assembled spec invalid — Normalize refuses it, so the supervisor's
// wrap refuses the launch before any process starts. A disjoint workspace
// stays valid (the session dir being a CHILD of the denied state dir is
// the normal production layout — only the containment direction is a
// violation).
func TestDriverSandbox_DeniedContainment(t *testing.T) {
	home := t.TempDir()
	stateDir := filepath.Join(home, ".pagnet")
	sessionDir := filepath.Join(stateDir, "sessions", "inst1")

	f := NewFake("")
	spec := TurnSpec{
		InstanceID:    "inst1",
		Workspace:     home, // the $HOME-shape violation
		SessionDir:    sessionDir,
		SandboxDenied: []string{stateDir},
	}
	if err := f.SandboxSpec(spec).Normalize(); err == nil {
		t.Fatal("driver spec with workspace=$HOME covering the state dir: valid, want a refusal")
	}

	ok := TurnSpec{
		InstanceID:    "inst1",
		Workspace:     filepath.Join(home, "projects", "ws"),
		SessionDir:    sessionDir,
		SandboxDenied: []string{stateDir},
	}
	if err := f.SandboxSpec(ok).Normalize(); err != nil {
		t.Fatalf("driver spec with a disjoint workspace: %v, want accepted", err)
	}
}

// TestDriverSandbox_DeniedEveryDriver pins the F-CFG-1 seam for the spec
// construction shapes of ALL drivers: the process-per-turn adapters (their
// SandboxSpec method) and the persistent-driver shape (driverSandbox, the
// same function codex/qwen/persistent-fake call from their launch path).
// A driver that dropped the denied field would fail here, and a $HOME
// workspace would silently void that driver's sandbox.
func TestDriverSandbox_DeniedEveryDriver(t *testing.T) {
	stateDir := t.TempDir()
	sessionDir := filepath.Join(stateDir, "sessions", "inst1")
	denied := []string{stateDir}

	// The workspace is the DENIED state dir itself (the strongest
	// violation — equal, not just containing).
	violating := TurnSpec{
		Workspace:     stateDir,
		SessionDir:    sessionDir,
		SandboxDenied: denied,
	}
	adapterSpecs := map[string]*sandbox.Spec{
		"fake":     NewFake("").SandboxSpec(violating),
		"claude":   NewClaude("").SandboxSpec(violating),
		"opencode": NewOpenCode("").SandboxSpec(violating),
	}
	// The persistent-driver shape (sess.SandboxDenied → driverSandbox →
	// the same NewSpec point).
	driverSpec := driverSandbox(driverSandboxOpts{
		workspace: stateDir,
		stateDir:  sessionDir,
		denied:    denied,
	})

	for name, s := range adapterSpecs {
		if len(s.Denied) != 1 || s.Denied[0] != stateDir {
			t.Errorf("%s: spec.Denied = %v, want the containment set carried through", name, s.Denied)
		}
		if err := s.Normalize(); err == nil {
			t.Errorf("%s: workspace = the denied state dir: spec valid, want a refusal", name)
		} else if !strings.Contains(err.Error(), stateDir) {
			t.Errorf("%s: refusal %q does not name the denied path", name, err)
		}
	}
	if len(driverSpec.Denied) != 1 || driverSpec.Denied[0] != stateDir {
		t.Fatalf("persistent-driver shape: spec.Denied = %v, want the containment set carried through", driverSpec.Denied)
	}
	if err := driverSpec.Normalize(); err == nil {
		t.Fatal("persistent-driver shape: workspace = the denied state dir: spec valid, want a refusal")
	}
}
