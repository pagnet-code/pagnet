package runtime

import (
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/pagnet-code/pagnet/internal/proc"
)

// defaultStartupTimeout is the PRODUCTION startup budget of a persistent
// runtime driver: the maximum it allows a healthy endpoint process to take
// before its activation handshake completes. It bounds only the startup
// stage — it is NOT the in-flight turn stall threshold (that lives in the
// turn state machine) and NOT a turn execution deadline.
//
// 60s, not the 15s the fake runtime driver uses for its own deterministic
// test deadline: a genuinely healthy cold start of a real vendor CLI
// (node boot + MCP server bring-up + auth + resume replay) was observed in
// production exceeding 15s on the first launch of a host while the warm
// start of the identical launch took 2s. A budget tuned for a test fake
// must not kill real processes.
const defaultStartupTimeout = 60 * time.Second

// effectiveStartupTimeout resolves a persistent driver's startup budget: an
// explicit driver-owned value wins, and the zero value means "the production
// default" (so the daemon's constructors need no change to get the correct
// budget).
//
// Invariant: every PRODUCTION persistent driver owns its startup budget
// through its own StartupTimeout field resolved here. A fake/test driver's
// deadline must never define production runtime behavior — the defect this
// removes was a 15s constant declared in the fake persistent driver that the
// real Qwen and Codex drivers silently inherited, so a test tuning knob
// decided when healthy production startups were killed.
func effectiveStartupTimeout(v time.Duration) time.Duration {
	if v > 0 {
		return v
	}
	return defaultStartupTimeout
}

// startupBudgetText renders a startup budget for the startup-failure text an
// operator actually reads ("60s", "250ms"). time.Duration renders 60s as
// "1m0s"; the budget is the number that matters in that sentence, so whole
// seconds are printed as seconds.
func startupBudgetText(d time.Duration) string {
	if d >= time.Second && d%time.Second == 0 {
		return fmt.Sprintf("%ds", int(d/time.Second))
	}
	return d.String()
}

// LifecycleSetter is the process-supervision injection seam (abuse
// addendum Part B §20). The daemon implements one CENTRAL supervisor and
// injects it into every adapter it drives, so all turn processes share a
// single registry, launch gate, semaphore, and cleanup path. An adapter
// that is driven standalone (tests, demo) and never receives an injection
// falls back to a private standalone supervisor — same guarantees, one
// process per adapter.
//
// This is a SUB-interface, mirroring InteractionObserver: the Adapter
// contract itself is unchanged, and adapters that do not manage OS
// processes (test stubs) simply do not implement it.
type LifecycleSetter interface {
	// SetLifecycle installs the process lifecycle the adapter launches
	// turn processes through. It must be called before the first
	// StartTurn.
	SetLifecycle(l proc.Lifecycle)
}

// lifecycleState is the shared process-supervision plumbing embedded in
// each real runtime adapter. It holds the injected Lifecycle and lazily
// creates a private standalone supervisor when none was injected.
type lifecycleState struct {
	mu  sync.Mutex
	lif proc.Lifecycle
}

// SetLifecycle implements LifecycleSetter.
func (l *lifecycleState) SetLifecycle(lif proc.Lifecycle) {
	l.mu.Lock()
	l.lif = lif
	l.mu.Unlock()
}

// get returns the injected lifecycle, creating a private standalone
// supervisor on first use when the daemon did not inject one. The
// standalone supervisor uses the safe defaults and no state dir (no
// ownership records — standalone use has no cross-restart reconciliation
// to perform).
func (l *lifecycleState) get() proc.Lifecycle {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.lif == nil {
		l.lif = proc.NewSupervisor(proc.DefaultConfig(), slog.Default())
	}
	return l.lif
}
