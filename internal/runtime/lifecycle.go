package runtime

import (
	"log/slog"
	"sync"

	"github.com/pagnet-code/pagnet/internal/proc"
)

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
