// Package fabricnative composes genuine local native ownership with Fabric.
package fabricnative

import (
	"context"
	"sync"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/internal/localpeer"
)

// OwnerGuard excludes managed worker trees from owner authentication even when
// a descendant omits all managed selectors. Register the mutually authenticated
// LocalClient.OwnerProcess before admitting the first native intent. Registrations
// outlive terminal/socket detachment and remain until the supervisor has joined
// the complete owned process tree. The registry is not a source of principals.
type OwnerGuard struct {
	mu       sync.RWMutex
	roots    map[int]localpeer.ProcessSnapshot
	revision uint64
	read     func(int) (localpeer.ProcessSnapshot, error)
}

func NewOwnerGuard() *OwnerGuard {
	return &OwnerGuard{roots: make(map[int]localpeer.ProcessSnapshot), read: localpeer.ReadProcess}
}

func guardDenied() error {
	return fabric.NewError(fabric.CodeUnauthenticated, "Current independent owner process required")
}

// Register accepts only supervisor-obtained IPC kernel evidence, never request
// JSON. A reused PID cannot replace another live ownership registration.
func (g *OwnerGuard) Register(ctx context.Context, worker localpeer.ProcessSnapshot) error {
	if g == nil || ctx == nil || ctx.Err() != nil || worker.PID <= 1 || worker.Start <= 0 {
		return guardDenied()
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	current, err := g.read(worker.PID)
	if err != nil || current != worker || ctx.Err() != nil {
		return guardDenied()
	}
	if old, ok := g.roots[worker.PID]; ok {
		if old != worker {
			return guardDenied()
		}
		return nil
	}
	if len(g.roots) >= 4096 {
		return fabric.NewError(fabric.CodeTargetUnavailable, "Native ownership capacity unavailable")
	}
	g.roots[worker.PID] = worker
	g.revision++
	return nil
}

// RetireJoined removes only the exact registered generation. The trusted
// supervisor must call this after joining every owned descendant, never merely
// because a worker socket closed or its root PID disappeared.
func (g *OwnerGuard) RetireJoined(worker localpeer.ProcessSnapshot) error {
	if g == nil {
		return guardDenied()
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if old, ok := g.roots[worker.PID]; !ok || old != worker {
		return guardDenied()
	}
	delete(g.roots, worker.PID)
	g.revision++
	return nil
}

// Validate has bounded ancestry work independent of the number of registered
// workers. Missing, changed or excessive ancestry fails closed. Registrations
// changing during inspection invalidate the check rather than racing admission.
func (g *OwnerGuard) Validate(ctx context.Context, peer localpeer.ProcessSnapshot) error {
	if g == nil || ctx == nil || ctx.Err() != nil || peer.PID <= 1 || peer.Start <= 0 {
		return guardDenied()
	}
	g.mu.RLock()
	revision := g.revision
	g.mu.RUnlock()
	chain := make([]localpeer.ProcessSnapshot, 0, 32)
	seen := make(map[int]bool, 32)
	pid := peer.PID
	for len(chain) < 32 {
		if ctx.Err() != nil || pid <= 1 || seen[pid] {
			return guardDenied()
		}
		seen[pid] = true
		process, err := g.read(pid)
		if err != nil || process.PID != pid || process.Start <= 0 {
			return guardDenied()
		}
		if len(chain) == 0 && process != peer {
			return guardDenied()
		}
		if len(chain) > 0 && process.Start > chain[len(chain)-1].Start {
			return guardDenied()
		}
		g.mu.RLock()
		_, managed := g.roots[pid]
		changed := g.revision != revision
		g.mu.RUnlock()
		if managed || changed {
			return guardDenied()
		}
		chain = append(chain, process)
		if process.Parent <= 1 {
			for _, before := range chain {
				after, err := g.read(before.PID)
				if err != nil || after != before {
					return guardDenied()
				}
			}
			g.mu.RLock()
			unchanged := g.revision == revision
			g.mu.RUnlock()
			if !unchanged || ctx.Err() != nil {
				return guardDenied()
			}
			return nil
		}
		pid = process.Parent
	}
	return guardDenied()
}
