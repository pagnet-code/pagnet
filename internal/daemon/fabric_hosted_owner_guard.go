package daemon

import (
	"context"
	"sync"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/internal/fabricauth"
	"github.com/pagnet-code/pagnet/internal/localpeer"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
)

// HostedOwnerGuard chains the existing local-managed guard and rejects owner
// elevation by descendants of authenticated original CLOUD workers. Roots are
// registered BEFORE exposing the node listener or allowing new native launches.
// Lookup walks bounded kernel ancestry, never the catalog or every worker.
type HostedOwnerGuard struct {
	mu      sync.RWMutex
	roots   map[int]localpeer.ProcessSnapshot
	workers map[sessionworker.Scope]localpeer.ProcessSnapshot
	next    fabricauth.OwnerValidator
}

func NewHostedOwnerGuard(next fabricauth.OwnerValidator) (*HostedOwnerGuard, error) {
	if next == nil {
		return nil, hostedOwnerDenied()
	}
	return &HostedOwnerGuard{roots: make(map[int]localpeer.ProcessSnapshot), workers: make(map[sessionworker.Scope]localpeer.ProcessSnapshot), next: next}, nil
}
func hostedOwnerDenied() error {
	return fabric.NewError(fabric.CodeUnauthenticated, "Managed runtime cannot authenticate as the installation owner")
}

// Register accepts only the mutually authenticated original private controller.
// Disconnection does not remove a still-running worker's owner-mode protection.
func (g *HostedOwnerGuard) Register(proxy *NativeWorkerProxy) error {
	if g == nil || proxy == nil {
		return hostedOwnerDenied()
	}
	root, err := proxy.HostedOwnerProcess()
	if err != nil {
		return err
	}
	if err = g.register(root); err != nil {
		return err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, found := g.workers[proxy.scope]; !found && len(g.workers) >= 65536 {
		return fabric.NewError(fabric.CodeTargetUnavailable, "Hosted original worker scope guard capacity reached")
	}
	g.workers[proxy.scope] = root
	return nil
}
func (g *HostedOwnerGuard) register(root localpeer.ProcessSnapshot) error {
	current, err := localpeer.ReadProcess(root.PID)
	if err != nil || current != root || root.Start <= 0 {
		return hostedOwnerDenied()
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, found := g.roots[root.PID]; !found && len(g.roots) >= 65536 {
		return fabric.NewError(fabric.CodeTargetUnavailable, "Hosted worker owner guard capacity reached")
	}
	if old, found := g.roots[root.PID]; found && old != root {
		// Only a real different incarnation may replace an exited worker.
		if old.Start == root.Start {
			return hostedOwnerDenied()
		}
	}
	g.roots[root.PID] = root
	return nil
}

func (g *HostedOwnerGuard) Validate(ctx context.Context, peer localpeer.ProcessSnapshot) error {
	if g == nil || g.next == nil || ctx == nil || ctx.Err() != nil || peer.PID <= 0 || peer.Start <= 0 {
		return hostedOwnerDenied()
	}
	chain := make([]localpeer.ProcessSnapshot, 0, 33)
	seen := make(map[int]bool, 33)
	id := peer.PID
	for hops := 0; hops <= 32; hops++ {
		if ctx.Err() != nil || seen[id] {
			return hostedOwnerDenied()
		}
		seen[id] = true
		current, err := localpeer.ReadProcess(id)
		if err != nil || current.PID != id || current.Start <= 0 || hops == 0 && current != peer {
			return hostedOwnerDenied()
		}
		chain = append(chain, current)
		g.mu.RLock()
		root, managed := g.roots[id]
		g.mu.RUnlock()
		if managed && current.Start == root.Start && current.UID == root.UID {
			// A same-incarnation reparent is still managed. It is never a reason
			// to release the owner fence or promote the process to operator.
			return hostedOwnerDenied()
		}
		if current.Parent <= 1 {
			for _, before := range chain {
				after, err := localpeer.ReadProcess(before.PID)
				if err != nil || after != before {
					return hostedOwnerDenied()
				}
			}
			return g.next(ctx, peer)
		}
		id = current.Parent
	}
	return hostedOwnerDenied()
}
