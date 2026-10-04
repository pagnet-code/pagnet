package fabricnative

import (
	"context"
	"errors"
	"testing"

	"github.com/pagnet-code/pagnet/internal/localpeer"
)

func TestOwnerGuardRejectsManagedDowngradeAndMixedAncestry(t *testing.T) {
	ctx := context.Background()
	owner := localpeer.ProcessSnapshot{PID: 10, Parent: 1, UID: 1000, Start: 10}
	worker := localpeer.ProcessSnapshot{PID: 20, Parent: 10, UID: 1000, Start: 20}
	child := localpeer.ProcessSnapshot{PID: 30, Parent: 20, UID: 1000, Start: 30}
	processes := map[int]localpeer.ProcessSnapshot{10: owner, 20: worker, 30: child}
	g := NewOwnerGuard()
	g.read = func(pid int) (localpeer.ProcessSnapshot, error) {
		p, ok := processes[pid]
		if !ok {
			return p, errors.New("unavailable")
		}
		return p, nil
	}
	if err := g.Register(ctx, worker); err != nil {
		t.Fatal(err)
	}
	if err := g.Validate(ctx, owner); err != nil {
		t.Fatal(err)
	}
	if g.Validate(ctx, worker) == nil || g.Validate(ctx, child) == nil {
		t.Fatal("managed process admitted as owner")
	}
	// PID reuse cannot silently remove a deny registration.
	reused := worker
	reused.Start++
	processes[20] = reused
	if g.Register(ctx, reused) == nil || g.Validate(ctx, child) == nil {
		t.Fatal("reused registered PID admitted")
	}
	if g.RetireJoined(reused) == nil {
		t.Fatal("another generation retired live guard")
	}
	processes[20] = worker
	if err := g.RetireJoined(worker); err != nil {
		t.Fatal(err)
	}
	// A stable independent tree is admitted only after the trusted join boundary.
	if err := g.Validate(ctx, child); err != nil {
		t.Fatal(err)
	}
	calls := 0
	g.read = func(pid int) (localpeer.ProcessSnapshot, error) {
		calls++
		p := processes[pid]
		if calls == 4 {
			p.Parent = 1
		}
		return p, nil
	}
	if g.Validate(ctx, child) == nil {
		t.Fatal("mixed ancestry admitted")
	}
}

func TestOwnerGuardRegistrationDuringInspectionFailsClosed(t *testing.T) {
	ctx := context.Background()
	owner := localpeer.ProcessSnapshot{PID: 10, Parent: 1, UID: 1000, Start: 10}
	child := localpeer.ProcessSnapshot{PID: 20, Parent: 10, UID: 1000, Start: 20}
	g := NewOwnerGuard()
	processes := map[int]localpeer.ProcessSnapshot{10: owner, 20: child}
	reads := 0
	g.read = func(pid int) (localpeer.ProcessSnapshot, error) {
		reads++
		if reads == 2 {
			g.mu.Lock()
			g.roots[20] = child
			g.revision++
			g.mu.Unlock()
		}
		return processes[pid], nil
	}
	if g.Validate(ctx, child) == nil {
		t.Fatal("concurrent managed registration admitted as owner")
	}
}

func TestOwnerGuardBoundsUnknownCyclicAndDeepAncestry(t *testing.T) {
	ctx := context.Background()
	for _, mode := range []string{"missing", "cycle", "deep"} {
		t.Run(mode, func(t *testing.T) {
			g := NewOwnerGuard()
			count := 0
			g.read = func(pid int) (localpeer.ProcessSnapshot, error) {
				count++
				if mode == "missing" {
					return localpeer.ProcessSnapshot{}, errors.New("unavailable")
				}
				parent := pid - 1
				if mode == "cycle" {
					parent = pid
				}
				return localpeer.ProcessSnapshot{PID: pid, Parent: parent, UID: 1000, Start: int64(pid)}, nil
			}
			peer := localpeer.ProcessSnapshot{PID: 100, Parent: 99, UID: 1000, Start: 100}
			if mode == "cycle" {
				peer.Parent = 100
			}
			if g.Validate(ctx, peer) == nil || count > 32 {
				t.Fatal("unsafe or unbounded ancestry check")
			}
		})
	}
}
