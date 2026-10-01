package localpeer

import (
	"fmt"
	"net"
	"strconv"
)

// ProcessSnapshot is a kernel-owned process identity, never a peer claim.
// Start is a platform-specific stable start marker; comparisons use one source.
type ProcessSnapshot struct {
	PID, Parent int
	UID         uint32
	Start       int64
}

// VerifyProcessTree refuses partial inspection, UID changes, PID reuse,
// reparenting and cycles. Snapshots are re-read before success so a process that
// exits/reparents during inspection cannot assemble a mixed-generation proof.
func VerifyProcessTree(peerPID, rootPID int, uid uint32, read func(int) (ProcessSnapshot, error)) error {
	if peerPID <= 0 || rootPID <= 0 {
		return fmt.Errorf("invalid peer or instance root pid")
	}
	root, err := read(rootPID)
	if err != nil {
		return fmt.Errorf("instance root is unavailable: %w", err)
	}
	if root.PID != rootPID || root.UID != uid || root.Start <= 0 {
		return fmt.Errorf("invalid instance root identity")
	}
	const maxHops = 32
	chain := make([]ProcessSnapshot, 0, maxHops+1)
	seen := map[int]bool{}
	current := peerPID
	for hops := 0; hops <= maxHops; hops++ {
		if seen[current] {
			return fmt.Errorf("peer process ancestry contains a cycle")
		}
		seen[current] = true
		process, err := read(current)
		if err != nil {
			return fmt.Errorf("peer ancestry unavailable: %w", err)
		}
		if process.PID != current || process.UID != uid || process.Start < root.Start {
			return fmt.Errorf("peer ancestry has another owner or predates the instance root")
		}
		if len(chain) > 0 && process.Start > chain[len(chain)-1].Start {
			return fmt.Errorf("peer ancestry parent started after its child")
		}
		chain = append(chain, process)
		if current == rootPID {
			if process != root {
				return fmt.Errorf("instance root changed during peer verification")
			}
			for _, before := range chain {
				after, err := read(before.PID)
				if err != nil || after != before {
					return fmt.Errorf("peer ancestry changed during verification")
				}
			}
			return nil
		}
		if process.Parent <= 1 {
			return fmt.Errorf("peer process tree does not contain the instance root")
		}
		current = process.Parent
	}
	return fmt.Errorf("peer process ancestry exceeded %d hops", maxHops)
}

// VerifyOwned pins the claimed root to its supervisor-captured birth marker.
// Merely reading whatever currently owns a recycled PID cannot prove ownership.
func VerifyOwned(c net.Conn, rootPID int, startIdentity string) error {
	pid, uid, err := Owner(c)
	if err != nil {
		return err
	}
	if startIdentity == "" {
		return fmt.Errorf("missing activation process identity")
	}
	read := func(id int) (ProcessSnapshot, error) {
		snapshot, err := ReadProcess(id)
		if err != nil {
			return snapshot, err
		}
		if id == rootPID && strconv.FormatInt(snapshot.Start, 10) != startIdentity {
			return snapshot, fmt.Errorf("activation process identity changed")
		}
		return snapshot, nil
	}
	if err := VerifyProcessTree(pid, rootPID, uid, read); err != nil {
		return err
	}
	endPID, endUID, err := Owner(c)
	if err != nil || endPID != pid || endUID != uid {
		return fmt.Errorf("peer kernel identity changed during verification")
	}
	return nil
}
