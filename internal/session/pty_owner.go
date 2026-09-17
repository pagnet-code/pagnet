package session

import (
	"os"
)

// PTYOwner is the narrow OPTIONAL interface a persistent Driver implements
// when its endpoint OWNS a native TUI PTY (Phase 3 terminal session
// unification). It is deliberately NOT part of the base Driver contract:
//
//   - The generic Driver contract exposes only SEMANTIC operations
//     (Activate/Submit/Hibernate/Stop/...). It must not gain or require
//     stdin/stdout pipes, os.File, or io.Pipe as the generic runtime
//     architecture — pipes are a specific driver's PHYSICAL machine plane
//     (the fake's JSONL control channel), not the generic contract.
//   - PTYOwner's *os.File is HUMAN-PLANE only: the daemon's terminal plane
//     relays a human's keystrokes/output to it and resizes it
//     (TIOCSWINSZ). It is acceptable precisely because it is a narrow
//     optional interface outside the base contract, type-asserted and
//     nil-safe.
//
// A Driver whose endpoint has NO PTY (server-class runtimes with no native
// TUI) simply does not implement PTYOwner; Manager.PTYMaster returns nil
// for it, and the daemon's terminal attach is a clean defined refusal (no
// crash, no hang, no partial state). PTY ownership stays OPTIONAL per
// endpoint: the generic architecture supports both the PTY-owning topology
// (the fake in Phase 3; Qwen/Claude later) and the no-PTY topology.
type PTYOwner interface {
	// PTYMaster is the endpoint's TUI PTY master for the instance (the
	// human plane) — nil when the endpoint is not live or was launched
	// without a PTY. The master is owned by the process handle: callers
	// hold it as a VIEW and never close it.
	PTYMaster(instanceID string) *os.File
}

// PTYMaster is the endpoint's TUI PTY master for an instance (the human
// plane) — nil-safe on every missing link:
//
//   - no session for the instance → nil;
//   - no registered driver for the session's runtime → nil;
//   - the driver does NOT implement PTYOwner (no-PTY topology) → nil;
//   - the driver implements PTYOwner but has no active PTY → nil.
//
// It is the seam the daemon's terminal plane uses to attach a human to the
// ENDPOINT'S OWN PTY instead of spawning a second interactive process. It
// takes m.mu only for the quick lookup (never across a driver call),
// consistent with the Manager's concurrency model.
func (m *Manager) PTYMaster(instanceID string) *os.File {
	m.mu.Lock()
	sess := m.sessions[instanceID]
	var d Driver
	if sess != nil {
		d = m.drivers[sess.Runtime]
	}
	m.mu.Unlock()
	if sess == nil || d == nil {
		return nil
	}
	owner, ok := d.(PTYOwner)
	if !ok {
		return nil
	}
	return owner.PTYMaster(instanceID)
}
