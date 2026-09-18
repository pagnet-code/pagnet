package session

// RemoteResolvable is the narrow OPTIONAL interface a persistent Driver
// implements when it can remote-resolve SOME interaction kinds (and not
// others). It is deliberately NOT part of the base Driver contract (the
// Driver interface must not gain vendor-specific members — I2 invariant):
// the base Capabilities.RemoteInteractionResolve is a single bool (the
// driver CAN remote-resolve at least some kind), while this interface lets
// the daemon query the PER-KIND policy.
//
// The canonical case is Qwen Dual Output (doc §6.3 / R3): can_use_tool
// kinds are remotely resolvable (proceed_once / cancel — the only two
// expressible outcomes, R10), but ask_user_question is HUMAN-ONLY — the
// daemon must never auto-resolve it (a generic allowed:true yields a
// phantom "No valid answers were provided." answer, worse than a hang).
//
// A Driver that remote-resolves every kind (or none) need not implement
// this interface; the daemon falls back to Capabilities.RemoteInteractionResolve.
type RemoteResolvable interface {
	// SupportsRemoteResolve reports whether a pending interaction of kind
	// can be resolved remotely (the answer is supplied back into the
	// native session).
	SupportsRemoteResolve(kind string) bool
}

// SupportsRemoteResolve is the nil-safe per-kind remote-resolution query
// for a Driver. It returns:
//
//   - false when the driver is nil or does not implement RemoteResolvable
//     (the daemon falls back to Capabilities.RemoteInteractionResolve);
//   - the driver's per-kind answer otherwise.
func SupportsRemoteResolve(d Driver, kind string) bool {
	if d == nil {
		return false
	}
	rr, ok := d.(RemoteResolvable)
	if !ok {
		return false
	}
	return rr.SupportsRemoteResolve(kind)
}
