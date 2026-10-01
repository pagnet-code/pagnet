package daemon

// Per-activation bridge nonces (security wave S1).
//
// The daemon mints a fresh random nonce for every instance process
// (re)launch — the "activation" — and ships it to the bridge process
// inside the daemon-rendered MCP config (the PAGNET_BRIDGE_NONCE env of
// the bridge server entry). The bridge presents it in its first auth
// message; the daemon accepts a bridge only when the presented nonce
// matches the one it minted for that instance's CURRENT activation.
//
// Why a nonce and not just the instance identity: identifier-only auth
// let ANY same-UID process on the box (a compromised runtime, any user
// process) auth as any other live instance — including a representative
// and its full control surface. The nonce is a capability the daemon
// hands out at launch and re-rolls on every activation, so a stale or
// stolen-elsewhere credential dies with the activation that minted it.
// On Linux and Darwin the nonce is backed by kernel peer-PID process-tree
// binding; on platforms without a supported peer-PID implementation the
// nonce + "instance has a live process" check is the portable floor.
//
// The nonce is in-memory ONLY: it is never logged, never persisted, and
// not exported as a standalone runtime variable. It IS visible inside the
// runtime's PAGNET_MCP_CONFIG environment/launch payload, which the runtime
// hands to its bridge. It must therefore not be treated as a secret against
// other same-UID code: supported platforms require kernel process binding.
// A daemon restart
// wipes the store: every surviving bridge's nonce is unknown to the new
// process and is refused (fail closed; the restarted daemon re-mints on
// the next activation).

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
)

// bridgeNonceBytes is the nonce's entropy (32 bytes = 256 bits; the
// nonce is a per-activation capability, not a key — but a 256-bit
// comparison surface is plenty and costs nothing).
const bridgeNonceBytes = 32

// bridgeNonceForActivation mints (or, for a session-driven instance
// whose endpoint is ALREADY live, returns) the nonce the instance's next
// process launch carries, and returns it. It is the SINGLE mint point:
// turnSpecFor calls it before rendering the MCP config the launch env
// carries, so the rendered env always contains the nonce the daemon
// will accept.
//
// The live-endpoint case is the one where a re-mint would be WRONG: a
// persistent endpoint's bridge credentials are fixed at its launch (the
// launch env is never refreshed per turn), so re-rolling the nonce on
// every turn would invalidate the live endpoint's bridge the next time
// the MCP client re-spawns it. Legacy process-per-turn instances and
// session-driven instances WITHOUT a live endpoint get a fresh nonce on
// every call — each of their launches is a new activation.
//
// A crypto/rand failure returns "": the rendered config then carries no
// nonce, and the bridge REFUSES TO START without one (fail closed — an
// agent comes up without its network surface, loudly, instead of the
// daemon minting insecure credentials from a broken entropy source).
func (d *Daemon) bridgeNonceForActivation(row *InstanceRow) string {
	if d.sessionDriverFor(row) != nil && d.sup.EndpointPID(row.InstanceID) != nil {
		if n := d.currentBridgeNonce(row.InstanceID); n != "" {
			return n // the live endpoint's nonce is fixed at its launch
		}
	}
	return d.mintBridgeNonce(row.InstanceID)
}

// mintBridgeNonce generates a fresh nonce for the instance and stores it
// (replacing any prior one: a new activation supersedes the old
// credential). It returns the minted value ("" on a crypto/rand failure
// — see bridgeNonceForActivation).
func (d *Daemon) mintBridgeNonce(instanceID string) string {
	var buf [bridgeNonceBytes]byte
	if _, err := rand.Read(buf[:]); err != nil {
		d.Log.Error("bridge nonce mint failed (crypto/rand); the instance's bridge will refuse to start",
			"instance", instanceID, "err", err)
		return ""
	}
	nonce := hex.EncodeToString(buf[:])
	d.bridgeNonceMu.Lock()
	if d.bridgeNonces == nil {
		d.bridgeNonces = map[string]string{}
	}
	d.bridgeNonces[instanceID] = nonce
	d.bridgeNonceMu.Unlock()
	d.Log.Debug("bridge nonce minted for instance activation", "instance", instanceID)
	return nonce
}

// currentBridgeNonce returns the instance's stored nonce ("" when none
// is stored — a never-activated or invalidated instance).
func (d *Daemon) currentBridgeNonce(instanceID string) string {
	d.bridgeNonceMu.Lock()
	defer d.bridgeNonceMu.Unlock()
	return d.bridgeNonces[instanceID]
}

// invalidateBridgeNonce drops the instance's stored nonce. Called at
// every process-death boundary — stop, hibernate, restart
// (activation reset), and instance removal — so a dead activation's
// credential can never auth again.
func (d *Daemon) invalidateBridgeNonce(instanceID string) {
	d.bridgeNonceMu.Lock()
	delete(d.bridgeNonces, instanceID)
	d.bridgeNonceMu.Unlock()
}

// bridgeNonceValid reports whether presented is the instance's current
// activation nonce (constant-time comparison; an empty nonce is never
// valid).
func (d *Daemon) bridgeNonceValid(instanceID, presented string) bool {
	if presented == "" {
		return false
	}
	d.bridgeNonceMu.Lock()
	current := d.bridgeNonces[instanceID]
	d.bridgeNonceMu.Unlock()
	if current == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(presented), []byte(current)) == 1
}
