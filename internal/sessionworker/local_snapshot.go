package sessionworker

import (
	"encoding/json"
	"errors"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/session"
)

// LocalNativeSnapshot is owner-private evidence, delivered only after mutually
// authenticating the pinned local worker scope/control channel. ActivationNonce
// is never published to discovery, Cloud source history or ordinary output.
// Current registry authorization and actual kernel peer ancestry remain separate
// mandatory checks; a snapshot cannot authenticate an asserted remote PID.
type LocalNativeSnapshot struct {
	Authority           AuthorityScope       `json:"authority"`
	ActualRuntime       domain.RuntimeName   `json:"actualRuntime"`
	ProfileFingerprint  string               `json:"profileFingerprint"`
	NativeGeneration    string               `json:"nativeGeneration"`
	NativeSessionID     string               `json:"nativeSessionId"`
	NativeStartIdentity string               `json:"nativeStartIdentity,omitempty"`
	PID                 int                  `json:"pid"`
	State               session.SessionState `json:"state"`
	Origin              json.RawMessage      `json:"origin,omitempty"`
	ActivationNonce     string               `json:"activationNonce,omitempty"`
	IdentityPending     bool                 `json:"identityPending,omitempty"`
	HasTerminal         bool                 `json:"hasTerminal"`
}

func (o *SessionOwner) LocalSnapshot() (LocalNativeSnapshot, error) {
	if o == nil || o.journal == nil || !o.journal.isLocal() {
		return LocalNativeSnapshot{}, errors.New("local native snapshot requires local authority")
	}
	physical := o.physicalSnapshot()
	o.mu.Lock()
	defer o.mu.Unlock()
	if physical.NativeGeneration != o.generation {
		return LocalNativeSnapshot{}, ErrFenced
	}
	s := LocalNativeSnapshot{Authority: o.journal.authority, ActualRuntime: physical.ActualRuntime, ProfileFingerprint: LocalNativeProfileFingerprint(o.spec), NativeGeneration: physical.NativeGeneration, NativeSessionID: physical.NativeSessionID, NativeStartIdentity: physical.NativeStartIdentity, PID: physical.PID, State: physical.State, Origin: physical.Origin, IdentityPending: physical.IdentityPending, HasTerminal: physical.HasTerminal}
	if physical.PID > 0 && !physical.IdentityPending && physical.NativeSessionID != "" && physical.NativeGeneration != "" {
		s.ActivationNonce = o.nonce
	}
	return s, nil
}
