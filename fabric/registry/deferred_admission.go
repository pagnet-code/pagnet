package registry

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/pagnet-code/pagnet/fabric"
)

// DeferredAdmission is domain-level historical authentication evidence. It
// deliberately grants no native origin, paid dispatch or current permission.
// Rich continuation snapshots remain in their private store; this root record
// commits their exact bounded bytes without importing engine/storage packages.
type DeferredAdmission struct {
	Version            uint32            `json:"version"`
	DeferralID         string            `json:"deferralId"`
	OriginalCaller     fabric.Principal  `json:"originalCaller"`
	Provenance         fabric.Provenance `json:"provenance"`
	OriginalDigest     [32]byte          `json:"originalDigest"`
	SnapshotCommitment [32]byte          `json:"snapshotCommitment"`
	PlanRevision       fabric.Revision   `json:"planRevision"`
}

func deferredKey(id string) (AuthorityKey, error) {
	raw, err := hex.DecodeString(id)
	if err != nil || len(raw) != 32 || hex.EncodeToString(raw) != id {
		return AuthorityKey{}, invalid("Invalid durable deferral identity")
	}
	return AuthorityKey{Kind: AuthorityDeferredAdmission, ID: id}, nil
}

func (a *AuthorityTx) RecordDeferredAdmission(caller fabric.ExecutionContext, original []byte, v DeferredAdmission) (AuthorityRecord, error) {
	if a == nil {
		return AuthorityRecord{}, invalid("Missing deferred authority transaction")
	}
	a.mu.Lock()
	err := a.guard()
	a.mu.Unlock()
	if err != nil {
		return AuthorityRecord{}, err
	}
	key, err := deferredKey(v.DeferralID)
	if err != nil {
		return AuthorityRecord{}, err
	}
	if v.Version != 1 || v.PlanRevision == "" || len(v.PlanRevision) > 256 || v.OriginalDigest == ([32]byte{}) || v.SnapshotCommitment == ([32]byte{}) || v.OriginalCaller != caller.PrincipalView() || sha256.Sum256(original) != v.OriginalDigest {
		return AuthorityRecord{}, invalid("Invalid deferred admission commitment")
	}
	if _, err = caller.DecodeVerifiedEnvelope(original, a.store.identity.Namespace); err != nil {
		return AuthorityRecord{}, err
	}
	provenance, _ := json.Marshal(caller.ProvenanceView())
	expected, _ := json.Marshal(v.Provenance)
	if !bytes.Equal(provenance, expected) {
		return AuthorityRecord{}, invalid("Deferred provenance differs")
	}
	raw, err := json.Marshal(v)
	if err != nil || len(raw) > fabric.MaxSigningFrameBytes {
		return AuthorityRecord{}, invalid("Deferred admission exceeds bound")
	}
	// CAS(0) is exact immutable replay only: altered snapshots cannot create a
	// second revision/secret for the same engine-owned deferral identity.
	return a.CAS(key, 0, raw, false)
}

func (a *AuthorityTx) VerifyDeferredAdmission(record AuthorityRecord, original []byte, commitment [32]byte) (DeferredAdmission, error) {
	var value DeferredAdmission
	if a == nil {
		return value, invalid("Missing deferred authority transaction")
	}
	a.mu.Lock()
	err := a.guard()
	a.mu.Unlock()
	if err != nil {
		return value, err
	}
	if record.Key.Kind != AuthorityDeferredAdmission || record.Retired || record.Revision != 1 || len(record.Value) > fabric.MaxSigningFrameBytes {
		return value, invalid("Invalid historical deferral record")
	}
	retained, err := a.Get(record.Key)
	if err != nil {
		return value, err
	}
	raw, _ := json.Marshal(retained)
	exact, _ := json.Marshal(record)
	if !bytes.Equal(raw, exact) || fabric.DecodeJSON(record.Value, &value) != nil {
		return value, invalid("Deferred admission not retained unchanged")
	}
	key, err := deferredKey(value.DeferralID)
	if err != nil || key != record.Key || value.Version != 1 || sha256.Sum256(original) != value.OriginalDigest || value.SnapshotCommitment != commitment || value.PlanRevision == "" {
		return value, invalid("Historical deferral commitment differs")
	}
	return value, nil
}
