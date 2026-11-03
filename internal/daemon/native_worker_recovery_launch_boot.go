//go:build linux || darwin

package daemon

import (
	"encoding/json"
	"errors"

	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

func validLaunchRecoveryProof(r NativeWorkerRecovery) bool {
	p := r.LaunchProof
	if p == (NativeWorkerLaunchRecoveryProof{}) {
		return true
	}
	return p.Scope.InstanceID == r.InstanceID && p.Scope.Generation == r.OriginalGeneration && p.Scope.Generation == r.LocalGeneration && p.Scope.Generation != "" && p.Scope.ServerURL != "" && p.Scope.HostID == r.HostID && p.Scope.TenantID == r.TenantID && p.Scope.AccountID == r.AccountID && p.ProfileFingerprint != "" && p.OriginalOwnershipID == r.OwnershipID && p.DeathProof.Kind == "prior_launch_boot" && p.DeathProof.LaunchBoot == p.LaunchBoot && p.LaunchBoot.Valid() && p.LaunchBoot.Quality == "boot_uuid"
}

func launchRecoveryClaim(local NativeWorkerRecord) NativeWorkerLaunchRecoveryProof {
	p := NativeWorkerLaunchRecoveryProof{Scope: local.Scope, Profile: local.Profile, ProfileFingerprint: local.ProfileFingerprint, OriginalOwnershipID: local.OriginalOwnershipID}
	if local.LaunchBoot != nil {
		p.LaunchBoot = *local.LaunchBoot
	}
	p.DeathProof = transport.NativeWorkerRecoveryDeathProof{Kind: "prior_launch_boot", LaunchBoot: p.LaunchBoot}
	return p
}

// The fence has already committed before this function takes the original
// lifetime lock. No journal is opened, and no SQLite transaction spans the lock.
func (r *NativeWorkerRegistry) preparePriorLaunchBootProof(record NativeWorkerRecovery, serverURL string, readBoot func() (transport.KernelBootEvidence, error)) (NativeWorkerRecovery, error) {
	if record.OriginalGeneration == "" || record.OriginalGeneration != record.LocalGeneration {
		return record, nil
	}
	fenced, err := r.RecoveryTombstoned(record.InstanceID, record.OriginalGeneration)
	if err != nil || !fenced {
		return record, ErrNativeOriginAdmissionDeferred
	}
	local, err := r.Lookup(record.InstanceID)
	if err != nil {
		return record, err
	}
	if local.Ownership != nil && (validateOwnership(local.Scope, local.Spec, local.Profile, local.Ownership) != nil || local.Ownership.ID != record.OwnershipID) {
		return record, ErrNativeObservationConflict
	}
	candidate := record
	candidate.LaunchProof = launchRecoveryClaim(local)
	if record.LaunchProof != (NativeWorkerLaunchRecoveryProof{}) && candidate.LaunchProof != record.LaunchProof {
		return record, ErrNativeObservationConflict
	}
	if local.LaunchState != "launching" && local.LaunchState != "launched" || local.Scope.ServerURL != serverURL || !validLaunchRecoveryProof(candidate) {
		return record, nil
	}
	lock, err := sessionworker.AcquireWorkerLifetimeLock(local.Dir)
	if err != nil {
		return record, ErrNativeOriginAdmissionDeferred
	}
	defer lock.Close()
	exact, err := r.Lookup(record.InstanceID)
	if err != nil {
		return record, err
	}
	if exact.Dir != local.Dir || launchRecoveryClaim(exact) != candidate.LaunchProof || exact.LaunchState != local.LaunchState {
		return record, ErrNativeObservationConflict
	}
	bootstrap, key, err := sessionworker.LoadControllerBootstrap(exact.Dir, candidate.LaunchProof.Scope)
	clear(key)
	if err != nil || sessionworker.NativeProfileFingerprint(bootstrap.Native) != candidate.LaunchProof.ProfileFingerprint {
		return record, ErrNativeObservationConflict
	}
	current, err := readBoot()
	if err != nil || !candidate.provesPriorLaunchBoot(current) {
		return record, nil
	}
	// The immutable payload is replaced only once, by exact byte CAS. Concurrent
	// retries may accept only the same frozen claim and proof.
	r.mu.Lock()
	defer r.mu.Unlock()
	stored, err := r.LookupRecovery(record.RecoveryID)
	if err != nil {
		return record, err
	}
	if stored == candidate {
		return stored, nil
	}
	if stored != record {
		return record, ErrNativeObservationConflict
	}
	updated := candidate
	updated.Phase = "prepared"
	var before []byte
	if err = r.db.QueryRow(`SELECT payload FROM native_worker_recoveries WHERE recovery_id=?`, record.RecoveryID).Scan(&before); err != nil {
		return record, err
	}
	var immutable NativeWorkerRecovery
	if json.Unmarshal(before, &immutable) != nil || immutable != record {
		return record, ErrNativeObservationConflict
	}
	after, err := json.Marshal(updated)
	if err != nil {
		return record, err
	}
	result, err := r.db.Exec(`UPDATE native_worker_recoveries SET payload=? WHERE recovery_id=? AND payload=? AND phase='prepared'`, after, record.RecoveryID, before)
	if err != nil {
		return record, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return record, err
	}
	if count != 1 {
		return record, errors.New("native recovery launch proof conflict")
	}
	return candidate, nil
}
