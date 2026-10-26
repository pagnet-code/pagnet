//go:build !linux && !darwin

package daemon

import (
	"context"
	"errors"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

var errNativeWorkerPlatform = errors.New("independent native workers require Linux or macOS; use a Linux environment on this platform")

type NativeWorkerRecord struct {
	Scope                                            sessionworker.Scope
	Dir                                              string
	Spec                                             sessionworker.NativeSpec
	Profile, ProfileFingerprint, OriginalOwnershipID string
	Ownership                                        *transport.NativeWorkerOwnership
	LaunchState                                      string
}
type NativeWorkerRegistry struct{}

func OpenNativeWorkerRegistry(string) (*NativeWorkerRegistry, error) {
	return nil, errNativeWorkerPlatform
}
func (*NativeWorkerRegistry) Close() error                   { return nil }
func (*NativeWorkerRegistry) Dir(sessionworker.Scope) string { return "" }
func (*NativeWorkerRegistry) Owns(string) bool               { return true }
func (*NativeWorkerRegistry) Lookup(string) (NativeWorkerRecord, error) {
	return NativeWorkerRecord{}, errNativeWorkerPlatform
}
func (*NativeWorkerRegistry) list(bool) ([]NativeWorkerRecord, error) {
	return nil, errNativeWorkerPlatform
}
func (*NativeWorkerRegistry) List() ([]NativeWorkerRecord, error) {
	return nil, errNativeWorkerPlatform
}
func (*NativeWorkerRegistry) Reserve(sessionworker.Scope, sessionworker.NativeSpec, string, string) (NativeWorkerRecord, error) {
	return NativeWorkerRecord{}, errNativeWorkerPlatform
}
func (*NativeWorkerRegistry) BindOwnership(NativeWorkerRecord, transport.NativeWorkerOwnership) error {
	return errNativeWorkerPlatform
}
func EnsureNativeWorker(context.Context, *NativeWorkerRegistry, NativeWorkerRecord, string, []string, string) error {
	return errNativeWorkerPlatform
}

type nativeWorkerGC struct{ Phase string }

func (*NativeWorkerRegistry) lookupGC(string) (nativeWorkerGC, error) {
	return nativeWorkerGC{}, errNativeWorkerPlatform
}
func (*NativeWorkerRegistry) ordinarySourceDrainAdmission(string) error {
	return errNativeWorkerPlatform
}

func (*NativeWorkerRegistry) LookupRecovery(string) (NativeWorkerRecovery, error) {
	return NativeWorkerRecovery{}, errNativeWorkerPlatform
}
func (*NativeWorkerRegistry) RecoveryTombstoned(string, string) (bool, error) {
	return true, errNativeWorkerPlatform
}
func (*NativeWorkerRegistry) checkRecoveryFence(string, string) error { return errNativeWorkerPlatform }
func (*NativeWorkerRegistry) PrepareRecovery(NativeWorkerRecovery) (NativeWorkerRecovery, error) {
	return NativeWorkerRecovery{}, errNativeWorkerPlatform
}
func (*NativeWorkerRegistry) AdvanceRecoveryPhase(string, string, string) error {
	return errNativeWorkerPlatform
}

func (*NativeWorkerRegistry) pendingCollectedRecoveries() ([]NativeWorkerRecovery, error) {
	return nil, errNativeWorkerPlatform
}
func (*NativeWorkerRegistry) confirmRecoveryCleaned(string) error { return errNativeWorkerPlatform }
func (*NativeWorkerRegistry) collectRecovery(NativeWorkerRecovery) error {
	return errNativeWorkerPlatform
}
