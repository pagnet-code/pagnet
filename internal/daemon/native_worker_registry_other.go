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
func (*NativeWorkerRegistry) List() ([]NativeWorkerRecord, error) {
	return nil, errNativeWorkerPlatform
}
func (*NativeWorkerRegistry) Reserve(sessionworker.Scope, sessionworker.NativeSpec, string, string) (NativeWorkerRecord, error) {
	return NativeWorkerRecord{}, errNativeWorkerPlatform
}
func (*NativeWorkerRegistry) BindOwnership(NativeWorkerRecord, transport.NativeWorkerOwnership) error {
	return errNativeWorkerPlatform
}
func EnsureNativeWorker(context.Context, *NativeWorkerRegistry, NativeWorkerRecord, string, []string) error {
	return errNativeWorkerPlatform
}

type nativeWorkerGC struct{ Phase string }

func (*NativeWorkerRegistry) lookupGC(string) (nativeWorkerGC, error) {
	return nativeWorkerGC{}, errNativeWorkerPlatform
}
