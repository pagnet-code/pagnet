//go:build !linux && !darwin

package proc

import "errors"

// ReadBootIdentity fails closed on platforms without a kernel boot identity
// implementation. An empty identity must never be treated as a known boot.
func ReadBootIdentity() (BootIdentity, error) {
	return BootIdentity{}, errors.New("proc: kernel boot identity unsupported on this platform")
}
