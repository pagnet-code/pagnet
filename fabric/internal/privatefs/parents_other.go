//go:build !linux && !darwin && !windows

package privatefs

import "errors"

func verifyOwnedParent(string) error {
	return errors.New("private installation parent verification is unsupported on this platform")
}

func CheckPrivateDirectory(string) error {
	return errors.New("private directory verification is unsupported on this platform")
}
