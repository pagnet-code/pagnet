//go:build !linux && !darwin

package sdk

import "errors"

func (k *keyring) lockPairMessages(principal string) (func(), error) {
	return nil, errors.New("sdk: durable pair message locking unsupported on this platform")
}
