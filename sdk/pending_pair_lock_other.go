//go:build !linux && !darwin

package sdk

import "errors"

func (k *keyring) lockPendingPairs() (func(), error) {
	return nil, errors.New("sdk: durable pending pair locking unsupported on this platform")
}
