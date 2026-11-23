//go:build !linux && !darwin

package sdk

import "errors"

func (k *keyring) lockPendingDirectChannels() (func(), error) {
	return nil, errors.New("sdk: durable pending direct channel locking unsupported on this platform")
}
