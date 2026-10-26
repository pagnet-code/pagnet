//go:build !linux && !darwin

package sdk

import "errors"

func (k *keyring) lockProjectMessages(principal string) (func(), error) {
	return nil, errors.New("sdk: durable project message locking unsupported on this platform")
}
