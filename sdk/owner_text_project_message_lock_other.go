//go:build !linux && !darwin

package sdk

import "errors"

func (k *keyring) lockOwnerTextProjectMessages(principal string) (func(), error) {
	return nil, errors.New("sdk: durable owner text project message locking unsupported on this platform")
}
