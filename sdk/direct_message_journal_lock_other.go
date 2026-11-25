//go:build !linux && !darwin

package sdk

import "errors"

func (k *keyring) lockDirectMessages() (func(), error) {
	return nil, errors.New("sdk: durable direct message V2 locking unsupported on this platform")
}
