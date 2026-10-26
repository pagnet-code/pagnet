//go:build !linux && !darwin && !freebsd && !openbsd && !netbsd && !dragonfly

package main

import "errors"

func textBridgePrivateDir(string) error {
	return errors.New("text bridge private storage is unsupported on this platform")
}

func textBridgeReadPrivate(string, int64) ([]byte, error) {
	return nil, errors.New("text bridge private storage is unsupported on this platform")
}

func textBridgeLock(string) (func(), error) {
	return nil, errors.New("text bridge private locking is unsupported on this platform")
}
