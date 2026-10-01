//go:build unix

package main

import (
	"errors"
	"os"
	"syscall"
)

func validateJevKeyFileOwner(stat os.FileInfo) error {
	owner, ok := stat.Sys().(*syscall.Stat_t)
	if !ok || int(owner.Uid) != os.Getuid() {
		return errors.New("TypeSafe key file must be owned by the current user")
	}
	return nil
}

func validateServiceProfileOwner(info os.FileInfo) error {
	if info.Mode().Perm()&0077 != 0 {
		return errors.New("local Jev profile must be private (chmod 600)")
	}
	if err := validateJevKeyFileOwner(info); err != nil {
		return errors.New("local Jev profile must be owned by the current user")
	}
	return nil
}
