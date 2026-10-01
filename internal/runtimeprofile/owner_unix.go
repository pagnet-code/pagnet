//go:build unix

package runtimeprofile

import (
	"errors"
	"os"
	"syscall"
)

func validateOwner(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0077 != 0 {
		return errors.New("runtime profile file must be owned by this user with mode 0600")
	}
	return nil
}
