//go:build unix

package externalprofile

import (
	"errors"
	"os"
	"syscall"
)

func owner(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Getuid() || info.Mode().Perm()&0077 != 0 {
		return errors.New("external profile must be private and owned by the current user")
	}
	return nil
}
