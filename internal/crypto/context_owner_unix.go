//go:build unix

package crypto

import (
	"errors"
	"os"
	"syscall"
)

func validateContextFileOwner(info os.FileInfo) error {
	s, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint32(os.Geteuid()) != s.Uid {
		return errors.New("protected context owner mismatch")
	}
	return nil
}
