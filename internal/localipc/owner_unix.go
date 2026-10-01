//go:build unix

package localipc

import (
	"fmt"
	"os"
	"syscall"
)

func checkDirectoryOwner(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Getuid()) {
		return fmt.Errorf("IPC directory is not owned by the current user")
	}
	return nil
}
