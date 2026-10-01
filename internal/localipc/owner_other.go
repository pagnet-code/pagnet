//go:build !unix

package localipc

import (
	"errors"
	"os"
)

func checkDirectoryOwner(os.FileInfo) error {
	return errors.New("private Unix IPC directory ownership is unsupported on this platform")
}
