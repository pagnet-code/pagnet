//go:build linux || darwin

package fabrichost

import (
	"fmt"
	"github.com/pagnet-code/pagnet/fabric"
	"golang.org/x/sys/unix"
)

// ValidateSocketPath checks the native pathname byte bound, including the
// terminating NUL. It never shortens or substitutes an operator-selected path.
func ValidateSocketPath(path string) error {
	maximum := len(unix.RawSockaddrUnix{}.Path) - 1
	if len(path) > maximum {
		return fabric.NewError(fabric.CodeInvalidInput, fmt.Sprintf("Local socket path exceeds the platform limit of %d bytes; choose a shorter socket path", maximum))
	}
	return nil
}
