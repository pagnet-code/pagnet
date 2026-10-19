//go:build linux

package proc

import (
	"io"
	"os"
)

// ReadBootIdentity reads the kernel boot UUID. It never substitutes a process
// start time, hostname, or random value when the kernel identity is unavailable.
func ReadBootIdentity() (BootIdentity, error) {
	return readLinuxBootIdentity(func(path string) ([]byte, error) {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		return io.ReadAll(io.LimitReader(f, 65))
	})
}
