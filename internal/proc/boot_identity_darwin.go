//go:build darwin

package proc

import "golang.org/x/sys/unix"

// ReadBootIdentity prefers the kernel boot session UUID, falling back to the
// validated kernel boot timeval with lower quality metadata.
func ReadBootIdentity() (BootIdentity, error) {
	return readDarwinBootIdentity(unix.Sysctl, func(name string) (int64, int64, error) {
		value, err := unix.SysctlTimeval(name)
		if err != nil {
			return 0, 0, err
		}
		return value.Sec, int64(value.Usec), nil
	})
}
