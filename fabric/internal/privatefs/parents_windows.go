//go:build windows

package privatefs

import "golang.org/x/sys/windows"

func verifyOwnedParent(path string) error {
	h, e := privateHandle(path, windows.GENERIC_READ, windows.OPEN_EXISTING, true)
	if e != nil {
		return e
	}
	return windows.CloseHandle(h)
}

func CheckPrivateDirectory(path string) error { return verifyOwnedParent(path) }
