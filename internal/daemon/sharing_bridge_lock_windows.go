//go:build windows

package daemon

func lockSharingBridge(dir string) (func(), error) { return nil, errWindowsHostUnsupported }
