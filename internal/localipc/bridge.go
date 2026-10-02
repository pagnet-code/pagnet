// Package localipc gives every local bridge consumer the same socket address.
package localipc

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

const BridgeSocketName = "pagnetd.sock"

// BridgeSocketPath preserves normal state-directory sockets. Darwin's Unix
// socket sockaddr has 104 bytes including its terminator; long state paths
// instead use a private checked directory and a full canonical-path digest.
func BridgeSocketPath(stateDir string) (string, error) {
	path := filepath.Join(stateDir, BridgeSocketName)
	if runtime.GOOS != "darwin" || len(path) < 104 {
		return path, nil
	}
	root, err := filepath.EvalSymlinks("/tmp")
	if err != nil {
		return "", fmt.Errorf("resolve local IPC directory: %w", err)
	}
	return shortBridgeSocketPath(stateDir, filepath.Join(root, fmt.Sprintf("pagnet-%d", os.Getuid())), 104)
}

func shortBridgeSocketPath(stateDir, privateDir string, limit int) (string, error) {
	return shortNamedSocketPath(stateDir, privateDir, BridgeSocketName, "", limit)
}

func shortNamedSocketPath(stateDir, privateDir, name, domain string, limit int) (string, error) {
	absolute, err := filepath.Abs(stateDir)
	if err != nil {
		return "", err
	}
	canonical, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", fmt.Errorf("resolve bridge state directory: %w", err)
	}
	direct := filepath.Join(canonical, name)
	if len(direct) < limit {
		return direct, nil
	}
	sum := sha256.Sum256([]byte(domain + canonical))
	path := filepath.Join(privateDir, hex.EncodeToString(sum[:])+".sock")
	if len(path) >= limit {
		return "", fmt.Errorf("private bridge socket path exceeds platform limit")
	}
	if err := os.Mkdir(privateDir, 0700); err != nil && !os.IsExist(err) {
		return "", fmt.Errorf("create private IPC directory: %w", err)
	}
	info, err := os.Lstat(privateDir)
	if err != nil {
		return "", err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
		return "", fmt.Errorf("IPC directory must be an owner-only real directory")
	}
	if err := checkDirectoryOwner(info); err != nil {
		return "", err
	}
	return path, nil
}
