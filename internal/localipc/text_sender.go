package localipc

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const TextSenderSocketName = "text-sender.sock"

// TextSenderSocketPath uses a fixed endpoint and a separate digest domain from
// both the agent bridge and worker sockets. Callers must check private ancestors.
func TextSenderSocketPath(stateDir string) (string, error) {
	root, err := filepath.EvalSymlinks("/tmp")
	if err != nil {
		return "", err
	}
	return shortNamedSocketPath(stateDir, filepath.Join(root, fmt.Sprintf("pagnet-%d", os.Getuid())), TextSenderSocketName, "pagnet-text-sender-v1\x00", 104)
}

func CheckTextSenderSocket(path string) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0600 {
		return nil, errors.New("sender IPC requires an owner-only real socket")
	}
	if err := checkDirectoryOwner(info); err != nil {
		return nil, err
	}
	return info, nil
}
