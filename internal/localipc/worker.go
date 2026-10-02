package localipc

import (
	"fmt"
	"os"
	"path/filepath"
)

// WorkerSocketPath preserves existing short endpoints. Long paths use the same
// owner-only namespace as the bridge, with a separate full-digest domain. The
// fixed /tmp root is canonicalized rather than inherited from controller TMPDIR.
func WorkerSocketPath(dir string) (string, error) {
	return OwnedWorkerSocketPath(dir, "controller.sock")
}

// OwnedWorkerSocketPath only accepts the two fixed, authenticated worker endpoints.
func OwnedWorkerSocketPath(dir, name string) (string, error) {
	if name != "controller.sock" && name != "native.sock" {
		return "", fmt.Errorf("unknown worker endpoint")
	}
	root, err := filepath.EvalSymlinks("/tmp")
	if err != nil {
		return "", fmt.Errorf("resolve worker IPC root: %w", err)
	}
	return shortNamedSocketPath(dir, filepath.Join(root, fmt.Sprintf("pagnet-%d", os.Getuid())), name, "pagnet-worker-v1\x00"+name+"\x00", 104)
}
