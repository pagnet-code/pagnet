package sessionworker

import "github.com/pagnet-code/pagnet/internal/localipc"

// SocketPath is the common discovery address for the original owned worker.
// Authentication and kernel peer identity remain mandatory after discovery.
func SocketPath(dir string) (string, error) { return localipc.WorkerSocketPath(dir) }

func NativeSocketPath(dir string) (string, error) {
	return localipc.OwnedWorkerSocketPath(dir, "native.sock")
}
