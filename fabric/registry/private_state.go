package registry

import (
	"io"

	"github.com/pagnet-code/pagnet/fabric/internal/privatefs"
)

func lockDirectory(dir string) (io.Closer, error)         { return privatefs.Acquire(dir, "writer.lock") }
func readPrivate(path string, bound int) ([]byte, error)  { return privatefs.ReadFile(path, bound) }
func checkPrivateDatabase(path string, bound int64) error { return privatefs.CheckFile(path, bound) }
func createPrivateDirectory(dir string) error             { return privatefs.CreateDirectory(dir) }
func publishPrivate(from, to string) error                { return privatefs.Publish(from, to) }
func syncDirectory(dir string) error {
	return privatefs.SyncDirectory(dir, "genesis.key", "registry.sqlite")
}
