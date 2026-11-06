//go:build !linux && !darwin && !freebsd && !openbsd && !netbsd && !dragonfly

package inbox

import (
	"errors"
	"os"
)

var errUnsupported = errors.New("inbox: private durable state is unsupported on this platform")

func openDirectory(string) (*os.File, error)              { return nil, errUnsupported }
func acquireLock(*os.File) (*os.File, error)              { return nil, errUnsupported }
func readPrivate(*os.File, string, int64) ([]byte, error) { return nil, errUnsupported }
func writeAtomic(*os.File, string, []byte) error          { return errUnsupported }
func removeTemporary(*os.File, string) error              { return errUnsupported }
