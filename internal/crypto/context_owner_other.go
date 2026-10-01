//go:build !unix

package crypto

import (
	"errors"
	"os"
)

func validateContextFileOwner(os.FileInfo) error {
	return errors.New("protected context private storage unsupported")
}
