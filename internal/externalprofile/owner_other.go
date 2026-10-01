//go:build !unix

package externalprofile

import (
	"errors"
	"os"
)

func owner(os.FileInfo) error {
	return errors.New("private external profiles require verified file ownership support on this platform")
}
