//go:build !unix

package runtimeprofile

import (
	"errors"
	"os"
)

// Profile files may contain provider credentials: require a verified private ACL
// implementation before accepting them on a platform without Unix ownership.
func validateOwner(os.FileInfo) error {
	return errors.New("host runtime profiles require supported private file ownership on this platform")
}
