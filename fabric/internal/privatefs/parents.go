package privatefs

import (
	"errors"
	"os"
	"path/filepath"
)

// PrepareParents is explicit installation-only preparation of nonsecret parent
// directories. It never creates target itself, changes existing permissions or
// follows symlink/reparse ancestors. The nearest existing ancestor must belong
// to the current operator and deny other unprivileged writers.
func PrepareParents(target string) error {
	if !filepath.IsAbs(target) || filepath.Clean(target) != target || len(target) > 4096 {
		return errors.New("private installation path must be absolute and canonical")
	}
	parent := filepath.Dir(target)
	var missing []string
	anchor := ""
	for path, depth := parent, 0; ; depth++ {
		if depth >= 128 {
			return errors.New("private installation parent nesting exceeds bound")
		}
		info, e := os.Lstat(path)
		if e == nil {
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return errors.New("private installation parent is a link or not a directory")
			}
			if anchor == "" {
				anchor = path
			}
		} else if os.IsNotExist(e) {
			missing = append(missing, path)
		} else {
			return e
		}
		next := filepath.Dir(path)
		if next == path {
			break
		}
		path = next
	}
	if anchor == "" {
		return errors.New("private installation has no existing operator parent")
	}
	if e := verifyOwnedParent(anchor); e != nil {
		return e
	}
	for n := len(missing) - 1; n >= 0; n-- {
		if e := CreateDirectory(missing[n]); e != nil && !os.IsExist(e) {
			return e
		}
		if e := verifyOwnedParent(missing[n]); e != nil {
			return e
		}
	}
	return nil
}
