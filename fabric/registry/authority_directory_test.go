package registry

import (
	"context"
	"path/filepath"
	"testing"
)

func TestCurrentAuthorityDirectoryPinsActualRetainedRootAndFailsClosed(t *testing.T) {
	for _, mode := range []string{"closed", "missing", "substituted", "oversized", "cancelled", "nil-context"} {
		t.Run(mode, func(t *testing.T) {
			s, _, dir := fixture(t)
			ctx := context.Background()
			actual, err := s.CurrentAuthorityDirectory(ctx)
			if err != nil || actual != dir || !filepath.IsAbs(actual) {
				t.Fatal("private sandbox root differs from actual retained store", err)
			}
			switch mode {
			case "closed":
				err = s.Close()
			case "missing":
				_, err = s.db.Exec("DELETE FROM identity")
			case "substituted":
				_, err = s.db.Exec("UPDATE identity SET genesis=?", []byte(`{"body":{},"signature":""}`))
			case "oversized":
				_, err = s.db.Exec("UPDATE identity SET genesis=?", make([]byte, 65537))
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "nil-context":
				ctx = nil
			}
			if err != nil {
				t.Fatal(err)
			}
			if returned, err := s.CurrentAuthorityDirectory(ctx); err == nil || returned != "" {
				t.Fatal("unavailable retained root disclosed usable sandbox authority")
			}
		})
	}
}
