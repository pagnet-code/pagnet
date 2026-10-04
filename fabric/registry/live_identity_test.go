package registry

import (
	"context"
	"testing"
)

func TestCurrentRootRejectsClosedOrSubstitutedRetainedIdentity(t *testing.T) {
	for _, mode := range []string{"closed", "substituted", "oversized", "missing"} {
		t.Run(mode, func(t *testing.T) {
			s, _, _ := fixture(t)
			ctx := context.Background()
			before, err := s.CurrentAuthorityIdentity(ctx)
			if err != nil || before.Namespace != s.Namespace() {
				t.Fatal(err)
			}
			switch mode {
			case "closed":
				s.Close()
			case "substituted":
				_, err = s.db.ExecContext(ctx, "UPDATE identity SET genesis=? WHERE singleton=1", []byte(`{"body":{},"signature":""}`))
			case "oversized":
				_, err = s.db.ExecContext(ctx, "UPDATE identity SET genesis=? WHERE singleton=1", make([]byte, 65537))
			case "missing":
				_, err = s.db.ExecContext(ctx, "DELETE FROM identity WHERE singleton=1")
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.CurrentAuthorityIdentity(ctx); err == nil {
				t.Fatal("historical public root snapshot granted current authentication")
			}
			if s.AuthorityIdentity().Namespace != before.Namespace {
				t.Fatal("public historical verification material changed")
			}
		})
	}
}
