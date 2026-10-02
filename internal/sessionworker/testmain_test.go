package sessionworker

import (
	"github.com/pagnet-code/pagnet/internal/sandbox"
	"os"
	"testing"
)

// Actual isolated owner subprocess tests use the same private sandbox wrapper
// seam as production pagnet. Without interception a wrapped launch would run
// this Go test suite recursively instead of executing its synthetic runtime.
func TestMain(m *testing.M) {
	if len(os.Args) >= 2 && os.Args[1] == sandbox.Subcommand {
		os.Exit(sandbox.RunWrapperMain(os.Args[2:]))
	}
	os.Exit(m.Run())
}
