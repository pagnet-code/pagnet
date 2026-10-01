//go:build !unix

package proc

import (
	"github.com/creack/pty"
	"os"
	"os/exec"
)

func pollablePTYMaster(master *os.File) (*os.File, error) { return master, nil }
func startPollablePTY(cmd *exec.Cmd, size *pty.Winsize) (*os.File, error) {
	return pty.StartWithAttrs(cmd, size, SessionAttrs())
}
