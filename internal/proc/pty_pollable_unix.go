//go:build unix

package proc

import (
	"os"
	"os/exec"

	"github.com/creack/pty"
	"golang.org/x/sys/unix"
)

// pollablePTYMaster transfers ownership before the master is published. Some
// PTY openers use a blocking NewFile; others use OpenFile, whose Fd method
// switches it back to blocking during resize. Wrapping an already-nonblocking
// descriptor in NewFile avoids both hazards and makes deadlines cancellable.
func pollablePTYMaster(master *os.File) (*os.File, error) {
	raw, err := master.SyscallConn()
	if err != nil {
		return nil, err
	}
	duplicate := -1
	var dupErr error
	err = raw.Control(func(fd uintptr) {
		duplicate, dupErr = unix.FcntlInt(fd, unix.F_DUPFD_CLOEXEC, 0)
	})
	if err != nil {
		return nil, err
	}
	if dupErr != nil {
		return nil, dupErr
	}
	if err := unix.SetNonblock(duplicate, true); err != nil {
		_ = unix.Close(duplicate)
		return nil, err
	}
	result := os.NewFile(uintptr(duplicate), master.Name())
	_ = master.Close()
	return result, nil
}

func startPollablePTY(cmd *exec.Cmd, size *pty.Winsize) (*os.File, error) {
	master, slave, err := pty.Open()
	if err != nil {
		return nil, err
	}
	defer slave.Close()
	normalized, err := pollablePTYMaster(master)
	if err != nil {
		_ = master.Close()
		return nil, err
	}
	master = normalized
	if err := pty.Setsize(master, size); err != nil {
		_ = master.Close()
		return nil, err
	}
	if cmd.Stdin == nil {
		cmd.Stdin = slave
	}
	if cmd.Stdout == nil {
		cmd.Stdout = slave
	}
	if cmd.Stderr == nil {
		cmd.Stderr = slave
	}
	cmd.SysProcAttr = SessionAttrs()
	if err := cmd.Start(); err != nil {
		_ = master.Close()
		return nil, err
	}
	return master, nil
}
