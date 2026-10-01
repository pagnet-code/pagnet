//go:build darwin

package daemon

import (
	"errors"
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

func bridgeIsolationMode() string { return bridgeIsolationProcessBound }
func runtimeSandboxMode() string  { return sandboxModeUnsupportedPlatform }

func readDarwinBridgeProcess(pid int) (bridgeProcessSnapshot, error) {
	info, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return bridgeProcessSnapshot{}, err
	}
	// XNU's process states: 0 is absent, SZOMB(5) has no executing process.
	// The start timestamp and UID are kernel records, not proc environment data.
	if info.Proc.P_pid != int32(pid) || info.Proc.P_stat == 0 || info.Proc.P_stat == 5 || info.Proc.P_starttime.Sec <= 0 || info.Proc.P_starttime.Usec < 0 || info.Proc.P_starttime.Usec >= 1000000 {
		return bridgeProcessSnapshot{}, errors.New("process absent, exited or has no valid start identity")
	}
	return bridgeProcessSnapshot{PID: pid, Parent: int(info.Eproc.Ppid), UID: info.Eproc.Ucred.Uid, Start: info.Proc.P_starttime.Sec*1000000 + int64(info.Proc.P_starttime.Usec)}, nil
}

// Darwin names the socket's actual peer through LOCAL_PEERPID and its owner
// through LOCAL_PEERCRED. Missing kernel information always rejects; the nonce
// is still required, but never substitutes for process ancestry on macOS.
func (d *Daemon) verifyBridgePeer(c net.Conn, rootPID int) error {
	connection, ok := c.(*net.UnixConn)
	if !ok {
		return errors.New("bridge connection is not a Unix socket")
	}
	raw, err := connection.SyscallConn()
	if err != nil {
		return fmt.Errorf("peer credentials unavailable: %w", err)
	}
	var pid int
	var credentials *unix.Xucred
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		credentials, socketErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if socketErr == nil {
			pid, socketErr = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
		}
	}); err != nil {
		return fmt.Errorf("peer credentials unavailable: %w", err)
	}
	if socketErr != nil {
		return fmt.Errorf("peer credentials unavailable: %w", socketErr)
	}
	// XUCRED_VERSION is 0 in XNU's bsd/sys/ucred.h. Reject future unknown formats.
	if credentials == nil || credentials.Version != 0 || credentials.Uid != uint32(os.Getuid()) || pid <= 0 {
		return errors.New("peer kernel credentials do not identify the daemon owner")
	}
	return verifyKernelProcessTree(pid, rootPID, credentials.Uid, readDarwinBridgeProcess)
}
