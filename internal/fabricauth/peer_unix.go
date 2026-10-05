//go:build linux || darwin

package fabricauth

import (
	"context"
	"github.com/pagnet-code/pagnet/internal/localpeer"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"path/filepath"
)

func peer(ctx context.Context, conn *net.UnixConn, path string) (localpeer.ProcessSnapshot, error) {
	if ctx == nil || ctx.Err() != nil || conn == nil {
		return localpeer.ProcessSnapshot{}, denied()
	}
	addr, ok := conn.LocalAddr().(*net.UnixAddr)
	if !ok || addr.Name != path || !filepath.IsAbs(path) {
		return localpeer.ProcessSnapshot{}, denied()
	}
	dir, e := unix.Open(filepath.Dir(path), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return localpeer.ProcessSnapshot{}, denied()
	}
	defer unix.Close(dir)
	var directory, socket unix.Stat_t
	if unix.Fstat(dir, &directory) != nil || directory.Uid != uint32(os.Geteuid()) || directory.Mode&0777 != 0700 || unix.Lstat(path, &socket) != nil || socket.Uid != uint32(os.Geteuid()) || socket.Mode&unix.S_IFMT != unix.S_IFSOCK || socket.Mode&0777 != 0600 {
		return localpeer.ProcessSnapshot{}, denied()
	}
	pid, uid, e := localpeer.Owner(conn)
	if e != nil || uid != uint32(os.Geteuid()) {
		return localpeer.ProcessSnapshot{}, denied()
	}
	raw, e := conn.SyscallConn()
	if e != nil {
		return localpeer.ProcessSnapshot{}, denied()
	}
	var liveErr error
	e = raw.Control(func(fd uintptr) {
		liveErr = checkSocketLiveness(ctx, int(fd), unix.Poll, func(fd int, bytes []byte, flags int) (int, error) {
			n, _, err := unix.Recvfrom(fd, bytes, flags)
			return n, err
		})
	})
	if e != nil || liveErr != nil {
		return localpeer.ProcessSnapshot{}, denied()
	}
	process, e := localpeer.ReadProcess(pid)
	if e != nil || process.UID != uid || process.Start <= 0 {
		return localpeer.ProcessSnapshot{}, denied()
	}
	endPID, endUID, e := localpeer.Owner(conn)
	if e != nil || endPID != pid || endUID != uid || ctx.Err() != nil {
		return localpeer.ProcessSnapshot{}, denied()
	}
	return process, nil
}
