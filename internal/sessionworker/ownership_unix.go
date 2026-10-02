//go:build linux || darwin

package sessionworker

import (
	"context"
	"errors"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// Hold one exclusive worker owner for the whole process lifetime. Opening the
// same journal while another worker is live must not turn its admitted work
// into crash uncertainty or race two native command owners.
func acquireOwnership(dir string) (io.Closer, error) {
	dirFD, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(dirFD)
	var dirStat unix.Stat_t
	if err = unix.Fstat(dirFD, &dirStat); err != nil {
		return nil, err
	}
	if dirStat.Uid != uint32(os.Getuid()) || dirStat.Mode&0777 != 0700 {
		return nil, errors.New("worker state directory has another owner or unsafe permissions")
	}
	fd, err := unix.Open(filepath.Join(dir, "worker.lock"), unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "worker.lock")
	var stat unix.Stat_t
	if err = unix.Fstat(fd, &stat); err != nil {
		_ = f.Close()
		return nil, err
	}
	if stat.Uid != uint32(os.Getuid()) || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0777 != 0600 {
		_ = f.Close()
		return nil, errors.New("worker ownership lock is not a private owner file")
	}
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, ErrWorkerOwned
		}
		return nil, err
	}
	return f, nil
}

func removeStaleSocket(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket == 0 {
		return errors.New("worker controller path is not a stale socket")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Getuid()) {
		return errors.New("worker controller socket belongs to another owner")
	}
	return os.Remove(path)
}
func privateSocket(path string) error { return os.Chmod(path, 0600) }

func readPrivateFile(path string, bound int) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "private-worker-file")
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Getuid()) || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() < 0 || info.Size() > int64(bound) {
		return nil, errors.New("worker bootstrap file is not private or exceeds bound")
	}
	data, err := io.ReadAll(io.LimitReader(f, int64(bound)+1))
	if err != nil || len(data) > bound {
		return nil, errors.New("worker bootstrap file exceeds bound")
	}
	return data, nil
}
func workerSignals(ctx context.Context) (context.Context, context.CancelFunc) {
	return signal.NotifyContext(ctx, syscall.SIGTERM)
}
