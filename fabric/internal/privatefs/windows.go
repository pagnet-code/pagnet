//go:build windows

package privatefs

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

func currentOwner() (*windows.SID, error) {
	u, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		return nil, e
	}
	return u.User.Sid, nil
}
func CreateDirectory(dir string) error {
	sid, e := currentOwner()
	if e != nil {
		return e
	}
	sd, e := windows.SecurityDescriptorFromString("O:" + sid.String() + "D:P(A;OICI;FA;;;" + sid.String() + ")")
	if e != nil {
		return e
	}
	p, e := windows.UTF16PtrFromString(dir)
	if e != nil {
		return e
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	return windows.CreateDirectory(p, &sa)
}
func privateHandle(path string, access, creation uint32, directory bool) (windows.Handle, error) {
	p, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return 0, e
	}
	flags := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if directory {
		flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
	}
	h, e := windows.CreateFile(p, access|windows.READ_CONTROL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, creation, flags, 0)
	if e != nil {
		return 0, e
	}
	if e = verifyHandle(h, directory); e != nil {
		windows.CloseHandle(h)
		return 0, e
	}
	return h, nil
}
func verifyHandle(h windows.Handle, directory bool) error {
	var info windows.ByHandleFileInformation
	if e := windows.GetFileInformationByHandle(h, &info); e != nil {
		return e
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || (info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != directory {
		return errors.New("private state file is a reparse point or wrong file type")
	}
	sd, e := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if e != nil {
		return e
	}
	sid, e := currentOwner()
	if e != nil {
		return e
	}
	owner, _, e := sd.Owner()
	if e != nil || owner == nil || !owner.Equals(sid) {
		return errors.New("private state file has another Windows owner")
	}
	acl, _, e := sd.DACL()
	if e != nil || acl == nil || acl.AceCount == 0 {
		return errors.New("private state file lacks private Windows ACL")
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if e = windows.GetAce(acl, i, &ace); e != nil {
			return e
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || !(*windows.SID)(unsafe.Pointer(&ace.SidStart)).Equals(sid) {
			return errors.New("private state Windows ACL grants another principal")
		}
	}
	return nil
}

type windowsWriter struct {
	handle     windows.Handle
	overlapped windows.Overlapped
}

func (w *windowsWriter) Close() error {
	e := windows.UnlockFileEx(w.handle, 0, 1, 0, &w.overlapped)
	closeErr := windows.CloseHandle(w.handle)
	if e != nil {
		return e
	}
	return closeErr
}
func Acquire(dir string, lockName string) (io.Closer, error) {
	h, e := privateHandle(dir, windows.FILE_READ_ATTRIBUTES, windows.OPEN_EXISTING, true)
	if e != nil {
		return nil, e
	}
	windows.CloseHandle(h)
	h, e = privateHandle(filepath.Join(dir, lockName), windows.GENERIC_READ|windows.GENERIC_WRITE, windows.OPEN_ALWAYS, false)
	if e != nil {
		return nil, e
	}
	w := &windowsWriter{handle: h}
	if e = windows.LockFileEx(h, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &w.overlapped); e != nil {
		windows.CloseHandle(h)
		return nil, errors.New("private state already has a writer or Windows locking failed")
	}
	return w, nil
}
func ReadFile(path string, bound int) ([]byte, error) {
	h, e := privateHandle(path, windows.GENERIC_READ, windows.OPEN_EXISTING, false)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(h), "private state file")
	defer f.Close()
	info, e := f.Stat()
	if e != nil {
		return nil, e
	}
	if info.Size() < 0 || info.Size() > int64(bound) {
		return nil, errors.New("private state file exceeds bound")
	}
	b, e := io.ReadAll(io.LimitReader(f, int64(bound)+1))
	if e != nil || len(b) > bound {
		return nil, errors.New("private state file read exceeds bound")
	}
	return b, nil
}
func CheckFile(path string, bound int64) error {
	h, e := privateHandle(path, windows.GENERIC_READ, windows.OPEN_EXISTING, false)
	if e != nil {
		return e
	}
	f := os.NewFile(uintptr(h), "private state database")
	defer f.Close()
	info, e := f.Stat()
	if e != nil {
		return e
	}
	if info.Size() < 0 || info.Size() > bound {
		return errors.New("private state database exceeds configured bound")
	}
	return nil
}

// MOVEFILE_WRITE_THROUGH publishes the already flushed same-directory private
// key without replacing an existing identity. No POSIX directory-fsync claim.
// https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexw
func Publish(from, to string) error {
	a, e := windows.UTF16PtrFromString(from)
	if e != nil {
		return e
	}
	b, e := windows.UTF16PtrFromString(to)
	if e != nil {
		return e
	}
	return windows.MoveFileEx(a, b, windows.MOVEFILE_WRITE_THROUGH)
}

// Windows flushes the committed identity files through verified writable handles.
// An unsupported filesystem flush fails bootstrap; it is never a no-op success.
func SyncDirectory(dir string, names ...string) error {
	if len(names) == 0 {
		return errors.New("Windows private metadata flush needs explicit files")
	}
	for _, name := range names {
		path := filepath.Join(dir, name)
		if _, e := os.Lstat(path); e != nil {
			return e
		}
		h, e := privateHandle(path, windows.GENERIC_WRITE, windows.OPEN_EXISTING, false)
		if e != nil {
			return e
		}
		e = windows.FlushFileBuffers(h)
		closeErr := windows.CloseHandle(h)
		if e != nil {
			return e
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}
