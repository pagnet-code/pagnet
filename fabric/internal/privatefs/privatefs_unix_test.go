//go:build linux || darwin

package privatefs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateStateLockAndNoFollow(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	if e := CreateDirectory(dir); e != nil {
		t.Fatal(e)
	}
	lock, e := Acquire(dir, "writer.lock")
	if e != nil {
		t.Fatal(e)
	}
	if other, e := Acquire(dir, "writer.lock"); e == nil {
		other.Close()
		t.Fatal("concurrent writer acquired")
	}
	if e = lock.Close(); e != nil {
		t.Fatal(e)
	}
	lock, e = Acquire(dir, "writer.lock")
	if e != nil {
		t.Fatal(e)
	}
	defer lock.Close()
	p := filepath.Join(dir, "data")
	if e = os.WriteFile(p, []byte("data"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = ReadFile(p, 4); e != nil {
		t.Fatal(e)
	}
	if _, e = ReadFile(p, 3); e == nil {
		t.Fatal("file bound ignored")
	}
	link := filepath.Join(dir, "link")
	if e = os.Symlink(p, link); e != nil {
		t.Fatal(e)
	}
	if _, e = ReadFile(link, 4); e == nil {
		t.Fatal("private reader followed symlink")
	}
	if e = CheckFile(link, 4); e == nil {
		t.Fatal("private DB followed symlink")
	}
	if e = os.Chmod(p, 0644); e != nil {
		t.Fatal(e)
	}
	if _, e = ReadFile(p, 4); e == nil {
		t.Fatal("public file read")
	}
	if e = CheckFile(p, 4); e == nil {
		t.Fatal("public DB admitted")
	}
}
