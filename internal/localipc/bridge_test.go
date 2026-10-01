//go:build unix

package localipc

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestLongBridgePathPrivateStableAndConnectable(t *testing.T) {
	root, err := os.MkdirTemp("/tmp", "p-ipc-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	state := filepath.Join(root, strings.Repeat("a", 90), strings.Repeat("b", 90))
	if err = os.MkdirAll(state, 0700); err != nil {
		t.Fatal(err)
	}
	private := filepath.Join(root, "ipc")
	got, err := shortBridgeSocketPath(state, private, 104)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) >= 104 {
		t.Fatalf("oversized path %d", len(got))
	}
	alias := filepath.Join(root, "alias")
	if err = os.Symlink(state, alias); err != nil {
		t.Fatal(err)
	}
	same, err := shortBridgeSocketPath(alias, private, 104)
	if err != nil || same != got {
		t.Fatalf("aliases differ: %q %v", same, err)
	}
	second := filepath.Join(root, strings.Repeat("c", 90))
	if err = os.Mkdir(second, 0700); err != nil {
		t.Fatal(err)
	}
	other, err := shortBridgeSocketPath(second, private, 104)
	if err != nil || other == got {
		t.Fatalf("distinct states collide: %q %v", other, err)
	}
	info, _ := os.Lstat(private)
	if info.Mode().Perm() != 0700 {
		t.Fatal("directory is not private")
	}
	listener, err := net.Listen("unix", got)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.Dial("unix", got)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	server.Close()
}

func TestLongBridgePathRejectsUnsafeDirectories(t *testing.T) {
	for _, kind := range []string{"symlink", "public", "file", "too long"} {
		t.Run(kind, func(t *testing.T) {
			root, err := os.MkdirTemp("/tmp", "p-ipc-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(root)
			state := filepath.Join(root, strings.Repeat("s", 100))
			if err = os.Mkdir(state, 0700); err != nil {
				t.Fatal(err)
			}
			private := filepath.Join(root, "ipc")
			switch kind {
			case "symlink":
				if err = os.Symlink(root, private); err != nil {
					t.Fatal(err)
				}
			case "public":
				if err = os.Mkdir(private, 0755); err != nil {
					t.Fatal(err)
				}
			case "file":
				if err = os.WriteFile(private, nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "too long":
				private = filepath.Join(root, strings.Repeat("x", 100))
			}
			if _, err = shortBridgeSocketPath(state, private, 104); err == nil {
				t.Fatal("unsafe directory accepted")
			}
		})
	}
}

func TestPrivateBridgeDirectoryRejectsOtherOwner(t *testing.T) {
	info, err := os.Stat(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	stat.Uid = uint32(os.Getuid()) + 1
	if err = checkDirectoryOwner(info); err == nil {
		t.Fatal("foreign directory owner accepted")
	}
}
