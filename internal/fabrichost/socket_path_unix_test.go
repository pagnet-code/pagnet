//go:build linux || darwin

package fabrichost

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/pagnet-code/pagnet/fabric"
	"golang.org/x/sys/unix"
)

func TestExactPlatformSocketPathBoundaryAndEarlyOverlongRejection(t *testing.T) {
	config, _ := fixture(t)
	parent := filepath.Dir(config.SocketPath)
	maximum := len(unix.RawSockaddrUnix{}.Path) - 1
	path := filepath.Join(parent, strings.Repeat("s", maximum-len(parent)-1))
	if len(path) != maximum {
		t.Fatal("fixture boundary differs")
	}
	listener, release, e := listenPrivate(path)
	if e != nil {
		t.Fatal("exact kernel boundary rejected", e)
	}
	connection, e := net.Dial("unix", path)
	if e != nil {
		t.Fatal("kernel boundary connection", e)
	}
	connection.Close()
	listener.Close()
	release()
	before, e := os.ReadDir(parent)
	if e != nil {
		t.Fatal(e)
	}
	overlong := path + "x"
	config.SocketPath = overlong
	for _, call := range []func() error{
		func() error { _, e := Start(t.Context(), config); return e },
		func() error {
			_, _, e := DialProtocol(t.Context(), overlong, Authentication{Type: "fabric.auth", Mode: "owner"}, Protocol)
			return e
		},
		func() error { _, _, e := listenPrivate(overlong); return e },
		func() error { return ValidateSocketPath(strings.Repeat("é", maximum/2+1)) },
	} {
		e := call()
		var typed *fabric.Error
		if !errors.As(e, &typed) || typed.Code != fabric.CodeInvalidInput || !strings.Contains(typed.Message, "shorter socket path") {
			t.Fatal("overlong path misclassified", e)
		}
	}
	after, e := os.ReadDir(parent)
	if e != nil {
		t.Fatal(e)
	}
	entryNames := func(entries []os.DirEntry) []string {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		return names
	}
	if !reflect.DeepEqual(entryNames(before), entryNames(after)) {
		t.Fatal("rejected path wrote private listener state")
	}
	// Valid length never grants permission: the exact private parent mode guard
	// remains authoritative, with no fallback to an insecure parent.
	if e = os.Chmod(parent, 0755); e != nil {
		t.Fatal(e)
	}
	defer os.Chmod(parent, 0700)
	if _, _, e = listenPrivate(config.SocketPath[:maximum]); e == nil {
		t.Fatal("nonprivate parent accepted")
	}
}
