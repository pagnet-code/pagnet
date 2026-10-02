package sessionworker

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Real Unix sockets exercise independent viewers and controller lease replacement.
func TestTerminalMultipleViewsShareLeaseButNotDetach(t *testing.T) {
	dir := t.TempDir()
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(dir, "views.sock"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	pair := func() (*net.UnixConn, *net.UnixConn) {
		t.Helper()
		peer, err := net.DialUnix("unix", nil, listener.Addr().(*net.UnixAddr))
		if err != nil {
			t.Fatal(err)
		}
		owned, err := listener.AcceptUnix()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { peer.Close(); owned.Close() })
		return owned, peer
	}
	controller, _ := pair()
	current := &currentController{lease: 1, identity: "controller-A", conn: controller}
	first, _ := pair()
	second, secondPeer := pair()
	if !current.installStream(1, "controller-A", first) || !current.installStream(1, "controller-A", second) {
		t.Fatal("second viewer evicted original")
	}
	current.releaseStream(first)
	first.Close()
	effects := 0
	if err := current.terminalEffect(1, second, func() error { effects++; return nil }); err != nil || effects != 1 {
		t.Fatal("detaching one viewer revoked another", err)
	}
	if !errors.Is(current.terminalEffect(1, first, func() error { t.Fatal("detached effect"); return nil }), ErrFenced) {
		t.Fatal("detached input was not fenced")
	}
	journalDir := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(journalDir, 0700); err != nil {
		t.Fatal(err)
	}
	j, err := OpenJournal(journalDir, testScope())
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	replacement, _ := pair()
	lease, err := current.advanceAndInstall(context.Background(), j, "controller-B", replacement)
	if err != nil {
		t.Fatal(err)
	}
	_ = secondPeer.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, err := secondPeer.Read(b[:]); err == nil {
		t.Fatal("old viewer survived controller replacement")
	}
	if !errors.Is(current.terminalEffect(1, second, func() error { t.Fatal("old controller effect"); return nil }), ErrFenced) {
		t.Fatal("old viewer wasn't fenced")
	}
	for i := 0; i < 32; i++ {
		stream, _ := pair()
		if !current.installStream(lease, "controller-B", stream) {
			t.Fatal("bounded view slot unavailable", i)
		}
	}
	overflow, _ := pair()
	if current.installStream(lease, "controller-B", overflow) {
		t.Fatal("unbounded viewers accepted")
	}
}

func TestQuietTerminalStreamExitsWhenOwnerRetires(t *testing.T) {
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(t.TempDir(), "quiet.sock"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	peer, err := net.DialUnix("unix", nil, listener.Addr().(*net.UnixAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	owned, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer owned.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan struct{})
	go func() { serveTerminalStream(ctx, owned, nil, nil, 1); close(done) }()
	// Keep the real viewer open and send no input: EOF must come from owner
	// cancellation, rather than client detach or a subsequent keystroke.
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("quiet terminal stream prevents owner retirement")
	}
	if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	if n, err := peer.Read(b[:]); n != 0 || err == nil {
		t.Fatal("retired stream remains connected", n, err)
	}
}
