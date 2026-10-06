//go:build linux || darwin

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/fabric/localinstallation"
)

// TestOpenFusedInstallation proves the fused serve's installation load is
// honest: an ABSENT installation is daemon-only (nil, nil — never a silent
// fixture), a PRESENT-but-invalid installation is a genuine startup failure
// (no silent skip), and a present, valid installation composes the actual
// installed hosted product (daemon-side components + an explicit Hosted
// config, never implicit).
func TestOpenFusedInstallation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	absent := filepath.Join(t.TempDir(), "missing")
	if n, err := openFusedInstallation(ctx, absent); err != nil || n != nil {
		t.Fatalf("absent installation: got (node=%v, err=%v), want (nil, nil)", n != nil, err)
	}

	corrupt := t.TempDir()
	if err := os.WriteFile(filepath.Join(corrupt, "garbage.txt"), []byte("not a pagnet installation"), 0o644); err != nil {
		t.Fatal(err)
	}
	if n, err := openFusedInstallation(ctx, corrupt); err == nil {
		if n != nil {
			_ = n.Close()
		}
		t.Fatal("corrupt installation: got no error, want a genuine startup failure")
	}

	parent := t.TempDir()
	socketDir := filepath.Join(parent, "run")
	if err := os.Mkdir(socketDir, 0o700); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(parent, "authority")
	socket := filepath.Join(socketDir, "node.sock")
	installed, err := localinstallation.Bootstrap(ctx, dir, localinstallation.Options{Settings: localinstallation.DefaultSettings(socket)})
	if err != nil {
		t.Fatal(err)
	}
	if err := installed.Close(); err != nil {
		t.Fatal(err)
	}
	n, err := openFusedInstallation(ctx, dir)
	if err != nil {
		t.Fatalf("present installation: %v", err)
	}
	if n == nil {
		t.Fatal("present installation: got nil node, want the composed hosted product")
	}
	defer func() { _ = n.Close() }()
	if n.Hosted == nil {
		t.Fatal("present installation: the hosted product was not composed")
	}
	if n.Hosted.OwnerGuard == nil || n.Hosted.InvocationGuard == nil || n.Hosted.Sideports == nil {
		t.Fatal("present installation: the daemon-side components were not composed")
	}
}
