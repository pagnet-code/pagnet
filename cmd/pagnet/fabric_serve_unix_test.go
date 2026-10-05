//go:build linux || darwin

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/localinstallation"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/fabricclient"
	"github.com/pagnet-code/pagnet/internal/fabrichost"
	"github.com/spf13/cobra"
)

type localReadyWriter struct {
	once  sync.Once
	ready chan struct{}
}

func (w *localReadyWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.ready) })
	return len(p), nil
}
func TestActualLocalForegroundServeJoinsSocketAndWriter(t *testing.T) {
	parent, err := os.MkdirTemp("", "pgn-serve-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(parent)
	dir := filepath.Join(parent, "authority")
	run := filepath.Join(parent, "run")
	if err = os.Mkdir(run, 0700); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(run, "node.sock")
	installation, err := localinstallation.Bootstrap(context.Background(), dir, localinstallation.Options{Settings: localinstallation.DefaultSettings(socket)})
	if err != nil {
		t.Fatal(err)
	}
	root := installation.Store.AuthorityIdentity()
	if err = installation.Close(); err != nil {
		t.Fatal(err)
	}
	old := silent
	silent = false
	defer func() { silent = old }()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := &cobra.Command{}
	cmd.SetContext(ctx)
	ready := &localReadyWriter{ready: make(chan struct{})}
	cmd.SetOut(ready)
	done := make(chan error, 1)
	go func() { done <- runLocalFabricDaemon(cmd, dir) }()
	select {
	case <-ready.ready:
	case err := <-done:
		t.Fatal("local serve failed before ready", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	client, err := fabricclient.Dial(ctx, socket, fabrichost.Authentication{Type: "fabric.auth", Mode: "owner"})
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.Call(ctx, fabric.OperationDiscover, json.RawMessage(`{"query":"hello","limit":1}`))
	if err != nil || result.IsError {
		t.Fatal("actual foreground node did not serve", err, result)
	}
	client.Close()
	cancel()
	select {
	case err = <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("local daemon did not join")
	}
	retained, err := registry.Open(context.Background(), dir)
	if err != nil {
		t.Fatal("daemon retained writer after shutdown", err)
	}
	defer retained.Close()
	if retained.AuthorityIdentity().StoreID != root.StoreID {
		t.Fatal("daemon replaced root")
	}
	if _, err = os.Lstat(socket); !os.IsNotExist(err) {
		t.Fatal("daemon retained listener", err)
	}
}
func TestLocalForegroundMissingInstallationNeverCreatesState(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "missing")
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	if err := runLocalFabricDaemon(cmd, dir); err == nil {
		t.Fatal("missing installation started")
	}
	if _, err := os.Lstat(dir); !os.IsNotExist(err) {
		t.Fatal("serve initialized missing identity", err)
	}
}
