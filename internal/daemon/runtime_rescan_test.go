//go:build !windows

package daemon

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
)

func TestRuntimeRescanDiscoversInstallAfterStartupWithoutReplacingDrivers(t *testing.T) {
	binDir := t.TempDir()
	t.Setenv("PATH", binDir)
	d, err := newDaemon(Config{StateDir: t.TempDir(), NoScan: true}, nil, func() (string, error) {
		// Version probes fail immediately; this regression concerns discovery,
		// not launching a real vendor CLI or a sandbox from the test binary.
		return filepath.Join(binDir, "missing-pagnet"), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	type runtimeBinary struct {
		runtime domain.RuntimeName
		name    string
	}
	runtimes := []runtimeBinary{{domain.RuntimeQwenCode, "qwen"}, {domain.RuntimeCodex, "codex"}, {domain.RuntimeGrok, "grok"}}
	drivers := d.sessions.Drivers()
	for _, runtime := range runtimes {
		if drivers[runtime.runtime] == nil || !d.runtimeSupported(runtime.runtime) {
			t.Fatalf("missing built-in driver for %s before installation", runtime.runtime)
		}
		if d.runtimeAvailable(runtime.runtime) {
			t.Fatalf("uninstalled %s advertised available", runtime.runtime)
		}
	}
	client, server := newMemWS(t)
	scan := func() transport.InventoryPayload {
		t.Helper()
		env, err := transport.NewEnvelope(transport.MsgRequestInventory, transport.RequestInventoryPayload{})
		if err != nil {
			t.Fatal(err)
		}
		d.handleCommand(client, env)
		_ = server.SetReadDeadline(time.Now().Add(5 * time.Second))
		var reply transport.Envelope
		if err := server.ReadJSON(&reply); err != nil {
			t.Fatal(err)
		}
		if reply.Type != transport.MsgHostInventory {
			t.Fatalf("unexpected rescan reply %s", reply.Type)
		}
		var inventory transport.InventoryPayload
		if err := reply.DecodePayload(&inventory); err != nil {
			t.Fatal(err)
		}
		return inventory
	}
	if inventory := scan(); len(inventory.Runtimes) != 0 {
		t.Fatalf("uninstalled runtimes advertised: %+v", inventory.Runtimes)
	}
	for _, runtime := range runtimes {
		if err := os.WriteFile(filepath.Join(binDir, runtime.name), []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	inventory := scan()
	if len(inventory.Runtimes) != len(runtimes) {
		t.Fatalf("post-install rescan missed runtimes: %+v", inventory.Runtimes)
	}
	for _, runtime := range runtimes {
		found := false
		for _, installation := range inventory.Runtimes {
			if installation.Runtime == string(runtime.runtime) && installation.Path == filepath.Join(binDir, runtime.name) && installation.Capabilities != nil {
				found = true
			}
		}
		row := &InstanceRow{Runtime: string(runtime.runtime)}
		if !found || !d.runtimeAvailable(runtime.runtime) || d.sessionDriverFor(row) != drivers[runtime.runtime] {
			t.Fatalf("installed %s lacks inventory or original launch driver", runtime.runtime)
		}
		if err := os.Remove(filepath.Join(binDir, runtime.name)); err != nil {
			t.Fatal(err)
		}
	}
	if inventory := scan(); len(inventory.Runtimes) != 0 {
		t.Fatalf("removed runtimes remain advertised: %+v", inventory.Runtimes)
	}
	for _, runtime := range runtimes {
		if d.runtimeAvailable(runtime.runtime) || d.sessions.DriverFor(runtime.runtime) != drivers[runtime.runtime] {
			t.Fatalf("removing %s changed driver identity or availability", runtime.runtime)
		}
	}
}
