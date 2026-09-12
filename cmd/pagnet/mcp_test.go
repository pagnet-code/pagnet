package main

import (
	"strings"
	"testing"
)

// The mcp subcommands are internal (daemon-spawned); their fail-fast
// error paths are what a mis-launched process must hit: no socket, or
// no instance identity, before any dial is attempted.

func TestMCPWorkerRequiresSocket(t *testing.T) {
	t.Setenv("PAGNET_INSTANCE_ID", "inst-1")
	cmd := mcpWorkerCmd()
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "--socket is required") {
		t.Fatalf("expected --socket error, got %v", err)
	}
}

func TestMCPWorkerRequiresInstanceID(t *testing.T) {
	t.Setenv("PAGNET_INSTANCE_ID", "")
	cmd := mcpWorkerCmd()
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	if err := cmd.Flags().Set("socket", "/tmp/no-such-socket.sock"); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "PAGNET_INSTANCE_ID is not set") {
		t.Fatalf("expected PAGNET_INSTANCE_ID error, got %v", err)
	}
}

func TestMCPControlRequiresSocket(t *testing.T) {
	t.Setenv("PAGNET_INSTANCE_ID", "inst-1")
	cmd := mcpControlCmd()
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "--socket is required") {
		t.Fatalf("expected --socket error, got %v", err)
	}
}

func TestMCPControlRequiresInstanceID(t *testing.T) {
	t.Setenv("PAGNET_INSTANCE_ID", "")
	cmd := mcpControlCmd()
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	if err := cmd.Flags().Set("socket", "/tmp/no-such-socket.sock"); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "PAGNET_INSTANCE_ID is not set") {
		t.Fatalf("expected PAGNET_INSTANCE_ID error, got %v", err)
	}
}
