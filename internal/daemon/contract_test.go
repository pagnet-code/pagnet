package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"pagnet/internal/domain"
)

// The coordination contract is kind-aware and must reach the model:
// fresh sessions get it appended to the first turn; resumed sessions
// already carry it in context.

func TestContractKindAware(t *testing.T) {
	d := newTestDaemon(t)
	instID := domain.NewID().String()

	// Worker: network_* surface + capability-declaration duty.
	wrow := &InstanceRow{
		InstanceID: instID, AgentName: "coder-1", NetworkID: "net-1", Kind: "worker",
	}
	path, text, err := d.writeContract(wrow)
	if err != nil {
		t.Fatalf("writeContract(worker): %v", err)
	}
	if !strings.Contains(text, "PAGNET COORDINATION CONTRACT") {
		t.Fatalf("worker contract missing header: %s", text)
	}
	if !strings.Contains(text, "network_register_capabilities") {
		t.Fatalf("worker contract missing capability-declaration duty: %s", text)
	}
	if !strings.Contains(text, "network_whoami") {
		t.Fatalf("worker contract missing whoami pointer: %s", text)
	}
	if strings.Contains(text, "control_channel_send") {
		t.Fatalf("worker contract must not mention the rep surface: %s", text)
	}

	// File: in the state dir, never the workspace, 0600.
	if filepath.Dir(path) != filepath.Join(d.StateDir, "contracts") {
		t.Fatalf("contract path = %s, want under %s/contracts", path, d.StateDir)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat contract: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("contract mode = %v, want 0600", fi.Mode().Perm())
	}

	// Representative: control_* surface + channel-reply duty.
	rrow := &InstanceRow{
		InstanceID: instID, AgentName: "advisor-1", Kind: "representative",
	}
	_, rtext, err := d.writeContract(rrow)
	if err != nil {
		t.Fatalf("writeContract(rep): %v", err)
	}
	if !strings.Contains(rtext, "control_channel_send") {
		t.Fatalf("rep contract missing channel-reply duty: %s", rtext)
	}
	if !strings.Contains(rtext, "NOT delivered to the human") {
		t.Fatalf("rep contract missing plain-output warning: %s", rtext)
	}
	if strings.Contains(rtext, "network_register_capabilities") {
		t.Fatalf("rep contract must not mention the worker surface: %s", rtext)
	}
}

func TestTurnSpecContractInjection(t *testing.T) {
	d := newTestDaemon(t)
	instID := domain.NewID().String()
	row := &InstanceRow{
		InstanceID: instID, AgentName: "coder-1", NetworkID: "net-1",
		Kind: "worker", Workspace: "/tmp/ws",
	}

	// Fresh session: the contract rides with the first turn.
	fresh := d.turnSpecFor(row, false, "review the auth code", "mission")
	if !strings.Contains(fresh.Input, "review the auth code") {
		t.Fatalf("fresh input lost the mission: %q", fresh.Input)
	}
	if !strings.Contains(fresh.Input, "PAGNET COORDINATION CONTRACT") {
		t.Fatalf("fresh input missing the contract: %q", fresh.Input)
	}
	if !strings.HasSuffix(fresh.Input, "  instance: "+instID+"\n") {
		t.Fatalf("fresh input must end with the contract, got tail: %q", fresh.Input[len(fresh.Input)-80:])
	}
	if !strings.Contains(fresh.Input, "network_register_capabilities") {
		t.Fatalf("fresh input missing capability instruction: %q", fresh.Input)
	}
	env := strings.Join(fresh.Env, "\n")
	if !strings.Contains(env, "PAGNET_COORDINATION_CONTRACT="+filepath.Join(d.StateDir, "contracts", instID+".md")) {
		t.Fatalf("fresh env missing contract path: %s", env)
	}

	// Resumed session: the context already carries the contract.
	resumed := d.turnSpecFor(row, true, "continue", "delivery")
	if resumed.Input != "continue" {
		t.Fatalf("resumed input = %q, want unchanged (no contract appended)", resumed.Input)
	}
}
