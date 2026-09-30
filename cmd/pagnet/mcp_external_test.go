package main

import (
	"strings"
	"testing"
)

func TestExternalMCPRejectsAccountCredentialBeforeConnect(t *testing.T) {
	t.Setenv("PAGNET_SERVER", "http://127.0.0.1:1")
	t.Setenv("PAGNET_CREDENTIAL", "pgn_acc_v1_not-a-principal")
	cmd := mcpExternalCmd()
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{"--network", "01900000-0000-7000-8000-000000000001"})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "activation or endpoint") {
		t.Fatalf("expected principal credential rejection, got %v", err)
	}
}
func TestExternalMCPRejectsPublicBindBeforeActivation(t *testing.T) {
	t.Setenv("PAGNET_CREDENTIAL", "pgn_act_v1_should-never-be-consumed")
	t.Setenv("PAGNET_MCP_HTTP_TOKEN", strings.Repeat("a", 32))
	cmd := mcpExternalCmd()
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{"--network", "01900000-0000-7000-8000-000000000001", "--listen", "0.0.0.0:8787"})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("expected bind rejection before credential use, got %v", err)
	}
}
