package fabricnode

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/pagnet-code/pagnet/domain"
)

func TestDescriptionOnlyAgentSuppliesStandingRoleAndExplicitRoleOverrides(t *testing.T) {
	private := t.TempDir()
	bin := filepath.Join(private, "bin")
	if err := os.Mkdir(bin, 0700); err != nil {
		t.Fatal(err)
	}
	// Inventory only resolves this executable; selection must never execute it.
	if err := os.WriteFile(filepath.Join(bin, "claude"), []byte("#!/bin/sh\nexit 77\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", private)
	t.Setenv("PATH", bin)
	n := &InstalledNode{Runtime: &LocalRuntime{NativeRuntime: &NativeRuntime{executionPaths: NativeExecutionPaths{Binary: filepath.Join(private, "pagnet"), AuthorityDirectory: filepath.Join(private, "authority"), SocketPath: filepath.Join(private, "fabric.sock")}}}}
	in := AgentCreateInput{Name: "Maria", Description: "Maria supports sales and customers.", Runtime: string(domain.RuntimeClaudeCode), Workspace: private}
	spec, err := n.selectedAgentRuntime(context.Background(), in)
	if err != nil || spec == nil || spec.StandingInstructions != in.Description {
		t.Fatal("description-only role was not applied", err)
	}
	in.Role = "Private account-specific operating instructions."
	spec, err = n.selectedAgentRuntime(context.Background(), in)
	if err != nil || spec == nil || spec.StandingInstructions != in.Role {
		t.Fatal("explicit private role was not preserved", err)
	}
	if in.Description != "Maria supports sales and customers." {
		t.Fatal("private role rewrote network description")
	}
}
