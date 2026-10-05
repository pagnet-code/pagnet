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
	home := filepath.Join(private, "home")
	workspace := filepath.Join(private, "workspace")
	for _, dir := range []string{bin, home, workspace} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	// Inventory only resolves this executable; selection must never execute it.
	if err := os.WriteFile(filepath.Join(bin, "claude"), []byte("#!/bin/sh\nexit 77\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("PATH", bin)
	n := &InstalledNode{Runtime: &LocalRuntime{NativeRuntime: &NativeRuntime{executionPaths: NativeExecutionPaths{Binary: filepath.Join(bin, "pagnet"), AuthorityDirectory: filepath.Join(private, "authority"), SocketPath: filepath.Join(private, "fabric.sock")}}}}
	in := AgentCreateInput{Name: "Maria", Description: "Maria supports sales and customers.", Runtime: string(domain.RuntimeClaudeCode), Workspace: workspace}
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

func TestAgentCreationRefusesPrivateStateOverlapBeforeProvision(t *testing.T) {
	private := t.TempDir()
	bin, workspace, home := filepath.Join(private, "bin"), filepath.Join(private, "project"), filepath.Join(private, "home")
	for _, dir := range []string{bin, workspace, home} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(bin, "claude"), []byte("#!/bin/sh\nexit 77\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("PATH", bin)
	paths := NativeExecutionPaths{Binary: filepath.Join(bin, "pagnet"), AuthorityDirectory: filepath.Join(private, "authority"), SocketPath: filepath.Join(private, "fabric.sock")}
	n := &InstalledNode{Runtime: &LocalRuntime{NativeRuntime: &NativeRuntime{executionPaths: paths}}}
	in := AgentCreateInput{Name: "Maria", Description: "Sales", Runtime: string(domain.RuntimeClaudeCode), Workspace: private}
	if _, err := n.selectedAgentRuntime(context.Background(), in); err == nil {
		t.Fatal("ancestor workspace exposed private state")
	}
	in.Workspace = workspace
	if _, err := n.selectedAgentRuntime(context.Background(), in); err != nil {
		t.Fatal("separate project rejected", err)
	}
	n.Runtime.NativeRuntime.executionPaths.Binary = filepath.Join(private, "pagnet")
	if _, err := n.selectedAgentRuntime(context.Background(), in); err == nil {
		t.Fatal("bridge executable directory exposed private state")
	}
	if _, err := os.Stat(paths.AuthorityDirectory); !os.IsNotExist(err) {
		t.Fatal("selection materialized private state", err)
	}
	if _, err := os.Stat(filepath.Join(private, "workers")); !os.IsNotExist(err) {
		t.Fatal("selection launched or reserved worker", err)
	}
}
