//go:build !windows

package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/runtimeprofile"
	"github.com/pagnet-code/pagnet/transport"
)

func TestRuntimeRescanDiscoversInstallAfterStartupWithoutReplacingDrivers(t *testing.T) {
	binDir := t.TempDir()
	t.Setenv("PATH", binDir)
	d, err := newDaemon(Config{StateDir: privateDaemonStateDir(t), NoScan: true}, nil, func() (string, error) {
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

func TestRuntimeRescanRepairsMissingInterpreter(t *testing.T) {
	binDir := t.TempDir()
	t.Setenv("PATH", binDir)
	binary := filepath.Join(binDir, "qwen")
	marker := filepath.Join(binDir, "executed")
	if err := os.WriteFile(binary, []byte("#!/usr/bin/env node\n"), 0700); err != nil {
		t.Fatal(err)
	}
	d, err := newDaemon(Config{StateDir: privateDaemonStateDir(t), NoScan: true}, nil, func() (string, error) {
		return filepath.Join(binDir, "missing-pagnet"), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	if d.runtimeAvailable(domain.RuntimeQwenCode) || len(d.detectRuntimes()) != 0 {
		t.Fatal("wrapper without node advertised available")
	}
	instance := domain.NewID().String()
	if _, _, _, err := d.prepareLaunch(transport.LaunchAgentPayload{InstanceID: instance, Runtime: string(domain.RuntimeQwenCode), Kind: "representative"}); err == nil {
		t.Fatal("missing interpreter admitted launch")
	}
	if _, err := os.Stat(filepath.Join(d.StateDir, "representatives", instance)); !os.IsNotExist(err) {
		t.Fatal("failed runtime preflight created workspace")
	}
	if err := os.WriteFile(filepath.Join(binDir, "node"), []byte("#!/bin/sh\nprintf executed > '"+marker+"'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if !d.runtimeAvailable(domain.RuntimeQwenCode) || len(d.detectRuntimes()) != 1 {
		t.Fatal("rescan did not repair interpreter availability")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("availability check executed interpreter")
	}
	// Explicit launch PATH wins over the daemon's inherited PATH.
	d.RuntimeEnv = []string{"PATH=" + t.TempDir()}
	if d.runtimeAvailable(domain.RuntimeQwenCode) || len(d.detectRuntimes()) != 0 {
		t.Fatal("availability ignored effective launch PATH")
	}
}

func TestLaunchPreflightUsesWorkspacePathBeforeProfilePin(t *testing.T) {
	for _, profile := range []string{"", "custom"} {
		for _, searchPath := range []string{"bin", ""} {
			for _, installed := range []bool{true, false} {
				t.Run(fmt.Sprintf("profile=%s/path=%s/installed=%v", profile, searchPath, installed), func(t *testing.T) {
					controller := t.TempDir()
					t.Chdir(controller)
					workspace := t.TempDir()
					wrapperDir := t.TempDir()
					binary := filepath.Join(wrapperDir, "qwen")
					if err := os.WriteFile(binary, []byte("#!/usr/bin/env node\n"), 0700); err != nil {
						t.Fatal(err)
					}
					// The interpreter exists in exactly one context. Admission
					// must follow the workspace even when controller lookup disagrees.
					interpreterRoot := controller
					if installed {
						interpreterRoot = workspace
					}
					interpreterDir := filepath.Join(interpreterRoot, searchPath)
					if err := os.MkdirAll(interpreterDir, 0700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(interpreterDir, "node"), []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
						t.Fatal(err)
					}
					t.Setenv("PATH", wrapperDir)
					d, err := newDaemon(Config{StateDir: privateDaemonStateDir(t), NoScan: true, RuntimeEnv: []string{"PATH=" + searchPath}}, nil, func() (string, error) {
						return filepath.Join(wrapperDir, "missing-pagnet"), nil
					})
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = d.Close() })
					if profile != "" {
						d.RuntimeEnv = []string{"PATH=" + t.TempDir()}
						cfg := runtimeprofile.Profile{Name: profile, Runtime: domain.RuntimeQwenCode, Executable: binary, Env: map[string]string{"PATH": searchPath}}
						if err := runtimeprofile.Save(filepath.Join(d.StateDir, runtimeprofile.Filename), runtimeprofile.File{Version: 1, Profiles: []runtimeprofile.Profile{cfg}}); err != nil {
							t.Fatal(err)
						}
						if err := d.loadRuntimeProfiles(); err != nil {
							t.Fatal(err)
						}
					}
					instance := domain.NewID().String()
					row, _, _, err := d.prepareLaunch(transport.LaunchAgentPayload{InstanceID: instance, Runtime: string(domain.RuntimeQwenCode), Profile: profile, WorkspacePath: workspace, Access: domain.AccessReadOnly})
					if installed {
						if err != nil || row.Workspace != workspace {
							t.Fatalf("workspace interpreter rejected: %v", err)
						}
						if profile != "" {
							if _, pinned := d.state.KVGet("runtime-profile:" + instance); !pinned {
								t.Fatal("validated profile was not pinned")
							}
						}
						return
					}
					if err == nil {
						t.Fatal("controller interpreter incorrectly admitted workspace launch")
					}
					if _, pinned := d.state.KVGet("runtime-profile:" + instance); pinned {
						t.Fatal("failed exact preflight pinned profile")
					}
					if _, exists, err := d.state.GetInstance(instance); err != nil || exists {
						t.Fatalf("failed preflight registered instance: %v", err)
					}
					if _, err := os.Stat(filepath.Join(d.StateDir, "agentmd", instance+".md")); !os.IsNotExist(err) {
						t.Fatal("failed preflight wrote standing document")
					}
				})
			}
		}
	}
}

func TestLaunchPreflightRemovesOnlyNewManagedWorktree(t *testing.T) {
	for _, state := range []string{"new", "existing-clean", "existing-dirty"} {
		t.Run(state, func(t *testing.T) {
			existing := state != "new"
			repo := t.TempDir()
			gitInitRepo(t, repo)
			wrapperDir := t.TempDir()
			if err := os.WriteFile(filepath.Join(wrapperDir, "qwen"), []byte("#!/usr/bin/env node\n"), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", wrapperDir+string(os.PathListSeparator)+os.Getenv("PATH"))
			d := newTestDaemon(t)
			d.RuntimeEnv = []string{"PATH=bin"}
			if err := d.state.UpsertInstance(InstanceRow{InstanceID: domain.NewID().String(), Runtime: "fake", Workspace: repo, Status: "idle", Access: domain.AccessReadWrite}); err != nil {
				t.Fatal(err)
			}
			instance := domain.NewID().String()
			common, err := d.repoCommonDir(repo)
			if err != nil {
				t.Fatal(err)
			}
			worktree := filepath.Join(filepath.Dir(common), ".pagnet", "worktrees", instance)
			if existing {
				if _, err := d.ensureWorktree(repo, common, instance, worktreeBranch("", instance)); err != nil {
					t.Fatal(err)
				}
				if state == "existing-dirty" {
					if err := os.WriteFile(filepath.Join(worktree, "private-work"), []byte("keep"), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			if _, _, _, err := d.prepareLaunch(transport.LaunchAgentPayload{InstanceID: instance, Runtime: string(domain.RuntimeQwenCode), WorkspacePath: repo, Access: domain.AccessReadWrite}); err == nil {
				t.Fatal("missing workspace interpreter admitted")
			}
			_, err = os.Stat(worktree)
			if existing && err != nil {
				t.Fatal("preexisting managed worktree removed", err)
			}
			if !existing && !os.IsNotExist(err) {
				t.Fatal("new managed worktree retained after failed preflight", err)
			}
		})
	}
}
