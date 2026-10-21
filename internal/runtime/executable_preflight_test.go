//go:build !windows

package runtime

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExecutablePreflightUsesEffectivePathWithoutExecution(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "executed")
	binary := filepath.Join(dir, "qwen")
	if err := os.WriteFile(binary, []byte("#!/usr/bin/env node\nmarker-private\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := PreflightExecutable(binary, []string{"PATH=" + dir}, ""); err != ErrExecutableUnavailable {
		t.Fatalf("missing node: %v", err)
	}
	node := filepath.Join(dir, "node")
	if err := os.WriteFile(node, []byte("#!/bin/sh\nprintf executed > '"+marker+"'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", t.TempDir())
	if err := PreflightExecutable(binary, ChildEnv([]string{"PATH=" + dir}), ""); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("preflight executed interpreter")
	}
	if err := PreflightExecutable(binary, ChildEnv(), ""); err != ErrExecutableUnavailable {
		t.Fatalf("inherited PATH unexpectedly resolved node: %v", err)
	}
	if strings.Contains(ErrExecutableUnavailable.Error(), dir) || strings.Contains(ErrExecutableUnavailable.Error(), "marker-private") {
		t.Fatal("public diagnostic leaked launch configuration")
	}
}

func TestExecutablePreflightDirectInterpreterAndBounds(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "wrapper")
	for _, script := range []string{"#!" + filepath.Join(dir, "missing") + "\n", "#!" + binary + "\n", "#!/bin/sh " + strings.Repeat("x", 4096)} {
		if err := os.WriteFile(binary, []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
		if err := PreflightExecutable(binary, nil, ""); err != ErrExecutableUnavailable {
			t.Fatalf("invalid interpreter accepted: %v", err)
		}
	}
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := PreflightExecutable(binary, nil, ""); err != nil {
		t.Fatal(err)
	}
}

func TestExecutablePreflightResolvesPathFromLaunchWorkspace(t *testing.T) {
	workspace := t.TempDir()
	binDir := filepath.Join(workspace, "bin")
	if err := os.Mkdir(binDir, 0700); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "qwen")
	if err := os.WriteFile(binary, []byte("#!/usr/bin/env node\n"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(workspace, "node"), filepath.Join(binDir, "node")} {
		if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 1\n"), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, searchPath := range []string{"", "bin", "missing:bin", "missing:"} {
		env := ChildEnv([]string{"PATH=" + t.TempDir(), "PATH=" + searchPath})
		if err := PreflightExecutable(binary, env, workspace); err != nil {
			t.Fatalf("launch PATH %q failed: %v", searchPath, err)
		}
		if err := PreflightExecutable(binary, env, t.TempDir()); err != ErrExecutableUnavailable {
			t.Fatalf("launch PATH %q resolved from wrong workspace: %v", searchPath, err)
		}
	}
}

func TestExecutablePreflightEnvSplitStringSupportsOnlySimpleWords(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "wrapper")
	for _, tc := range []struct {
		line string
		ok   bool
	}{
		{"#!/usr/bin/env -S /bin/sh -e\n", true},
		{"#!/usr/bin/env -S '/bin/sh' -e\n", false},
		{"#!/usr/bin/env -S /bin/sh\\ -e\n", false},
		{"#!/usr/bin/env -S ${SHELL}\n", false},
		{"#!/usr/bin/env /bin/sh -e\n", false},
		{"#!/usr/bin/env /bin/sh\r\n", false},
	} {
		if err := os.WriteFile(binary, []byte(tc.line), 0700); err != nil {
			t.Fatal(err)
		}
		if err := PreflightExecutable(binary, nil, dir); (err == nil) != tc.ok {
			t.Fatalf("shebang %q: %v", tc.line, err)
		}
	}
}

func TestExecutablePreflightBeforeWorkspaceDefersOnlyRelativeLookup(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "wrapper")
	for _, searchPath := range []string{"bin", "", "missing:"} {
		if err := os.WriteFile(binary, []byte("#!/usr/bin/env node\n"), 0700); err != nil {
			t.Fatal(err)
		}
		if err := PreflightExecutableBeforeWorkspace(binary, []string{"PATH=" + searchPath}); err != ErrExecutableWorkspaceRequired {
			t.Fatalf("relative PATH %q should defer: %v", searchPath, err)
		}
		for _, shebang := range []string{"#!" + filepath.Join(dir, "missing"), "#!/usr/bin/env " + filepath.Join(dir, "missing")} {
			if err := os.WriteFile(binary, []byte(shebang+"\n"), 0700); err != nil {
				t.Fatal(err)
			}
			if err := PreflightExecutableBeforeWorkspace(binary, []string{"PATH=" + searchPath}); err != ErrExecutableUnavailable {
				t.Fatalf("absolute missing interpreter deferred: %v", err)
			}
		}
	}
}
