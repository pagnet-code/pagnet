package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
)

// --- listDirs (the click-to-select directory picker) -----------------------

func TestListDirs_OnlyDirsSorted(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"zeta", "alpha", "mid"} {
		if err := os.MkdirAll(filepath.Join(root, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// A file must NOT appear (the picker selects a directory).
	if err := os.WriteFile(filepath.Join(root, "file.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	d, err := New(Config{StateDir: t.TempDir(), AllowedRoots: []string{root}}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { d.Close() })

	res, err := d.listDirs(root)
	if err != nil {
		t.Fatalf("listDirs: %v", err)
	}
	var names []string
	for _, e := range res.Entries {
		names = append(names, e.Name)
		if !e.IsDir {
			t.Fatalf("entry %q is not a dir", e.Name)
		}
	}
	want := []string{"alpha", "mid", "zeta"}
	if len(names) != len(want) {
		t.Fatalf("entries = %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("entries = %v, want %v (sorted, dirs only)", names, want)
		}
	}
}

func TestListDirs_NestedPath(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(nested, "child"), 0o755); err != nil {
		t.Fatal(err)
	}
	d, err := New(Config{StateDir: t.TempDir(), AllowedRoots: []string{root}}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { d.Close() })

	res, err := d.listDirs(nested)
	if err != nil {
		t.Fatalf("listDirs(nested): %v", err)
	}
	if len(res.Entries) != 1 || res.Entries[0].Name != "child" {
		t.Fatalf("entries = %v, want [child]", res.Entries)
	}
}

func TestListDirs_OutsideRootRefused(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir() // a different temp dir, NOT under root
	d, err := New(Config{StateDir: t.TempDir(), AllowedRoots: []string{root},
		RootsMode: domain.RootsModeAllowList}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { d.Close() })

	if _, err := d.listDirs(outside); err == nil {
		t.Fatalf("listDirs(outside root) succeeded, want refused")
	}
}

func TestListDirs_NotADirectory(t *testing.T) {
	root := t.TempDir()
	f := filepath.Join(root, "file.txt")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	d, err := New(Config{StateDir: t.TempDir(), AllowedRoots: []string{root}}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { d.Close() })

	if _, err := d.listDirs(f); err == nil {
		t.Fatalf("listDirs(file) succeeded, want refused")
	}
}

// --- CWD override on launch ------------------------------------------------

func TestLaunch_CWDSubdir(t *testing.T) {
	repo := t.TempDir()
	sub := filepath.Join(repo, "packages", "api")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	d, err := New(Config{StateDir: t.TempDir(), AllowedRoots: []string{repo}}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	d.adapters[domain.RuntimeFake] = stubAdapter{}
	t.Cleanup(func() { d.Close() })

	id := domain.NewID().String()
	if err := d.doLaunch(nil, transport.LaunchAgentPayload{
		InstanceID:    id,
		WorkspacePath: repo,
		CWD:           sub,
		AgentName:     "cwd-agent",
		Access:        domain.AccessReadOnly, // read-only: no worktree
		Runtime:       string(domain.RuntimeFake),
	}); err != nil {
		t.Fatalf("doLaunch: %v", err)
	}
	row, ok, _ := d.state.GetInstance(id)
	if !ok || row == nil {
		t.Fatalf("missing instance row")
	}
	if row.Workspace != sub {
		t.Fatalf("workspace = %q, want %q (the CWD subdir)", row.Workspace, sub)
	}
}

func TestLaunch_CWDEqualsWorkspaceRoot(t *testing.T) {
	repo := t.TempDir()
	d, err := New(Config{StateDir: t.TempDir(), AllowedRoots: []string{repo}}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	d.adapters[domain.RuntimeFake] = stubAdapter{}
	t.Cleanup(func() { d.Close() })

	id := domain.NewID().String()
	if err := d.doLaunch(nil, transport.LaunchAgentPayload{
		InstanceID:    id,
		WorkspacePath: repo,
		CWD:           repo, // CWD == workspace root: no-op
		AgentName:     "cwd-root",
		Access:        domain.AccessReadOnly,
		Runtime:       string(domain.RuntimeFake),
	}); err != nil {
		t.Fatalf("doLaunch: %v", err)
	}
	row, _, _ := d.state.GetInstance(id)
	if row.Workspace != repo {
		t.Fatalf("workspace = %q, want %q", row.Workspace, repo)
	}
}

func TestLaunch_CWDSiblingOfWorkspaceRefused(t *testing.T) {
	root := t.TempDir()
	workspace := filepath.Join(root, "ws")
	sibling := filepath.Join(root, "sib")
	for _, p := range []string{workspace, sibling} {
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	d, err := New(Config{StateDir: t.TempDir(), AllowedRoots: []string{root}}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	d.adapters[domain.RuntimeFake] = stubAdapter{}
	t.Cleanup(func() { d.Close() })

	id := domain.NewID().String()
	// The CWD is under an allowed root but a SIBLING of the selected
	// workspace — the agent must not escape the workspace it was given.
	if err := d.doLaunch(nil, transport.LaunchAgentPayload{
		InstanceID:    id,
		WorkspacePath: workspace,
		CWD:           sibling,
		AgentName:     "cwd-sibling",
		Access:        domain.AccessReadOnly,
		Runtime:       string(domain.RuntimeFake),
	}); err == nil {
		t.Fatalf("doLaunch with sibling CWD succeeded, want refused")
	}
}
