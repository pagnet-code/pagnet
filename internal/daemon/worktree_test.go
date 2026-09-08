package daemon

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"pagnet/internal/domain"
	"pagnet/internal/transport"
)

func gitInitRepo(t *testing.T, dir string) {
	t.Helper()
	steps := [][]string{
		{"-C", dir, "init", "-b", "main", "."},
		{"-C", dir, "add", "."},
		{"-C", dir, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-m", "init"},
	}
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range steps {
		if out, err := exec.Command("git", args...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
}

func newTestDaemon(t *testing.T) *Daemon {
	t.Helper()
	d, err := New(Config{StateDir: t.TempDir()}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func TestResolveWorkspaceFirstRWKeepsCheckout(t *testing.T) {
	d := newTestDaemon(t)
	repo := t.TempDir()
	gitInitRepo(t, repo)

	p := transport.LaunchAgentPayload{InstanceID: "inst-1", WorkspacePath: repo, AgentName: "coder-1"}
	got, err := d.resolveWorkspace(p, domain.AccessReadWrite)
	if err != nil {
		t.Fatal(err)
	}
	if got != repo {
		t.Fatalf("first RW agent should keep the checkout, got %s", got)
	}
}

func TestResolveWorkspaceSecondRWGetsWorktree(t *testing.T) {
	d := newTestDaemon(t)
	repo := t.TempDir()
	gitInitRepo(t, repo)
	inst1, inst2 := domain.NewID().String(), domain.NewID().String()
	if err := d.state.UpsertInstance(InstanceRow{
		InstanceID: inst1, Runtime: "fake", Workspace: repo,
		Status: "idle", Access: domain.AccessReadWrite, AgentName: "coder-1",
	}); err != nil {
		t.Fatal(err)
	}

	p := transport.LaunchAgentPayload{InstanceID: inst2, WorkspacePath: repo, AgentName: "coder-2"}
	got, err := d.resolveWorkspace(p, domain.AccessReadWrite)
	if err != nil {
		t.Fatalf("second RW agent must be isolated, got error: %v", err)
	}
	want := filepath.Join(repo, ".pagnet", "worktrees", inst2)
	if got != want {
		t.Fatalf("worktree path = %s, want %s", got, want)
	}
	out, err := exec.Command("git", "-C", got, "branch", "--show-current").CombinedOutput()
	if err != nil {
		t.Fatalf("branch in worktree: %v: %s", err, out)
	}
	if br := strings.TrimSpace(string(out)); br != "pagnet/coder-2/"+inst2 {
		t.Fatalf("worktree branch = %q, want pagnet/coder-2/%s", br, inst2)
	}
}

func TestResolveWorkspaceReadOnlySharesCheckout(t *testing.T) {
	d := newTestDaemon(t)
	repo := t.TempDir()
	gitInitRepo(t, repo)
	if err := d.state.UpsertInstance(InstanceRow{
		InstanceID: "inst-1", Runtime: "fake", Workspace: repo,
		Status: "idle", Access: domain.AccessReadWrite, AgentName: "coder-1",
	}); err != nil {
		t.Fatal(err)
	}

	p := transport.LaunchAgentPayload{InstanceID: "inst-ro", WorkspacePath: repo, AgentName: "reviewer"}
	got, err := d.resolveWorkspace(p, domain.AccessReadOnly)
	if err != nil {
		t.Fatal(err)
	}
	if got != repo {
		t.Fatalf("read-only agent should share the checkout, got %s", got)
	}
}

func TestResolveWorkspaceIdempotentReplay(t *testing.T) {
	d := newTestDaemon(t)
	repo := t.TempDir()
	gitInitRepo(t, repo)
	inst1, inst2 := domain.NewID().String(), domain.NewID().String()
	if err := d.state.UpsertInstance(InstanceRow{
		InstanceID: inst1, Runtime: "fake", Workspace: repo,
		Status: "idle", Access: domain.AccessReadWrite, AgentName: "coder-1",
	}); err != nil {
		t.Fatal(err)
	}

	p := transport.LaunchAgentPayload{InstanceID: inst2, WorkspacePath: repo, AgentName: "coder-2"}
	first, err := d.resolveWorkspace(p, domain.AccessReadWrite)
	if err != nil {
		t.Fatal(err)
	}
	second, err := d.resolveWorkspace(p, domain.AccessReadWrite)
	if err != nil {
		t.Fatalf("replay of worktree resolution must be idempotent: %v", err)
	}
	if first != second {
		t.Fatalf("replay resolved differently: %s vs %s", first, second)
	}
}

func TestResolveWorkspaceOtherRepoNoWorktree(t *testing.T) {
	d := newTestDaemon(t)
	repoA := t.TempDir()
	gitInitRepo(t, repoA)
	repoB := t.TempDir()
	gitInitRepo(t, repoB)
	if err := d.state.UpsertInstance(InstanceRow{
		InstanceID: "inst-1", Runtime: "fake", Workspace: repoA,
		Status: "idle", Access: domain.AccessReadWrite, AgentName: "coder-1",
	}); err != nil {
		t.Fatal(err)
	}

	p := transport.LaunchAgentPayload{InstanceID: "inst-2", WorkspacePath: repoB, AgentName: "coder-2"}
	got, err := d.resolveWorkspace(p, domain.AccessReadWrite)
	if err != nil {
		t.Fatal(err)
	}
	if got != repoB {
		t.Fatalf("different repository must not share a worktree, got %s", got)
	}
}
