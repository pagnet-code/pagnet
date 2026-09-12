package daemon

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
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
	// Debug: daemon unit tests may drive the deterministic fake runtime.
	d, err := New(Config{StateDir: t.TempDir(), Debug: true}, nil)
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
	// repoCommonDir resolves symlinks (git stores canonical gitdirs), so
	// the worktree path is canonical even when repo is not (macOS /tmp).
	if resolved, err := filepath.EvalSymlinks(want); err == nil {
		want = resolved
	}
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

// TestResolveWorkspaceSymlinkedRepoPath: the checkout is reached through a
// symlink. Git records a worktree's gitdir with the symlink resolved
// (macOS /tmp -> /private/tmp is the production case), so the "same
// repository" identity must be compared in canonical form — otherwise the
// idempotent replay refuses its own worktree.
func TestResolveWorkspaceSymlinkedRepoPath(t *testing.T) {
	d := newTestDaemon(t)
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	gitInitRepo(t, link)
	inst1, inst2 := domain.NewID().String(), domain.NewID().String()
	if err := d.state.UpsertInstance(InstanceRow{
		InstanceID: inst1, Runtime: "fake", Workspace: link,
		Status: "idle", Access: domain.AccessReadWrite, AgentName: "coder-1",
	}); err != nil {
		t.Fatal(err)
	}

	p := transport.LaunchAgentPayload{InstanceID: inst2, WorkspacePath: link, AgentName: "coder-2"}
	first, err := d.resolveWorkspace(p, domain.AccessReadWrite)
	if err != nil {
		t.Fatal(err)
	}
	if first == link {
		t.Fatal("second RW agent on the same repository must be isolated, kept the checkout")
	}
	second, err := d.resolveWorkspace(p, domain.AccessReadWrite)
	if err != nil {
		t.Fatalf("replay through a symlinked repo path must be idempotent: %v", err)
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
