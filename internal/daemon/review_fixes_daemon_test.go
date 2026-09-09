package daemon

// Regression tests for the section-by-section review fixes (daemon scope),
// see docs/IMPLEMENTATION_STATUS.md "Section-by-section code review".

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"pagnet/internal/domain"
	agentruntime "pagnet/internal/runtime"
	"pagnet/internal/transport"
)

// Regression: runtime detection must resolve the CLI binary through the
// adapter (the canonical runtime name is NOT the binary name — qwen-code →
// `qwen`), or the inventory never reports runtimes the daemon can drive.
func TestDetectRuntimes_UsesAdapterBinaryResolution(t *testing.T) {
	d, err := New(Config{StateDir: t.TempDir()}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	d.adapters = map[domain.RuntimeName]agentruntime.Adapter{
		domain.RuntimeQwenCode: stubAdapter{},
	}
	out := d.detectRuntimes()
	if len(out) != 1 || out[0].Runtime != "qwen-code" || out[0].Path != "stub" {
		t.Fatalf("detectRuntimes = %+v, want one qwen-code entry with the adapter-resolved path", out)
	}
}

// waitUntil polls cond until true or the deadline (test helper).
func waitUntil(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// F2: a re-dispatched command (same CommandID, server ticks every 2 s
// while un-acked) must be dropped AT ENQUEUE while the original is
// queued or in flight — and after a clean run, acked from the persistent
// set without re-execution.
func TestEnqueueCommand_ResendDedup(t *testing.T) {
	d := newTestDaemon(t)
	ran := 0
	// Production job shape: the enqueued job wraps the handler in guarded
	// (claim already taken by enqueueCommand; guarded does the ack + the
	// persistent MarkProcessed on success).
	job := func() {
		d.guarded(nil, "cmd-1", func() error { ran++; return nil })
	}
	d.enqueueCommand(nil, "inst-1", "cmd-1", job)
	// Duplicate while the original is queued/in flight: dropped.
	d.enqueueCommand(nil, "inst-1", "cmd-1", job)
	waitUntil(t, "first run", 2*time.Second, func() bool { return ran == 1 })
	time.Sleep(50 * time.Millisecond) // let any stray duplicate run
	if ran != 1 {
		t.Fatalf("command ran %d times, want exactly 1", ran)
	}
	// After the clean run (MarkProcessed): acked, still not re-run.
	d.enqueueCommand(nil, "inst-1", "cmd-1", job)
	time.Sleep(100 * time.Millisecond)
	if ran != 1 {
		t.Fatalf("processed command re-ran: %d", ran)
	}
}

// F2: a full instance queue (long turn + backlog) must DROP the overflow
// instead of blocking the read loop, and the drop must release the dedup
// claim so the server's re-send can be enqueued on the next tick.
func TestEnqueueCommand_OverflowDropsAndReleasesClaim(t *testing.T) {
	d := newTestDaemon(t)
	gate := make(chan struct{})
	started := make(chan struct{})
	d.enqueueCommand(nil, "inst-2", "cmd-head", func() { close(started); <-gate })
	// The head job must be RUNNING (not merely queued) so the channel's
	// full 64 slots are free for the fillers.
	waitUntil(t, "head job running", 2*time.Second, func() bool {
		select {
		case <-started:
			return true
		default:
			return false
		}
	})
	// Fill the 64-slot channel behind the running head job.
	for i := 0; i < 64; i++ {
		if !d.enqueueInstance("inst-2", func() {}) {
			t.Fatalf("slot %d: queue should not be full yet", i)
		}
	}
	// Overflow: must return false (drop), never block.
	if d.enqueueInstance("inst-2", func() {}) {
		t.Fatal("overflow enqueue must drop, not block/accept")
	}
	d.enqueueCommand(nil, "inst-2", "cmd-new", func() {})
	d.seenMu.Lock()
	_, claimed := d.seen["cmd-new"]
	d.seenMu.Unlock()
	if claimed {
		t.Fatal("overflow drop must release the claim (re-send must run)")
	}
	close(gate)
}

// stubAdapter satisfies the runtime.Adapter contract for launch-path
// tests (no real process is spawned).
type stubAdapter struct{}

func (stubAdapter) Name() domain.RuntimeName { return domain.RuntimeFake }
func (stubAdapter) StartTurn(context.Context, agentruntime.TurnSpec, chan agentruntime.TurnEvent) error {
	return nil
}
func (stubAdapter) Stop(string) error          { return nil }
func (stubAdapter) Available() bool            { return true }
func (stubAdapter) BinaryPath() (string, bool) { return "stub", true }
func (stubAdapter) PID(string) *int            { return nil }
func (stubAdapter) InteractiveCmd(agentruntime.TurnSpec) (*exec.Cmd, error) {
	return nil, errors.New("stub adapter has no interactive process")
}

// F4: two CONCURRENT read-write launches on the same repository (parallel
// per-instance queues) must not both decide they are the first RW agent —
// exactly one keeps the main checkout, the other gets a worktree.
func TestConcurrentRWLaunches_ExactlyOneKeepsCheckout(t *testing.T) {
	repo := t.TempDir()
	gitInitRepo(t, repo)
	d, err := New(Config{StateDir: t.TempDir(), AllowedRoots: []string{repo}}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	d.adapters[domain.RuntimeFake] = stubAdapter{}
	t.Cleanup(func() { d.Close() })

	for iter := 0; iter < 5; iter++ {
		// Fresh state per iteration: the "first RW keeps the checkout"
		// decision depends on the existing rows, and rows persist.
		rows, _ := d.state.ListInstances()
		for _, row := range rows {
			_ = d.state.DeleteInstance(row.InstanceID)
		}
		idA, idB := domain.NewID().String(), domain.NewID().String()
		var wg sync.WaitGroup
		goLaunch := func(id, name string) {
			defer wg.Done()
			_ = d.doLaunch(nil, transport.LaunchAgentPayload{
				InstanceID:    id,
				WorkspacePath: repo,
				AgentName:     name,
				Access:        domain.AccessReadWrite,
				Runtime:       string(domain.RuntimeFake),
			})
		}
		wg.Add(2)
		go goLaunch(idA, "race-a")
		go goLaunch(idB, "race-b")
		wg.Wait()

		ra, _, _ := d.state.GetInstance(idA)
		rb, _, _ := d.state.GetInstance(idB)
		if ra == nil || rb == nil {
			t.Fatalf("iteration %d: missing instance row", iter)
		}
		aKept := ra.Workspace == repo
		bKept := rb.Workspace == repo
		if aKept == bKept {
			t.Fatalf("iteration %d: both kept=%v (workspaces %q / %q) — §29 race",
				iter, aKept, ra.Workspace, rb.Workspace)
		}
		for _, row := range []*InstanceRow{ra, rb} {
			if row.Workspace != repo {
				wt := filepath.Join(repo, ".pagnet", "worktrees", row.InstanceID)
				// repoCommonDir resolves symlinks (git stores canonical
				// gitdirs), so the worktree path is canonical even when
				// repo is not (macOS /tmp -> /private/tmp).
				if resolved, err := filepath.EvalSymlinks(wt); err == nil {
					wt = resolved
				}
				if row.Workspace != wt {
					t.Fatalf("iteration %d: unexpected workspace %q", iter, row.Workspace)
				}
				if fi, err := os.Stat(wt); err != nil || !fi.IsDir() {
					t.Fatalf("iteration %d: worktree %s not created", iter, wt)
				}
			}
		}
	}
}

// F12: a forget (server-side delete) removes the local row and the
// isolated worktree — but keeps the branch (the work product stays
// reachable).
func TestDoForget_RemovesWorktreeKeepsBranch(t *testing.T) {
	repo := t.TempDir()
	gitInitRepo(t, repo)
	d, err := New(Config{StateDir: t.TempDir(), AllowedRoots: []string{repo}}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	d.adapters[domain.RuntimeFake] = stubAdapter{}
	t.Cleanup(func() { d.Close() })

	id1, id2 := domain.NewID().String(), domain.NewID().String()
	for _, id := range []string{id1, id2} {
		if err := d.doLaunch(nil, transport.LaunchAgentPayload{
			InstanceID:    id,
			WorkspacePath: repo,
			AgentName:     "fg-coder",
			Access:        domain.AccessReadWrite,
			Runtime:       string(domain.RuntimeFake),
		}); err != nil {
			t.Fatalf("launch %s: %v", id, err)
		}
	}
	row2, _, _ := d.state.GetInstance(id2)
	if row2 == nil || row2.Workspace == repo {
		t.Fatalf("second launch should be in a worktree: %+v", row2)
	}
	branch := worktreeBranch("fg-coder", id2)

	if err := d.doForget(nil, id2); err != nil {
		t.Fatalf("forget: %v", err)
	}
	if _, ok, _ := d.state.GetInstance(id2); ok {
		t.Fatal("local row must be deleted by forget")
	}
	if fi, err := os.Stat(row2.Workspace); err == nil && fi.IsDir() {
		t.Fatalf("worktree dir must be removed: %s", row2.Workspace)
	}
	out, err := exec.Command("git", "-C", repo, "branch", "--list", branch).CombinedOutput()
	if err != nil {
		t.Fatalf("git branch: %v", err)
	}
	if !strings.Contains(string(out), branch) {
		t.Fatalf("branch %s must be kept (work product), git says: %s", branch, out)
	}
}

// F3: Close cancels the turn context (adapters kill the turn subprocess
// via ctx) — a SIGTERM mid-turn must not orphan the process.
func TestClose_CancelsTurnContext(t *testing.T) {
	d := newTestDaemon(t)
	if d.turnCtx.Err() != nil {
		t.Fatal("turn ctx must start live")
	}
	if err := d.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if d.turnCtx.Err() == nil {
		t.Fatal("Close must cancel the turn context")
	}
}

// F3: state left 'working' by a dead previous run is reconciled at
// startup (process-per-turn: the subprocess is gone; the server's
// re-send of the un-acked command re-wakes the instance).
func TestReconcileRestart(t *testing.T) {
	d := newTestDaemon(t)
	for _, c := range []struct {
		id, session string
		want        string
	}{
		{"inst-w1", "sess-1", "hibernated"},
		{"inst-w2", "", "idle"},
		{"inst-h1", "sess-2", "hibernated"}, // already hibernated: untouched
	} {
		st := "working"
		if c.want == "hibernated" && c.id == "inst-h1" {
			st = "hibernated"
		}
		if err := d.state.UpsertInstance(InstanceRow{
			InstanceID: c.id, DefinitionID: "def", Runtime: "fake",
			Status: st, SessionID: c.session,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := d.state.ReconcileRestart(); err != nil {
		t.Fatal(err)
	}
	for _, want := range []struct{ id, status string }{
		{"inst-w1", "hibernated"}, {"inst-w2", "idle"}, {"inst-h1", "hibernated"},
	} {
		row, ok, _ := d.state.GetInstance(want.id)
		if !ok || row.Status != want.status {
			t.Fatalf("%s status = %+v, want %s", want.id, row, want.status)
		}
	}
}

// F9: a symlink under an allowed root that points OUTSIDE it must be
// refused (even for a target that does not exist yet), while real
// subpaths stay allowed.
func TestWorkspaceAllowed_SymlinkEscape(t *testing.T) {
	d := newTestDaemon(t)
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "sneaky")); err != nil {
		t.Fatal(err)
	}
	d.AllowedRoots = []string{root}

	if d.workspaceAllowed(filepath.Join(root, "sneaky", "does-not-exist")) {
		t.Fatal("symlink escape to outside the allowed root must be refused")
	}
	if d.workspaceAllowed(filepath.Join(root, "sneaky")) {
		t.Fatal("the symlink itself must not be an allowed workspace")
	}
	if !d.workspaceAllowed(filepath.Join(root, "real-repo")) {
		t.Fatal("a real subpath of the allowed root must be allowed")
	}
}
