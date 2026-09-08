package daemon

// Git work isolation (spec §29): if two read/write agents run on the same
// physical clone they must not blindly edit the same checkout. The first
// RW agent keeps the current checkout; each subsequent RW agent on the
// same repository gets an automatic worktree at
//
//	<checkout>/.pagnet/worktrees/<instance-id>/
//
// on a branch `pagnet/<agent-name>/<short-id>`. Read-only agents share
// the checkout. If worktree creation is unsafe because of repository
// state, fail clearly — never silently corrupt work.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"pagnet/internal/domain"
	"pagnet/internal/transport"
)

func gitOut(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git %s: %v: %s",
			strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

func isGitRepo(path string) bool {
	out, err := gitOut(path, "rev-parse", "--is-inside-work-tree")
	return err == nil && out == "true"
}

// repoCommonDir is the canonical identity of the repository containing
// path: the directory holding the shared .git data. A normal checkout and
// all of its linked worktrees resolve to the SAME common dir, which is
// exactly the identity "same repository" needs.
func repoCommonDir(path string) (string, error) {
	out, err := gitOut(path, "rev-parse", "--git-common-dir")
	if err != nil {
		return "", err
	}
	dir := out
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(path, dir)
	}
	abs, err := filepath.Abs(filepath.Clean(dir))
	if err != nil {
		return "", err
	}
	return abs, nil
}

var branchUnsafe = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// worktreeBranch is the §29 branch name: pagnet/<agent-name>/<instance-id>.
// The full instance id is used: it is a server-minted UUID (validated at
// the daemon boundary), so it is a safe git ref and globally unique. An
// 8-char prefix was a collision hazard — UUIDv7 ids minted in the same
// millisecond share their first 8 hex chars, and concurrent launches in
// a burst would then fight over one branch.
func worktreeBranch(agentName, instanceID string) string {
	name := strings.ToLower(branchUnsafe.ReplaceAllString(agentName, "-"))
	name = strings.Trim(name, "-")
	if name == "" {
		name = "agent"
	}
	return fmt.Sprintf("pagnet/%s/%s", name, instanceID)
}

// resolveWorkspace applies §29 isolation for a launching instance and
// returns the workspace path the instance actually runs in. The first
// RW agent (and every read-only agent) keeps the given checkout; a
// second+ RW agent on the same repository is moved into a worktree.
func (d *Daemon) resolveWorkspace(p transport.LaunchAgentPayload, access string) (string, error) {
	if access == domain.AccessReadOnly || !isGitRepo(p.WorkspacePath) {
		return p.WorkspacePath, nil
	}
	common, err := repoCommonDir(p.WorkspacePath)
	if err != nil {
		// Not a resolvable git repository (or git missing): run in the
		// checkout as-is — there is nothing to isolate.
		return p.WorkspacePath, nil
	}
	insts, err := d.state.ListInstances()
	if err != nil {
		return "", err
	}
	for _, other := range insts {
		if other.InstanceID == p.InstanceID || other.Status == "stopped" {
			continue
		}
		if other.Access != domain.AccessReadWrite {
			continue
		}
		oc, err := repoCommonDir(other.Workspace)
		if err != nil || oc != common {
			continue
		}
		wt, err := d.ensureWorktree(p.WorkspacePath, common, p.InstanceID,
			worktreeBranch(p.AgentName, p.InstanceID))
		if err != nil {
			return "", err
		}
		return wt, nil
	}
	return p.WorkspacePath, nil
}

// removeWorktree removes the instance's isolated worktree when its
// workspace is a managed one (<checkout>/.pagnet/worktrees/<id>). The
// BRANCH is kept — the work product stays reachable as a branch; only
// the duplicate checkout goes away. Best-effort: a dirty worktree is
// kept and logged, never force-removed.
func (d *Daemon) removeWorktree(row *InstanceRow) {
	wt := row.Workspace
	if filepath.Base(filepath.Dir(wt)) != "worktrees" ||
		filepath.Base(filepath.Dir(filepath.Dir(wt))) != ".pagnet" {
		return
	}
	checkout := filepath.Dir(filepath.Dir(filepath.Dir(wt)))
	if !isGitRepo(checkout) {
		return
	}
	if out, err := gitOut(checkout, "worktree", "remove", wt); err != nil {
		d.Log.Warn("worktree remove failed (kept)", "worktree", wt, "err", err, "out", out)
		return
	}
	d.Log.Info("removed isolated worktree (branch kept)", "worktree", wt)
}

// ensureWorktree creates (or reuses) the worktree for instanceID in the
// repository containing fromRepo. It is idempotent across daemon
// restarts and command replays.
func (d *Daemon) ensureWorktree(fromRepo, common, instanceID, branch string) (string, error) {
	main := filepath.Dir(common) // common is <checkout>/.git
	if filepath.Base(common) != ".git" {
		return "", fmt.Errorf("repository %s has no ordinary checkout (bare repository); "+
			"worktree isolation is not possible", common)
	}
	// SEC-407 (defense in depth): the id becomes a path component inside
	// the user's repository — a non-UUID can never reach the join.
	if _, err := domain.ParseID(instanceID); err != nil {
		return "", fmt.Errorf("invalid instance id for worktree: %s", instanceID)
	}
	wt := filepath.Join(main, ".pagnet", "worktrees", instanceID)

	// Already created (daemon restart / replay)?
	if fi, err := os.Stat(wt); err == nil && fi.IsDir() {
		if oc, err := repoCommonDir(wt); err == nil && oc == common {
			return wt, nil
		}
		return "", fmt.Errorf("refusing to use %s: path exists but is not a worktree of this repository", wt)
	}

	// Create: new branch, or reuse an existing branch (worktree removed
	// but branch kept).
	var out string
	var err error
	if _, verr := gitOut(fromRepo, "rev-parse", "--verify", "--quiet", "refs/heads/"+branch); verr == nil {
		out, err = gitOut(fromRepo, "worktree", "add", wt, branch)
	} else {
		out, err = gitOut(fromRepo, "worktree", "add", "-b", branch, wt)
	}
	if err != nil {
		// §29: fail clearly rather than silently corrupt work.
		return "", fmt.Errorf("git worktree add failed (repository state unsafe?): %v", err)
	}
	d.Log.Info("created git worktree for same-repo isolation",
		"worktree", wt, "branch", branch, "repo", main)
	_ = out
	return wt, nil
}
