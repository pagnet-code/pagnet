//go:build linux || darwin

package fabricnative

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
)

type startupPolicyFunc func(context.Context, fabric.ExecutionContext, func(context.Context) error) error

func (f startupPolicyFunc) WithCurrentOwner(ctx context.Context, owner fabric.ExecutionContext, next func(context.Context) error) error {
	return f(ctx, owner, next)
}
func actualStartupPolicy(owner fabric.Principal) StartupPolicy {
	return startupPolicyFunc(func(ctx context.Context, c fabric.ExecutionContext, next func(context.Context) error) error {
		if c.PrincipalView() != owner {
			return checkpointDenied()
		}
		return next(ctx)
	})
}

func TestActualStartupGuardsOriginalWorkerAfterEndpointRetirementWithoutNativeEffect(t *testing.T) {
	c, value, authorityDir := checkpointFixture(t, registry.DefaultOptions())
	dir, err := os.MkdirTemp("", "pgn-retained-startup-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	binary := filepath.Join(dir, "pagnet")
	root, _ := filepath.Abs("../..")
	build := exec.CommandContext(t.Context(), "go", "build", "-o", binary, "./cmd/pagnet")
	build.Dir = root
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("actual SDK build: %v %s", err, output)
	}
	launch, peers := launcherBinding(t, c, value, binary, dir, authorityDir, "retired-original")
	launcher, err := NewLauncher(LauncherConfig{c, peers, binary, authorityDir, 10 * time.Second, 2})
	if err != nil {
		t.Fatal(err)
	}
	original, err := launcher.Launch(t.Context(), launch)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		child, _ := os.FindProcess(original.Process.PID)
		_ = child.Signal(os.Interrupt)
		launcher.mu.Lock()
		reaped := launcher.processes[launch.Directory]
		launcher.mu.Unlock()
		if reaped != nil {
			select {
			case <-reaped.done:
			case <-time.After(5 * time.Second):
				_ = child.Kill()
				<-reaped.done
			}
		}
	}()
	if err = launcher.Close(); err != nil {
		t.Fatal(err)
	}
	local, _ := launch.Ownership.Local()
	if _, err = c.store.Retire(t.Context(), c.owner, local.Endpoint, local.DescriptorRevision); err != nil {
		t.Fatal(err)
	}
	freshPeers, err := NewManagedPeers(c.store, c.authority, c.owner)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := NewLauncher(LauncherConfig{c, freshPeers, binary, authorityDir, 10 * time.Second, 2})
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	result, err := RecoverStartup(t.Context(), StartupConfig{Checkpoints: c, Launcher: recovered, ControllerBootID: "retained-startup-B", MaxWorkers: 2, MaxMetadataBytes: 1 << 20, Policy: actualStartupPolicy(c.owner.PrincipalView())})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Workers) != 1 {
		t.Fatal("retired original claim was skipped")
	}
	worker := result.Workers[0]
	if worker.Process.PID != original.Process.PID || worker.Process.Start != original.Process.Start || worker.Ownership != launch.Ownership {
		t.Fatal("startup recreated original worker")
	}
	if freshPeers.ValidateOwner(t.Context(), worker.Process) == nil {
		t.Fatal("retired managed worker was granted owner identity")
	}
	snapshot, err := worker.Client.Call(t.Context(), sessionworker.LocalRequest{Type: "snapshot"})
	if err != nil || snapshot.Snapshot == nil || snapshot.Snapshot.PID != 0 || snapshot.Snapshot.NativeSessionID != "" {
		t.Fatal("startup admitted paid native effect", err)
	}
}

func TestStartupRejectsUnresolvedDuplicateAndOverBudgetClaimsBeforeAdoption(t *testing.T) {
	for _, mode := range []string{"missing-original", "duplicate-directory", "over-workers", "over-bytes", "physical-duplicate-claim"} {
		t.Run(mode, func(t *testing.T) {
			c, value, authorityDir := checkpointFixture(t, registry.DefaultOptions())
			dir, err := os.MkdirTemp("", "pgn-startup-fence-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(dir)
			first, peers := launcherBinding(t, c, value, "/bin/true", dir, authorityDir, "first-retained")
			if _, err = c.BeginLaunch(t.Context(), first.Ownership, "first", first.Directory); err != nil {
				t.Fatal(err)
			}
			workers := 2
			metadata := 1 << 20
			if mode == "duplicate-directory" || mode == "over-workers" {
				second := additionalLauncherBinding(t, c, first, "second-retained")
				if mode == "duplicate-directory" {
					second.Directory = first.Directory
				}
				if _, err = c.BeginLaunch(t.Context(), second.Ownership, "second", second.Directory); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "over-workers" {
				workers = 1
			}
			if mode == "over-bytes" {
				metadata = 1024
			}
			if mode == "physical-duplicate-claim" {
				if _, err = c.BeginLaunch(t.Context(), first.Ownership, "changed-attempt", filepath.Join(dir, "different-directory")); err == nil {
					t.Fatal("same physical claim duplicated")
				}
			}
			launcher, err := NewLauncher(LauncherConfig{c, peers, "/bin/true", authorityDir, time.Second, 2})
			if err != nil {
				t.Fatal(err)
			}
			defer launcher.Close()
			result, err := RecoverStartup(t.Context(), StartupConfig{Checkpoints: c, Launcher: launcher, ControllerBootID: "missing-startup", MaxWorkers: workers, MaxMetadataBytes: metadata, Policy: actualStartupPolicy(c.owner.PrincipalView())})
			if err == nil || len(result.Workers) != 0 {
				t.Fatal("unresolved startup allowed owner listener")
			}
			if len(launcher.processes) != 0 || len(launcher.clients) != 0 {
				t.Fatal("invalid collection created or adopted worker")
			}
			if _, err = os.Stat(first.Directory); !os.IsNotExist(err) {
				t.Fatal("startup recreated bootstrap")
			}
		})
	}
}
func TestStartupPolicyCannotSkipSwallowRepeatOrEscapeClassification(t *testing.T) {
	for _, mode := range []string{"skip", "swallow", "repeat", "escape"} {
		t.Run(mode, func(t *testing.T) {
			c, value, authorityDir := checkpointFixture(t, registry.DefaultOptions())
			dir, err := os.MkdirTemp("", "pgn-startup-policy-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(dir)
			spec, peers := launcherBinding(t, c, value, "/bin/true", dir, authorityDir, "policy-original")
			if _, err = c.BeginLaunch(t.Context(), spec.Ownership, "uncertain", spec.Directory); err != nil {
				t.Fatal(err)
			}
			launcher, err := NewLauncher(LauncherConfig{c, peers, "/bin/true", authorityDir, time.Second, 1})
			if err != nil {
				t.Fatal(err)
			}
			defer launcher.Close()
			var escaped func(context.Context) error
			policy := startupPolicyFunc(func(ctx context.Context, _ fabric.ExecutionContext, next func(context.Context) error) error {
				switch mode {
				case "skip":
					return nil
				case "escape":
					escaped = next
					return nil
				case "swallow":
					_ = next(ctx)
					return nil
				case "repeat":
					_ = next(ctx)
					_ = next(ctx)
					return nil
				}
				return checkpointDenied()
			})
			result, err := RecoverStartup(t.Context(), StartupConfig{Checkpoints: c, Launcher: launcher, ControllerBootID: "policy-startup", MaxWorkers: 1, MaxMetadataBytes: 1 << 20, Policy: policy})
			if err == nil || len(result.Workers) != 0 {
				t.Fatal("policy bypassed startup classification")
			}
			if escaped != nil && escaped(t.Context()) == nil {
				t.Fatal("late callback admitted classification")
			}
			if len(launcher.clients) != 0 || len(launcher.processes) != 0 {
				t.Fatal("policy reached worker replacement")
			}
		})
	}
}

func TestStartupCollectsAllSignedClaimPagesBeforeAnyAdoption(t *testing.T) {
	c, value, authorityDir := checkpointFixture(t, registry.DefaultOptions())
	dir, err := os.MkdirTemp("", "pgn-startup-pages-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	original, peers := launcherBinding(t, c, value, "/bin/true", dir, authorityDir, "page-original")
	if _, err = c.BeginLaunch(t.Context(), original.Ownership, "page-original", original.Directory); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 32; i++ {
		name := fmt.Sprintf("page-worker-%02d", i)
		additional := additionalLauncherBinding(t, c, original, name)
		if _, err = c.BeginLaunch(t.Context(), additional.Ownership, name, additional.Directory); err != nil {
			t.Fatal(err)
		}
	}
	launcher, err := NewLauncher(LauncherConfig{c, peers, "/bin/true", authorityDir, time.Second, 33})
	if err != nil {
		t.Fatal(err)
	}
	defer launcher.Close()
	config := StartupConfig{Checkpoints: c, Launcher: launcher, ControllerBootID: "paged-startup", MaxWorkers: 33, MaxMetadataBytes: 1 << 20, Policy: actualStartupPolicy(c.owner.PrincipalView())}
	claims, err := collectStartupClaims(t.Context(), config)
	if err != nil || len(claims) != 33 {
		t.Fatal("signed claim page boundary was truncated", len(claims), err)
	}
	for _, claim := range claims {
		if claim.Observed != nil {
			t.Fatal("collection fabricated process observation")
		}
		if _, err = os.Stat(claim.Directory); !os.IsNotExist(err) {
			t.Fatal("collection prepared worker")
		}
	}
	if len(launcher.clients) != 0 || len(launcher.processes) != 0 {
		t.Fatal("enumeration adopted before final page")
	}
	config.MaxWorkers = 32
	if _, err = collectStartupClaims(t.Context(), config); err == nil {
		t.Fatal("last signed page bypassed finite count budget")
	}
}
