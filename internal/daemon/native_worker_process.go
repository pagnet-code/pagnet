//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	agentruntime "github.com/pagnet-code/pagnet/internal/runtime"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
)

// EnsureNativeWorker launches a reserved original worker at most once. Socket
// readiness is not authentication: callers MUST next use AttachNativeWorker.
// Cancellation, TCP disconnect and daemon Close never kill this process. An
// unavailable previously launched owner requires explicit recovery, not restart.
func EnsureNativeWorker(ctx context.Context, r *NativeWorkerRegistry, record NativeWorkerRecord, binary string, runtimeEnv []string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !filepath.IsAbs(binary) {
		return errors.New("native worker binary must be absolute")
	}
	if err := agentruntime.ValidateExtraEnv(runtimeEnv); err != nil {
		return err
	}
	envRaw, err := json.Marshal(runtimeEnv)
	if err != nil || len(envRaw) > 128<<10 {
		return errors.New("native worker environment exceeds bound")
	}
	defer clear(envRaw)
	current, err := r.Lookup(record.Scope.InstanceID)
	if err != nil {
		return err
	}
	if current.Scope != record.Scope || current.Dir != record.Dir || current.ProfileFingerprint != record.ProfileFingerprint {
		return errors.New("native worker launch identity conflict")
	}
	if current.LaunchState == "reserved" {
		r.mu.Lock()
		err = r.prepare(current)
		if err != nil {
			r.mu.Unlock()
			return err
		}
		result, claimErr := r.db.Exec(`UPDATE native_workers SET launch_state='launching' WHERE instance_id=? AND launch_state='reserved'`, current.Scope.InstanceID)
		r.mu.Unlock()
		if claimErr != nil {
			return claimErr
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if n == 1 {
			input, output, err := os.Pipe()
			if err != nil {
				return err
			}
			defer input.Close()
			defer output.Close()
			cmd := exec.Command(binary, sessionworker.Subcommand, "--state", current.Dir, "--env-fd", "3")
			cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
			cmd.ExtraFiles = []*os.File{input}
			// Do not inherit controller credentials, sockets, stdio, or provider env.
			cmd.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin"}
			if home, err := os.UserHomeDir(); err == nil {
				cmd.Env = append(cmd.Env, "HOME="+home)
			}
			if err = cmd.Start(); err != nil {
				// No process was started. Only this exact claim can become retryable.
				_, _ = r.db.Exec(`UPDATE native_workers SET launch_state='reserved' WHERE instance_id=? AND launch_state='launching'`, current.Scope.InstanceID)
				return err
			}
			_ = input.Close()
			_, markErr := r.db.Exec(`UPDATE native_workers SET launch_state='launched' WHERE instance_id=? AND launch_state='launching'`, current.Scope.InstanceID)
			// Reap when this controller remains alive; the child is independent when it
			// exits. Never use CommandContext or cancel/kill the original process.
			go func() { _ = cmd.Wait() }()
			// Bounded private pipe; writer closure ensures original worker sees EOF.
			written := make(chan error, 1)
			go func() {
				_, writeErr := io.Copy(output, bytes.NewReader(envRaw))
				_ = output.Close()
				written <- writeErr
			}()
			select {
			case err = <-written:
				if err != nil {
					return err
				}
			case <-ctx.Done():
				_ = output.Close()
				<-written
				return ctx.Err()
			}
			if markErr != nil {
				return markErr
			}
		}
	}
	path, err := sessionworker.SocketPath(current.Dir)
	if err != nil {
		return err
	}
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		info, err := os.Lstat(path)
		if err == nil {
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok || stat.Uid != uint32(os.Getuid()) || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0600 {
				return errors.New("native worker readiness path is not a private socket")
			}
			return nil
		}
		if !os.IsNotExist(err) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errors.New("original native worker unavailable; automatic replacement forbidden")
		case <-tick.C:
		}
	}
}
