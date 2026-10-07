//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/localpeer"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

func TestDetachedNativeWorkerPreservesFilteredExecutionEnvironment(t *testing.T) {
	r, scope, spec := nativeRegistryFixture(t)
	bin := t.TempDir()
	build := func(name, pkg string) string {
		path := filepath.Join(bin, name)
		cmd := exec.Command("go", "build", "-o", path, pkg)
		cmd.Dir = "../.."
		cmd.Env = append(os.Environ(), "GOWORK=off")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("fixture build: %v %s", err, output)
		}
		return path
	}
	worker := build("pagnet", "./cmd/pagnet")
	native := build("native-real", "./cmd/pagnet-fake-runtime")
	launcher := filepath.Join(bin, "native-shebang")
	interpreter := filepath.Join(bin, "fixture-node")
	marker := filepath.Join(spec.Workspace, "environment-ok")
	// The vendor executable exists outside standard PATH; its interpreter is
	// found only in the launching daemon's PATH, just like an NVM installation.
	if err := os.WriteFile(launcher, []byte("#!/usr/bin/env fixture-node\n"), 0700); err != nil {
		t.Fatal(err)
	}
	probe := fmt.Sprintf("#!/bin/sh\n[ \"$ANTHROPIC_API_KEY\" = inherited-provider-fixture ] || exit 21\n[ \"$OPENAI_API_KEY\" = configured-provider-fixture ] || exit 22\n[ -z \"$GH_TOKEN\" ] || exit 23\n[ -z \"$DATABASE_URL\" ] || exit 24\n[ \"$LANG\" = C.UTF-8 ] || exit 25\nprintf ok > %q\nshift\nexec %q \"$@\"\n", marker, native)
	if err := os.WriteFile(interpreter, []byte(probe), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	t.Setenv("ANTHROPIC_API_KEY", "inherited-provider-fixture")
	t.Setenv("OPENAI_API_KEY", "inherited-overridden-fixture")
	t.Setenv("GH_TOKEN", "untrusted-shell-secret-fixture")
	t.Setenv("DATABASE_URL", "untrusted-database-secret-fixture")
	t.Setenv("LANG", "C.UTF-8")
	spec.Binary, spec.MCPExecutable = launcher, worker
	spec.Env = []string{"OPENAI_API_KEY=configured-provider-fixture"}
	record, err := r.Reserve(scope, spec, "", "")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	if err = EnsureNativeWorker(ctx, r, record, worker, spec.Env, ""); err != nil {
		t.Fatal(err)
	}
	_, key, err := sessionworker.LoadControllerBootstrap(record.Dir, scope)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	socket, err := sessionworker.SocketPath(record.Dir)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	pid, _, err := localpeer.Owner(peer)
	peer.Close()
	if err != nil || pid <= 0 {
		t.Fatal("worker identity unavailable", err)
	}
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGTERM) })
	controller, err := sessionworker.DialOwnerController(ctx, record.Dir, scope, key, "environment-proof")
	if err != nil {
		t.Fatal(err)
	}
	defer controller.Close()
	call := func(req sessionworker.Request) sessionworker.Response {
		t.Helper()
		response, err := controller.Call(ctx, req)
		if err != nil || response.Error != "" {
			t.Fatal("original worker request failed", req.Type, err, response.Error)
		}
		return response
	}
	admission := sessionworker.Admission{NativeAdmissionID: domain.NewID().String(), Scope: scope, TenantID: scope.TenantID, NetworkID: spec.NetworkID, Kind: "worker", RunnerID: domain.NewID().String(), RunnerEpoch: time.Now().UTC(), BootID: domain.NewID().String()}
	call(sessionworker.Request{Type: "admission", Admission: &admission})
	command := domain.NewID().String()
	payload, _ := json.Marshal(sessionworker.Operation{SourceCommandID: command, InputKind: "user_input"})
	call(sessionworker.Request{Type: "intent", Sequence: 1, CommandID: command, Kind: "attach", Payload: payload})
	for {
		response := call(sessionworker.Request{Type: "activation_poll"})
		if response.Activation != nil {
			request := response.Activation
			origin := transport.NativeObservationOrigin{ID: domain.NewID().String(), CommandID: command, TenantID: scope.TenantID, HostID: scope.HostID, InstanceID: scope.InstanceID, Runtime: string(spec.Runtime), NativeGeneration: request.NativeGeneration, NativeAdmissionID: admission.NativeAdmissionID, RunnerID: admission.RunnerID, RunnerEpoch: admission.RunnerEpoch, BootID: admission.BootID, CreatedAt: time.Now().UTC()}
			raw, _ := json.Marshal(origin)
			call(sessionworker.Request{Type: "activation_origin", ActivationOrigin: &sessionworker.ActivationOrigin{ID: request.ID, NativeGeneration: request.NativeGeneration, Origin: raw}})
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("original activation gate did not appear")
		case <-time.After(5 * time.Millisecond):
		}
	}
	for {
		response := call(sessionworker.Request{Type: "outcome", Sequence: 1})
		if response.Outcome != nil && response.Outcome.State != "admitted" {
			if response.Outcome.State != "completed" {
				t.Fatal("custom-PATH shebang runtime did not activate", response.Outcome.State)
			}
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("original runtime did not activate")
		case <-time.After(5 * time.Millisecond):
		}
	}
	if data, err := os.ReadFile(marker); err != nil || string(data) != "ok" {
		t.Fatal("runtime did not receive filtered inherited and configured environment", err)
	}
	snapshot := call(sessionworker.Request{Type: "snapshot"}).Snapshot
	if snapshot == nil || snapshot.PID <= 0 || !snapshot.HasTerminal || snapshot.NativeSessionID == "" {
		t.Fatal("original interactive endpoint missing")
	}
	if runtime.GOOS == "linux" {
		raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(raw, []byte("provider-fixture")) || bytes.Contains(raw, []byte("secret-fixture")) || bytes.Contains(raw, []byte(bin)) {
			t.Fatal("worker process inherited runtime secrets or runtime PATH")
		}
	}
	// Credentials pass through a private inherited pipe, not persistent
	// bootstrap/profile/journal records or the worker's own process environment.
	for _, name := range []string{"bootstrap.json", "intents.sqlite", "intents.sqlite-wal"} {
		raw, err := os.ReadFile(filepath.Join(record.Dir, name))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{"inherited-provider-fixture", "configured-provider-fixture", "untrusted-shell-secret-fixture", "untrusted-database-secret-fixture"} {
			if bytes.Contains(raw, []byte(secret)) {
				t.Fatal("runtime credential persisted", name)
			}
		}
	}
}
