//go:build linux || darwin

package sessionworker

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/session"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestActualVendorOwnerAcrossControllerReplacement(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp("", "pgn-vendor-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	binaries := filepath.Join(dir, "b", "bin")
	if err := os.MkdirAll(binaries, 0700); err != nil {
		t.Fatal(err)
	}
	worker := filepath.Join(binaries, "pagnet")
	aBinary := filepath.Join(binaries, "controller-a")
	bBinary := filepath.Join(binaries, "controller-b")
	native := filepath.Join(binaries, "native")
	testBinary(t, root, worker, "./cmd/pagnet", "-X main.version=worker-original")
	testBinary(t, root, aBinary, "./internal/sessionworker/testdata/controller", "-X main.build=controller-a")
	testBinary(t, root, bBinary, "./internal/sessionworker/testdata/controller", "-X main.build=controller-b")
	build := exec.Command("go", "test", "-c", "-o", native, "./internal/runtime")
	build.Dir = root
	build.Env = append(os.Environ(), "GOWORK=off")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("synthetic vendor executable build: %v %s", err, output)
	}
	for _, fixture := range []struct {
		runtime domain.RuntimeName
		mode    string
	}{{domain.RuntimeClaudeCode, "claude-stream-fixture"}, {domain.RuntimeOpenCode, "opencode-acp-fixture"}} {
		t.Run(string(fixture.runtime), func(t *testing.T) {
			base := filepath.Join(dir, string(fixture.runtime))
			state := filepath.Join(base, "state")
			workspace := filepath.Join(base, "workspace")
			if err := os.MkdirAll(workspace, 0700); err != nil {
				t.Fatal(err)
			}
			tenant := uuid.NewString()
			scope := Scope{ServerURL: "https://control.invalid", TenantID: tenant, AccountID: uuid.NewString(), HostID: uuid.NewString(), InstanceID: uuid.NewString(), Generation: uuid.NewString()}
			key := bytes.Repeat([]byte{19}, 32)
			var nativeDirs []string
			if fixture.runtime == domain.RuntimeClaudeCode {
				nativeDirs = []string{t.TempDir()}
			}
			bootstrap := Bootstrap{Protocol: Protocol, Scope: scope, Native: NativeSpec{Runtime: fixture.runtime, Binary: native, PrefixArgs: []string{fixture.mode}, MCPExecutable: worker, Workspace: workspace, NativeDirs: nativeDirs, Model: "synthetic-model", StandingInstructions: "synthetic standing", NetworkID: uuid.NewString(), Kind: "worker", TenantID: tenant, NetworkTenantID: tenant}}
			if err := PrepareBootstrap(state, bootstrap, key); err != nil {
				t.Fatal(err)
			}
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			command := exec.Command(worker, Subcommand, "--state", state, "--env-fd", "3")
			command.ExtraFiles = []*os.File{reader}
			var workerErrors bytes.Buffer
			command.Stderr = &workerErrors
			if err = command.Start(); err != nil {
				t.Fatal(err)
			}
			reader.Close()
			t.Cleanup(func() { command.Process.Kill(); command.Wait() })
			if err = json.NewEncoder(writer).Encode([]string{}); err != nil {
				t.Fatal(err)
			}
			writer.Close()
			waitPath(t, filepath.Join(state, "controller.sock"))
			a := startController(t, aBinary, state)
			admission := Admission{NativeAdmissionID: uuid.NewString(), Scope: scope, TenantID: tenant, NetworkID: bootstrap.Native.NetworkID, Kind: "worker", RunnerID: uuid.NewString(), RunnerEpoch: time.Now().UTC(), BootID: uuid.NewString()}
			if response := a.call(t, Request{Type: "admission", Admission: &admission}); response.Error != "" {
				t.Fatal(response.Error)
			}
			if response := a.intent(t, 1, "activation", "activate", Operation{SourceCommandID: "activation"}); response.Error != "" {
				t.Fatal(response.Error)
			}
			var activation *ActivationRequest
			deadline := time.Now().Add(8 * time.Second)
			for time.Now().Before(deadline) {
				response := a.call(t, Request{Type: "activation_poll"})
				if response.Error != "" {
					t.Fatal(response.Error)
				}
				if response.Activation != nil {
					activation = response.Activation
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if activation == nil {
				t.Fatal("native source activation missing")
			}
			if snapshot := a.snapshot(t); snapshot.PID != 0 {
				t.Fatal("native spawned before original source authority")
			}
			origin := json.RawMessage(fmt.Sprintf(`{"id":%q,"commandId":"activation","tenantId":%q,"hostId":%q,"instanceId":%q,"runtime":%q,"nativeGeneration":%q,"nativeAdmissionId":%q,"runnerId":%q,"runnerEpoch":%q,"bootId":%q,"createdAt":%q}`, uuid.NewString(), tenant, scope.HostID, scope.InstanceID, fixture.runtime, activation.NativeGeneration, admission.NativeAdmissionID, admission.RunnerID, admission.RunnerEpoch.Format(time.RFC3339Nano), admission.BootID, time.Now().UTC().Format(time.RFC3339Nano)))
			if response := a.call(t, Request{Type: "activation_origin", ActivationOrigin: &ActivationOrigin{ID: activation.ID, NativeGeneration: activation.NativeGeneration, Origin: origin}}); response.Error != "" {
				t.Fatal(response.Error)
			}
			if outcome := a.outcome(t, 1); outcome.State != "completed" {
				t.Fatalf("native activation failed: %s", outcome.State)
			}
			initial := a.snapshot(t)
			if initial.PID <= 0 || initial.NativeStartIdentity == "" || initial.NativeSessionID == "" || initial.HasTerminal {
				t.Fatal("invalid original machine endpoint identity or invented PTY")
			}
			if response := a.intent(t, 2, "first", "prompt", Operation{SourceCommandID: "first", Input: "first", InputKind: "task"}); response.Error != "" {
				t.Fatal(response.Error)
			}
			if outcome := a.outcome(t, 2); outcome.State != "completed" {
				t.Fatal("first native prompt failed")
			}
			b := startController(t, bBinary, state)
			if b.lease <= a.lease || b.build == a.build {
				t.Fatal("controller replacement was not independently fenced")
			}
			if response := a.call(t, Request{Type: "snapshot"}); response.Error == "" {
				t.Fatal("superseded controller remained authorized")
			}
			a.close()
			admission.NativeAdmissionID = uuid.NewString()
			admission.RunnerID = uuid.NewString()
			admission.RunnerEpoch = time.Now().UTC()
			admission.BootID = uuid.NewString()
			if response := b.call(t, Request{Type: "admission", Admission: &admission}); response.Error != "" {
				t.Fatal(response.Error)
			}
			if response := b.intent(t, 3, "second", "prompt", Operation{SourceCommandID: "second", Input: "second", InputKind: "task"}); response.Error != "" {
				t.Fatal(response.Error)
			}
			if outcome := b.outcome(t, 3); outcome.State != "completed" {
				t.Fatal("second native prompt failed")
			}
			after := b.snapshot(t)
			if after.PID != initial.PID || after.NativeStartIdentity != initial.NativeStartIdentity || after.NativeSessionID != initial.NativeSessionID || after.NativeGeneration != initial.NativeGeneration || !bytes.Equal(after.Origin, initial.Origin) {
				t.Fatal("controller replacement changed native PID, birth, session or original source")
			}
			response := b.call(t, Request{Type: "observations", Limit: 32})
			if response.Error != "" {
				t.Fatal(response.Error)
			}
			complete := map[string]bool{}
			for _, observation := range response.Observations {
				if observation.Event.Type != session.EventTurnCompleted {
					continue
				}
				if observation.NativeGeneration != initial.NativeGeneration || !bytes.Equal(observation.Origin, origin) || observation.TurnSource == nil || observation.Capture == nil {
					t.Fatal("native outcome lacked original source-bound encrypted capture")
				}
				complete[observation.TurnSource.SourceCommandID] = true
				chunk := b.call(t, Request{Type: "source_capture", ObservationID: observation.ID, SourceDigest: observation.SourceDigest})
				if chunk.Error != "" || chunk.Capture == nil {
					t.Fatal("encrypted source capture unavailable")
				}
				plain, err := OpenNativeCapture(key, scope, state, observation, chunk.Capture.Data)
				if err != nil {
					t.Fatal(err)
				}
				var source NativeSourceCapture
				if json.Unmarshal(plain, &source) != nil || source.Event.SessionID != initial.NativeSessionID {
					t.Fatal("original capture authentication failed")
				}
				clear(plain)
			}
			if !complete["first"] || !complete["second"] {
				t.Fatal("original delivery sources did not survive controller replacement")
			}
			if response := b.intent(t, 4, "stop", "stop", Operation{}); response.Error != "" {
				t.Fatal(response.Error)
			}
			if outcome := b.outcome(t, 4); outcome.State != "completed" {
				t.Fatal("source-safe native retirement failed")
			}
			stopped := false
			retirementPage := b.call(t, Request{Type: "observations", Limit: 32})
			if retirementPage.Error != "" {
				t.Fatal(retirementPage.Error)
			}
			for _, o := range retirementPage.Observations {
				if o.Event.Type != session.EventSessionStopped {
					continue
				}
				if o.NativeGeneration != initial.NativeGeneration || o.NativeSessionID != initial.NativeSessionID || !bytes.Equal(o.Origin, origin) || NativeSourceType(o) != "host.agent_stopped" {
					t.Fatal("exit lifecycle lacked original proof")
				}
				stopped = true
			}
			if !stopped {
				t.Fatal("supervised stop was retired before original lifecycle capture")
			}
		})
	}
}
