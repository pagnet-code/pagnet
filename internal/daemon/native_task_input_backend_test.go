//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/e2ee"
	hostcrypto "github.com/pagnet-code/pagnet/internal/crypto"
	"github.com/pagnet-code/pagnet/internal/session"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

func TestNativeOriginalTaskInputActualBridgeThroughReplacement(t *testing.T) {
	if os.Getenv("PAGNET_NATIVE_SOURCE_BACKEND_TEST_BINARY") == "" {
		t.Skip("requires isolated actual PostgreSQL backend helper")
	}
	t.Setenv("PAGNET_NATIVE_SOURCE_HELPER_RUNTIME", string(domain.RuntimeFakePersistent))
	binary := filepath.Join(t.TempDir(), "native-fake")
	build := exec.Command("go", "build", "-o", binary, "./cmd/pagnet-fake-runtime")
	build.Dir = "../.."
	build.Env = append(os.Environ(), "GOWORK=off")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("fake compile: %v %s", err, out)
	}
	workerBinary := filepath.Join(filepath.Dir(binary), "pagnet")
	build = exec.Command("go", "build", "-race", "-o", workerBinary, "./cmd/pagnet")
	build.Dir = "../.."
	build.Env = append(os.Environ(), "GOWORK=off")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("worker compile: %v %s", err, out)
	}
	proveOriginalTaskInputBridge(t, binary, workerBinary)
}
func proveOriginalTaskInputBridge(t *testing.T, binary, workerBinary string) {
	helper, fixture := startNativeBackendHelper(t)
	if fixture.Runtime != string(domain.RuntimeFakePersistent) {
		t.Fatal("paired turn helper lacks actual persistent native runtime fixture")
	}
	a := connectNativeBackend(t, fixture, false)
	var activation struct {
		CommandID      string                         `json:"commandId"`
		NativeDispatch *transport.NativeDispatchProof `json:"nativeDispatch"`
	}
	scope := sessionworker.Scope{ServerURL: a.connection.serverURL, TenantID: a.session.TenantID, AccountID: a.session.AccountID, HostID: fixture.HostID, InstanceID: fixture.InstanceID, Generation: domain.NewID().String()}
	dir, err := os.MkdirTemp("", "pgn-turn-proof-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	privateKey := bytes.Repeat([]byte{23}, 32)
	stateDir, err := os.MkdirTemp("", "pgn-task-controller-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(stateDir) })
	daemon, err := New(Config{StateDir: stateDir, Debug: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { daemon.Close() })
	taskKey := bytes.Repeat([]byte{31}, 32)
	ring := &hostcrypto.Keyring{NetworkID: fixture.NetworkID, Epochs: []hostcrypto.KeyEpoch{{ID: fixture.EpochID, State: hostcrypto.EpochActive, Key: taskKey, CreatedAt: time.Now().UTC()}}}
	if err = hostcrypto.SaveKeyring(daemon.StateDir, ring); err != nil {
		t.Fatal(err)
	}
	spec := sessionworker.NativeSpec{Runtime: domain.RuntimeFakePersistent, Binary: binary, MCPExecutable: workerBinary, Workspace: dir, Kind: "worker", TenantID: scope.TenantID, NetworkID: fixture.NetworkID, NetworkTenantID: fixture.TenantID, NetworkStateDir: daemon.StateDir}
	spec.Workspace, err = os.MkdirTemp("", "pgn-task-work-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(spec.Workspace) })
	spec.Env = []string{"PAGNET_FAKE_INTERACTION=question", "PAGNET_FAKE_BRIDGE_CONTROL=1", "PAGNET_FAKE_BRIDGE_RESULT_FILE=" + filepath.Join(spec.Workspace, "native-bridge.json")}
	if err = sessionworker.PrepareBootstrap(dir, sessionworker.Bootstrap{Protocol: sessionworker.Protocol, Scope: scope, Native: spec}, privateKey); err != nil {
		t.Fatal(err)
	}
	readEnv, writeEnv, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(workerBinary, sessionworker.Subcommand, "--state", dir, "--env-fd", "3")
	command.ExtraFiles = []*os.File{readEnv}
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "TEST_DATABASE_URL=") && !strings.HasPrefix(value, "PAGNET_TEST_DSN=") {
			command.Env = append(command.Env, value)
		}
	}
	if err = command.Start(); err != nil {
		t.Fatal(err)
	}
	_ = readEnv.Close()
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	t.Cleanup(func() {
		_ = command.Process.Signal(syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(8 * time.Second):
			_ = command.Process.Kill()
			<-done
			t.Error("actual worker shutdown exceeded bound")
		}
	})
	if err = json.NewEncoder(writeEnv).Encode(spec.Env); err != nil {
		t.Fatal(err)
	}
	_ = writeEnv.Close()
	ownership, err := a.connection.RegisterNativeWorkerOwnership(t.Context(), scope, spec, "", "")
	if err != nil {
		t.Fatal("actual ownership registration", err)
	}
	helper.call(t, map[string]any{"action": "seed_source", "runnerId": a.session.RunnerID, "runnerEpoch": a.session.RunnerEpoch, "bootId": a.session.BootID}, &activation)
	var controllerA *sessionworker.Controller
	deadline := time.Now().Add(5 * time.Second)
	for {
		controllerA, err = sessionworker.DialOwnerController(t.Context(), dir, scope, privateKey, "turn-controller-A")
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("private turn controller A unavailable")
		}
		time.Sleep(5 * time.Millisecond)
	}
	defer controllerA.Close()
	admit := func(peer *nativeBackendPeer, c *sessionworker.Controller) {
		t.Helper()
		grant, err := peer.connection.NativeWorkerAdmission(scope, fixture.NetworkID, "worker")
		if err != nil {
			t.Fatal(err)
		}
		r, err := c.Call(t.Context(), sessionworker.Request{Type: "admission", Admission: &grant})
		if err != nil || r.Error != "" {
			t.Fatal("actual worker admission failed")
		}
	}
	invoke := func(c *sessionworker.Controller, sequence int64, kind string, op sessionworker.Operation, proof *transport.NativeDispatchProof) {
		t.Helper()
		raw, _ := json.Marshal(op)
		r, err := c.Call(t.Context(), sessionworker.Request{Type: "dispatch", Sequence: sequence, CommandID: proof.SourceCommandID, Kind: kind, Payload: raw, NativeDispatch: proof})
		if err != nil || r.Error != "" || r.Outcome == nil {
			t.Fatal("actual native intent admission failed")
		}
	}
	outcome := func(c *sessionworker.Controller, sequence int64) {
		t.Helper()
		deadline := time.Now().Add(8 * time.Second)
		for {
			r, err := c.Call(t.Context(), sessionworker.Request{Type: "outcome", Sequence: sequence})
			if err != nil || r.Error != "" {
				t.Fatal("actual native outcome unavailable")
			}
			if r.Outcome != nil && r.Outcome.State != "admitted" {
				if r.Outcome.State != "completed" {
					if sequence == 1 {
						t.Logf("isolated activation refusal: %s", r.Outcome.Result)
					}
					t.Fatalf("actual native operation did not complete: %s", r.Outcome.State)
				}
				return
			}
			if time.Now().After(deadline) {
				t.Fatal("actual native outcome did not settle")
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	snapshot := func(c *sessionworker.Controller) func(context.Context) (sessionworker.NativeSnapshot, error) {
		return func(ctx context.Context) (sessionworker.NativeSnapshot, error) {
			r, err := c.Call(ctx, sessionworker.Request{Type: "snapshot"})
			if err != nil {
				return sessionworker.NativeSnapshot{}, err
			}
			if r.Error != "" || r.Snapshot == nil {
				return sessionworker.NativeSnapshot{}, errors.New("actual owner snapshot unavailable")
			}
			return *r.Snapshot, nil
		}
	}
	admit(a, controllerA)
	bound, bindErr := controllerA.Call(t.Context(), sessionworker.Request{Type: "ownership_bind", Ownership: ownership})
	if bindErr != nil || bound.Error != "" {
		t.Fatal("actual worker ownership bind failed")
	}
	if activation.NativeDispatch == nil {
		t.Fatal("fixture lacks authenticated activation proof")
	}
	invoke(controllerA, 1, "activate", sessionworker.Operation{SourceCommandID: activation.CommandID, SourceAdmissionID: a.session.NativeAdmissionID, InputKind: "wake"}, activation.NativeDispatch)
	deadline = time.Now().Add(8 * time.Second)
	var origin transport.NativeObservationOrigin
	for {
		r, err := controllerA.Call(t.Context(), sessionworker.Request{Type: "activation_poll"})
		if err != nil || r.Error != "" {
			t.Fatal("actual activation source poll failed")
		}
		if r.Activation != nil {
			authorized, err := a.connection.AuthorizeNativeWorkerActivation(t.Context(), scope, *r.Activation)
			if err != nil {
				t.Fatal("actual origin authorization failed", err)
			}
			if json.Unmarshal(authorized.Origin, &origin) != nil {
				t.Fatal("invalid actual native origin")
			}
			reply, err := controllerA.Call(t.Context(), sessionworker.Request{Type: "activation_origin", ActivationOrigin: &authorized})
			if err != nil || reply.Error != "" {
				t.Fatal("worker rejected actual source admission")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("actual activation gate never requested original source")
		}
		time.Sleep(5 * time.Millisecond)
	}
	outcome(controllerA, 1)
	initial, err := snapshot(controllerA)(t.Context())
	if err != nil || initial.PID <= 0 || initial.NativeStartIdentity == "" || initial.NativeSessionID == "" || initial.NativeGeneration != origin.NativeGeneration {
		t.Fatal("actual native process birth/session missing")
	}
	profileRaw, _ := json.Marshal(spec)
	profile := sha256.Sum256(profileRaw)
	if err = a.connection.ConfirmNativeWorkerSession(t.Context(), scope, origin, hex.EncodeToString(profile[:]), snapshot(controllerA)); err != nil {
		t.Fatal("actual native A kernel proof did not confirm", err)
	}
	if err = a.connection.DrainNativeWorkerSources(t.Context(), controllerA.Call); err != nil {
		t.Fatal("actual initial session observation did not commit", err)
	}
	taskID := domain.NewID().String()
	aad := e2ee.AAD{ProtocolVersion: transport.ProtocolVersion, TenantID: fixture.TenantID, NetworkID: fixture.NetworkID, ObjectType: e2ee.ObjectTypeTask, ObjectID: taskID, Sender: fixture.InstanceID, Recipient: fixture.InstanceID, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), KeyEpochID: fixture.EpochID}
	var key [32]byte
	copy(key[:], taskKey)
	originalBody := "private original accepted task instruction"
	originalEnvelope, err := e2ee.Encrypt([]byte(originalBody), key, aad)
	if err != nil {
		t.Fatal(err)
	}
	var task struct {
		CommandID      string                         `json:"commandId"`
		TaskID         string                         `json:"taskId"`
		TaskSource     *transport.NativeTaskSource    `json:"taskSource"`
		NativeDispatch *transport.NativeDispatchProof `json:"nativeDispatch"`
	}
	helper.call(t, map[string]any{"action": "seed_encrypted_task_source", "runnerId": a.session.RunnerID, "runnerEpoch": a.session.RunnerEpoch, "bootId": a.session.BootID, "nativeAdmissionId": a.session.NativeAdmissionID, "taskAAD": aad, "taskEnvelope": originalEnvelope}, &task)
	if task.NativeDispatch == nil || task.TaskSource == nil || task.TaskID != taskID || !bytes.Equal(task.TaskSource.InputAAD.CanonicalBytes(), aad.CanonicalBytes()) {
		t.Fatal("authentic original task authority absent")
	}
	invoke(controllerA, 2, "prompt", sessionworker.Operation{Input: originalBody, InputKind: "task", SourceCommandID: task.CommandID, SourceAdmissionID: a.session.NativeAdmissionID, SourceTask: task.TaskSource}, task.NativeDispatch)
	var started sessionworker.NativeObservation
	deadline = time.Now().Add(5 * time.Second)
	for started.ID == "" {
		page, err := controllerA.Call(t.Context(), sessionworker.Request{Type: "observations", Limit: 32})
		if err != nil || page.Error != "" {
			t.Fatal(err)
		}
		for _, o := range page.Observations {
			if o.Event.Type == session.EventTurnStarted {
				started = o
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("genuine started source missing")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if started.TurnSource == nil || !reflect.DeepEqual(started.TurnSource.SourceTask, task.TaskSource) {
		t.Fatal("accepted original task binding missing")
	}
	if err = a.connection.DrainNativeWorkerSources(t.Context(), controllerA.Call); err != nil {
		t.Fatal("actual started turn receipt failed", err)
	}
	var stats nativeTurnBackendStats
	helper.call(t, map[string]any{"action": "stats", "originId": origin.ID, "observationId": started.ID, "logicalTurnId": started.Event.TurnID, "forbiddenPlaintext": originalBody}, &stats)
	if stats.ReceiptCount != 1 || stats.TurnStatus != "running" || stats.TaskID != task.TaskID || !stats.PrivacyClean {
		t.Fatal("actual source turn not committed private")
	}
	a.connection.Close()
	_ = a.socket.Close()
	b := connectNativeBackend(t, fixture, false)
	b.agentDaemon.Store(daemon)
	controllerB, err := sessionworker.DialOwnerController(t.Context(), dir, scope, privateKey, "task-input-B")
	if err != nil {
		t.Fatal(err)
	}
	defer controllerB.Close()
	admit(b, controllerB)
	after, err := snapshot(controllerB)(t.Context())
	if err != nil || after.PID != initial.PID || after.NativeStartIdentity != initial.NativeStartIdentity || after.NativeGeneration != initial.NativeGeneration || after.NativeSessionID != initial.NativeSessionID || !bytes.Equal(after.Origin, initial.Origin) {
		t.Fatal("native process/source changed on B", err)
	}
	if err = b.connection.ConfirmNativeWorkerSession(t.Context(), scope, origin, hex.EncodeToString(profile[:]), snapshot(controllerB)); err != nil {
		t.Fatal(err)
	}
	if fixture.PrincipalID == "" {
		t.Fatal("helper must expose authentic public principal")
	}
	proxy := &NativeWorkerProxy{connection: b.connection, controller: controllerB, scope: scope, done: make(chan struct{})}
	link := &nativeWorkerLink{proxy: proxy, conn: b.socket}
	row := &InstanceRow{InstanceID: fixture.InstanceID, AgentPrincipalID: fixture.PrincipalID, NetworkID: fixture.NetworkID, Kind: "worker", Runtime: fixture.Runtime}
	control := dialControlSocket(t, filepath.Join(spec.Workspace, "bc-"+strings.ReplaceAll(fixture.InstanceID, "-", "")+".sock"))
	auth := control.op(t, map[string]any{"op": "auth", "instanceId": fixture.InstanceID, "networkId": fixture.NetworkID})
	rawAuth, _ := json.Marshal(auth)
	if !bytes.Contains(rawAuth, []byte("auth_ok")) {
		t.Fatalf("actual native bridge authentication failed: %s", rawAuth)
	}
	// Mutating ciphertext with the SAME AAD must still fetch the original snapshot.
	replacement := "private mutable task replacement must never reach original turn"
	changedEnvelope, err := e2ee.Encrypt([]byte(replacement), key, aad)
	if err != nil {
		t.Fatal(err)
	}
	var changed map[string]any
	helper.call(t, map[string]any{"action": "mutate_task_body", "taskId": taskID, "taskAAD": aad, "taskEnvelope": changedEnvelope}, &changed)
	if changed["updated"] != true {
		t.Fatal("real mutable task edit not applied")
	}
	// Rotation preserves retained A authority; publishing current B keys cannot
	// rewrite either original source or its immutable task snapshot.
	if _, err = ring.Rotate(time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err = hostcrypto.SaveKeyring(daemon.StateDir, ring); err != nil {
		t.Fatal(err)
	}
	invokeBridge := func(id string) (*sessionworker.BridgeCall, map[string]any) {
		t.Helper()
		reply := make(chan map[string]any, 1)
		go func() {
			reply <- control.op(t, map[string]any{"op": "call", "tool": "network_task_get", "args": map[string]any{"taskId": taskID}})
		}()
		deadline := time.Now().Add(5 * time.Second)
		var call *sessionworker.BridgeCall
		for call == nil {
			response, err := controllerB.Call(t.Context(), sessionworker.Request{Type: "bridge_poll"})
			if err != nil || response.Error != "" {
				t.Fatal("real bridge poll", err)
			}
			call = response.Bridge
			if time.Now().After(deadline) {
				t.Fatal("actual native call missing")
			}
			time.Sleep(5 * time.Millisecond)
		}
		if call.Admission.RunnerID != b.session.RunnerID || call.TurnSource == nil || !reflect.DeepEqual(call.TurnSource, started.TurnSource) || call.NativeGeneration != initial.NativeGeneration || !bytes.Equal(call.Origin, initial.Origin) {
			t.Fatal("bridge rewrote original source to B")
		}
		source, err := nativeBridgeSource(call)
		if err != nil || source.SourceCommandID != task.CommandID || source.SourceAdmissionID != a.session.NativeAdmissionID {
			t.Fatal("actual source-aware bridge binding invalid", err)
		}
		var result sessionworker.BridgeResult
		result.ID = call.ID
		result.Result, result.Error = daemon.executeBridgeToolWithRead(row, call.Tool, call.Args, func(tool string, args json.RawMessage) (json.RawMessage, string) {
			return daemon.relayNativeBridge(t.Context(), link, row, call, tool, args)
		}, func(args, raw json.RawMessage) (json.RawMessage, string) {
			return daemon.nativeTaskReadForBridge(t.Context(), proxy, row, call, args, raw)
		})
		result.OK = result.Error == ""
		if id == "original" && !result.OK {
			t.Logf("original task bridge refusal: %s", result.Error)
		}
		done, err := controllerB.Call(t.Context(), sessionworker.Request{Type: "bridge_result", Relay: &result})
		if err != nil || done.Error != "" {
			t.Fatal("actual bridge result failed", err)
		}
		select {
		case response := <-reply:
			return call, response
		case <-time.After(5 * time.Second):
			t.Fatal("actual native reply missing")
		}
		return nil, nil
	}
	call, reply := invokeBridge("original")
	rawReply, _ := json.Marshal(reply)
	if !bytes.Contains(rawReply, []byte(originalBody)) || bytes.Contains(rawReply, []byte(replacement)) || !bytes.Contains(rawReply, []byte(`"ok":true`)) {
		t.Fatal("actual scoped task read did not return original snapshot")
	}
	snapshotResult, err := b.connection.ReadOriginalTaskInput(t.Context(), fixture.InstanceID, task.CommandID, a.session.NativeAdmissionID, task.TaskSource)
	if err != nil || snapshotResult.Envelope == nil || !reflect.DeepEqual(*snapshotResult.Envelope, originalEnvelope) {
		t.Fatal("fresh B immutable original encrypted snapshot changed", err)
	}
	// A later mutable task version can use B's genuinely different active
	// epoch. The accepted turn still decrypts only A's immutable snapshot.
	latest := ring.Epochs[len(ring.Epochs)-1]
	latestKey, err := latest.KeyArray()
	if err != nil {
		t.Fatal(err)
	}
	latestAAD := aad
	latestAAD.KeyEpochID = latest.ID
	latestAAD.CreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	latestEnvelope, err := e2ee.Encrypt([]byte(replacement), latestKey, latestAAD)
	clear(latestKey[:])
	if err != nil {
		t.Fatal(err)
	}
	helper.call(t, map[string]any{"action": "mutate_task_body", "taskId": taskID, "taskAAD": latestAAD, "taskEnvelope": latestEnvelope}, &changed)
	_, rotated := invokeBridge("later-epoch")
	rawRotated, _ := json.Marshal(rotated)
	if !bytes.Contains(rawRotated, []byte(originalBody)) || bytes.Contains(rawRotated, []byte(replacement)) || !bytes.Contains(rawRotated, []byte(`"ok":true`)) {
		t.Fatal("mutable later epoch replaced original input")
	}
	// Foreign source tuples and a caller-modified descriptor receive no input.
	for _, mode := range []string{"command", "admission", "aad"} {
		cmd, admission := task.CommandID, a.session.NativeAdmissionID
		descriptor := *task.TaskSource
		switch mode {
		case "command":
			cmd = domain.NewID().String()
		case "admission":
			admission = b.session.NativeAdmissionID
		case "aad":
			descriptor.InputAAD.Sender = "foreign"
		}
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		_, err = b.connection.ReadOriginalTaskInput(ctx, fixture.InstanceID, cmd, admission, &descriptor)
		cancel()
		if err == nil {
			t.Fatal("foreign original input accepted", mode)
		}
	}
	// Genuine worker source metadata is validated by the actual AgentRequest
	// handler before the ordinary task read; B cannot substitute its admission.
	for _, mode := range []string{"command", "admission", "turn"} {
		deniedCall := *call
		deniedTurn := *call.TurnSource
		deniedCall.TurnSource = &deniedTurn
		switch mode {
		case "command":
			deniedTurn.SourceCommandID = domain.NewID().String()
		case "admission":
			deniedTurn.SourceAdmissionID = b.session.NativeAdmissionID
		case "turn":
			deniedTurn.Sequence++
			deniedTurn.LogicalTurnID = "pagnet-worker-turn-999"
		}
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		deniedRaw, deniedError := daemon.relayNativeBridge(ctx, link, row, &deniedCall, call.Tool, call.Args)
		cancel()
		if deniedError == "" || bytes.Contains(deniedRaw, []byte(originalBody)) {
			t.Fatal("foreign native agent source accepted", mode)
		}
	}
	// Original input decryption fails closed after actual monotonic revocation,
	// even though current mutable ciphertext/new epoch remains otherwise valid.
	for i := range ring.Epochs {
		if ring.Epochs[i].ID == aad.KeyEpochID {
			ring.Epochs[i].State = hostcrypto.EpochRevoked
		}
	}
	if err = hostcrypto.SaveKeyring(daemon.StateDir, ring); err != nil {
		t.Fatal(err)
	}
	_, denied := invokeBridge("revoked")
	rawDenied, _ := json.Marshal(denied)
	if bytes.Contains(rawDenied, []byte(originalBody)) || bytes.Contains(rawDenied, []byte(replacement)) || bytes.Contains(rawDenied, []byte(`"ok":true`)) {
		t.Fatal("revoked original task body exposed through mutable fallback")
	}
	helper.call(t, map[string]any{"action": "revoke_source"}, &changed)
	ctx, cancelRead := context.WithTimeout(t.Context(), time.Second)
	_, err = b.connection.ReadOriginalTaskInput(ctx, fixture.InstanceID, task.CommandID, a.session.NativeAdmissionID, task.TaskSource)
	cancelRead()
	if err == nil {
		t.Fatal("revoked current source grant returned original snapshot")
	}
	if call.TurnSource.SourceAdmissionID != a.session.NativeAdmissionID || call.Admission.RunnerID == a.session.RunnerID {
		t.Fatal("A source and B transport were not distinct")
	}
}
