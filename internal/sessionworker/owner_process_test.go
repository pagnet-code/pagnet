//go:build linux || darwin

package sessionworker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/internal/crypto"
	"github.com/pagnet-code/pagnet/transport"
)

type controllerProcess struct {
	cmd     *exec.Cmd
	in      io.WriteCloser
	decoder *json.Decoder
	build   string
	lease   int64
	stderr  bytes.Buffer
	closed  bool
}

func startController(t *testing.T, binary, dir string) *controllerProcess {
	t.Helper()
	p := &controllerProcess{}
	p.cmd = exec.Command(binary, dir)
	p.cmd.Stderr = &p.stderr
	var err error
	p.in, err = p.cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := p.cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	p.decoder = json.NewDecoder(out)
	if err = p.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.close() })
	var hello struct {
		ControllerBuild string `json:"controllerBuild"`
		WorkerBuild     string `json:"workerBuild"`
		Lease           int64  `json:"lease"`
	}
	if err = p.decoder.Decode(&hello); err != nil {
		t.Fatalf("controller startup: %v %s", err, p.stderr.String())
	}
	p.build = hello.ControllerBuild
	p.lease = hello.Lease
	if hello.WorkerBuild != "worker-original" {
		t.Fatalf("worker build ownership changed: %+v", hello)
	}
	return p
}
func (p *controllerProcess) close() {
	if p.closed {
		return
	}
	p.closed = true
	_ = p.in.Close()
	_ = p.cmd.Process.Kill()
	_ = p.cmd.Wait()
}
func (p *controllerProcess) call(t *testing.T, request Request) Response {
	t.Helper()
	if err := json.NewEncoder(p.in).Encode(request); err != nil {
		t.Fatal(err)
	}
	var response Response
	done := make(chan error, 1)
	go func() { done <- p.decoder.Decode(&response) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("controller IPC: %v %s", err, p.stderr.String())
		}
	case <-time.After(8 * time.Second):
		p.close()
		t.Fatal("controller IPC hung")
	}
	return response
}
func (p *controllerProcess) intent(t *testing.T, seq int64, id, kind string, operation Operation) Response {
	t.Helper()
	raw, _ := json.Marshal(operation)
	return p.call(t, Request{Type: "intent", Sequence: seq, CommandID: id, Kind: kind, Payload: raw})
}
func (p *controllerProcess) outcome(t *testing.T, seq int64) Outcome {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		r := p.call(t, Request{Type: "outcome", Sequence: seq})
		if r.Error != "" {
			t.Fatal(r.Error)
		}
		if r.Outcome != nil && r.Outcome.State != "admitted" {
			return *r.Outcome
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("native outcome %d never settled", seq)
	return Outcome{}
}
func (p *controllerProcess) snapshot(t *testing.T) NativeSnapshot {
	t.Helper()
	r := p.call(t, Request{Type: "snapshot"})
	if r.Error != "" || r.Snapshot == nil {
		t.Fatalf("native snapshot unavailable: %+v", r)
	}
	return *r.Snapshot
}
func testBinary(t *testing.T, root, output, packagePath, stamp string) {
	t.Helper()
	args := []string{"build", "-o", output}
	if stamp != "" {
		args = append(args, "-ldflags", stamp)
	}
	args = append(args, packagePath)
	cmd := exec.Command("go", args...)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOWORK=off")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build actual subprocess: %v\n%s", err, out)
	}
}
func waitPath(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("native path never appeared: %s", path)
}

func TestActualNativeOwnerAcrossIndependentControllerProcesses(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp("", "pgn-own-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	state := filepath.Join(dir, "s")
	workspace := filepath.Join(dir, "w")
	contextState := filepath.Join(dir, "c")
	binaries := filepath.Join(dir, "b", "bin")
	for _, path := range []string{workspace, contextState, binaries} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	workerBinary := filepath.Join(binaries, "pagnet")
	nativeBinary := filepath.Join(binaries, "native")
	controllerA := filepath.Join(binaries, "controller-a")
	controllerB := filepath.Join(binaries, "controller-b")
	testBinary(t, root, workerBinary, "./cmd/pagnet", "-X main.version=worker-original")
	testBinary(t, root, nativeBinary, "./cmd/pagnet-fake-runtime", "")
	testBinary(t, root, controllerA, "./internal/sessionworker/testdata/controller", "-X main.build=controller-a")
	testBinary(t, root, controllerB, "./internal/sessionworker/testdata/controller", "-X main.build=controller-b")
	scope := Scope{AccountID: uuid.NewString(), HostID: uuid.NewString(), InstanceID: uuid.NewString(), Generation: uuid.NewString()}
	tenant := uuid.NewString()
	protected := e2ee.ProtectedContext{Kind: e2ee.OwnerContextKind, ID: uuid.NewString(), TenantID: tenant, OwnerUserID: uuid.NewString(), HostID: scope.HostID}
	epoch := crypto.KeyEpoch{ID: uuid.NewString(), State: crypto.EpochActive, Key: bytes.Repeat([]byte{7}, 32), CreatedAt: time.Now().UTC()}
	if err = crypto.SaveContextKeyring(contextState, &crypto.ContextKeyring{Context: protected, Epochs: []crypto.KeyEpoch{epoch}}); err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{9}, 32)
	bootstrap := Bootstrap{Protocol: Protocol, Scope: scope, Native: NativeSpec{Runtime: domain.RuntimeFakePersistent, Binary: nativeBinary, MCPExecutable: workerBinary, Workspace: workspace, NetworkID: uuid.NewString(), Kind: "worker", TenantID: tenant, ProtectedContext: &protected, ContextStateDir: contextState}}
	if err = PrepareBootstrap(state, bootstrap, key); err != nil {
		t.Fatal(err)
	}
	fixtureResult := filepath.Join(workspace, "bridge-result.json")
	env := []string{"PAGNET_FAKE_INTERACTION=permission", `PAGNET_FAKE_INTERACTION_OPTIONS=[{"id":"proceed","kind":"allow_once"},{"id":"cancel","kind":"reject_once"}]`, "PAGNET_FAKE_TUI_BOOT_BYTES=65536", "PAGNET_FAKE_TUI_TICK_MS=50", "PAGNET_FAKE_BRIDGE_CONTROL=1", "PAGNET_FAKE_SPAWN_BRIDGE=1", "PAGNET_FAKE_BRIDGE_RESULT_FILE=" + fixtureResult, "PAGNET_FAKE_FS_PROBE=" + filepath.Join(state, "control.key"), "PAGNET_FAKE_FS_PROBE_FILE=" + filepath.Join(workspace, "fs-probe.json")}
	readEnv, writeEnv, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(workerBinary, Subcommand, "--state", state, "--env-fd", "3")
	command.ExtraFiles = []*os.File{readEnv}
	var workerStderr bytes.Buffer
	command.Stderr = &workerStderr
	if err = command.Start(); err != nil {
		t.Fatal(err)
	}
	_ = readEnv.Close()
	t.Cleanup(func() { _ = command.Process.Kill(); _ = command.Wait() })
	if err = json.NewEncoder(writeEnv).Encode(env); err != nil {
		t.Fatal(err)
	}
	_ = writeEnv.Close()
	waitPath(t, filepath.Join(state, "controller.sock"))
	waitPath(t, filepath.Join(state, "native.sock"))
	a := startController(t, controllerA, state)
	admission := Admission{Scope: scope, TenantID: tenant, NetworkID: bootstrap.Native.NetworkID, Kind: "worker", RunnerID: uuid.NewString(), RunnerEpoch: time.Now().UTC(), BootID: uuid.NewString()}
	if r := a.call(t, Request{Type: "admission", Admission: &admission}); r.Error != "" {
		t.Fatal(r.Error)
	}
	origin := json.RawMessage(fmt.Sprintf(`{"id":%q,"commandId":"activate-one","tenantId":%q,"hostId":%q,"instanceId":%q,"runtime":"fake-persistent","runnerId":%q,"runnerEpoch":%q,"bootId":%q,"createdAt":%q}`, uuid.NewString(), tenant, scope.HostID, scope.InstanceID, admission.RunnerID, admission.RunnerEpoch.Format(time.RFC3339Nano), admission.BootID, time.Now().UTC().Format(time.RFC3339Nano)))
	if r := a.intent(t, 1, "activate-one", "activate", Operation{Origin: origin}); r.Error != "" {
		t.Fatal(r.Error)
	}
	if out := a.outcome(t, 1); out.State != "completed" {
		t.Fatalf("native activation failed: %+v stderr=%s", out, workerStderr.String())
	}
	initial := a.snapshot(t)
	if initial.PID <= 0 || initial.NativeGeneration == "" || initial.NativeSessionID == "" || !initial.HasTerminal {
		t.Fatalf("actual native ownership missing: %+v", initial)
	}
	// The real native MCP subprocess forwards through the worker-owned socket.
	deadline := time.Now().Add(10 * time.Second)
	var spawned *BridgeCall
	for time.Now().Before(deadline) {
		r := a.call(t, Request{Type: "bridge_poll"})
		if r.Error != "" {
			t.Fatal(r.Error)
		}
		if r.Bridge != nil {
			spawned = r.Bridge
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if spawned == nil || spawned.Scope != scope || spawned.NativeGeneration != initial.NativeGeneration || !bytes.Equal(spawned.Origin, origin) {
		t.Fatalf("native MCP did not inherit exact worker source: %+v", spawned)
	}
	if r := a.call(t, Request{Type: "bridge_result", Relay: &BridgeResult{ID: spawned.ID, OK: true, Result: json.RawMessage(`{"fixture":"actual-native-mcp"}`)}}); r.Error != "" {
		t.Fatal(r.Error)
	}
	if runtime.GOOS == "linux" {
		waitPath(t, filepath.Join(workspace, "fs-probe.json"))
		raw, _ := os.ReadFile(filepath.Join(workspace, "fs-probe.json"))
		var probes []struct {
			OK bool `json:"ok"`
		}
		if json.Unmarshal(raw, &probes) != nil || len(probes) != 1 || probes[0].OK {
			t.Fatal("native process read its worker's private control key")
		}
	}
	if r := a.intent(t, 2, "memory-one", "prompt", Operation{Input: "let keep preserved", InputKind: "task", Origin: json.RawMessage(`{"id":"another-delivery"}`)}); r.Error != "" {
		t.Fatal(r.Error)
	}
	if out := a.outcome(t, 2); out.State != "completed" {
		t.Fatal(out)
	}
	if r := a.intent(t, 3, "long-turn-one", "prompt", Operation{Input: "continue native work across controller replacement", InputKind: "task"}); r.Error != "" {
		t.Fatal(r.Error)
	}
	var waiting NativeSnapshot
	deadline = time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		waiting = a.snapshot(t)
		if len(waiting.Pending) == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(waiting.Pending) != 1 {
		t.Fatalf("native inspected permission was not observed: %+v", waiting)
	}
	originalInspection := waiting.Pending[0]
	cek, _ := epoch.KeyArray()
	plain, err := e2ee.Decrypt(originalInspection.DetailEnvelope, cek, originalInspection.DetailAAD)
	if err != nil {
		t.Fatal(err)
	}
	var detail transport.OwnerInteractionDetail
	if err = json.Unmarshal(plain, &detail); err != nil {
		t.Fatal(err)
	}
	clear(plain)
	secret, err := base64.StdEncoding.DecodeString(detail.Inspection.Secret)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(secret)
	input := Operation{NativeGeneration: initial.NativeGeneration, Data: []byte("let via-terminal exactly-once\n")}
	if r := a.intent(t, 4, "terminal-one", "input", input); r.Error != "" {
		t.Fatal(r.Error)
	}
	if out := a.outcome(t, 4); out.State != "completed" {
		t.Fatal(out)
	}
	b := startController(t, controllerB, state)
	if b.build == a.build || b.lease <= a.lease {
		t.Fatal("controller replacement was not independently built/fenced")
	}
	if r := a.intent(t, 5, "stale-controller", "input", input); r.Error != ErrFenced.Error() {
		t.Fatalf("old controller retained native authority: %+v", r)
	}
	if r := b.intent(t, 4, "terminal-one", "input", input); r.Error != "" || r.Outcome == nil || r.Outcome.State != "completed" {
		t.Fatalf("controller replay did not retain terminal outcome: %+v", r)
	}
	handoff := b.snapshot(t)
	if handoff.PID != initial.PID || handoff.NativeGeneration != initial.NativeGeneration || handoff.NativeSessionID != initial.NativeSessionID || !bytes.Equal(handoff.Origin, origin) || len(handoff.Pending) != 1 || handoff.Pending[0].InteractionID != originalInspection.InteractionID {
		t.Fatalf("whole native session ownership changed: before=%+v after=%+v", initial, handoff)
	}
	if r := b.call(t, Request{Type: "bridge_poll"}); r.Error != "fresh control-plane admission is required" {
		t.Fatalf("old network authority inherited: %+v", r)
	}
	a.close()
	b.close()
	// No controller exists during this interval. The actual native timer/PTY
	// and paused permission continue in the independently owned process.
	time.Sleep(250 * time.Millisecond)
	b = startController(t, controllerB, state)
	recovered := b.snapshot(t)
	if recovered.PID != initial.PID || recovered.NativeGeneration != initial.NativeGeneration || len(recovered.Pending) != 1 {
		t.Fatal("native state depended on a controller process")
	}
	admission.RunnerID = uuid.NewString()
	admission.RunnerEpoch = time.Now().UTC()
	admission.BootID = uuid.NewString()
	if r := b.call(t, Request{Type: "admission", Admission: &admission}); r.Error != "" {
		t.Fatal(r.Error)
	}
	// The original native raw bridge connection survives both controller exits.
	controlPath := filepath.Join(workspace, "bc-"+strings.ReplaceAll(scope.InstanceID, "-", "")+".sock")
	waitPath(t, controlPath)
	control, err := net.Dial("unix", controlPath)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	_ = control.SetDeadline(time.Now().Add(10 * time.Second))
	if err = json.NewEncoder(control).Encode(map[string]any{"id": "native-after-handoff", "op": "call", "tool": "network_whoami", "args": map[string]any{}}); err != nil {
		t.Fatal(err)
	}
	var forwarded *BridgeCall
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		r := b.call(t, Request{Type: "bridge_poll"})
		if r.Error != "" {
			t.Fatal(r.Error)
		}
		if r.Bridge != nil {
			forwarded = r.Bridge
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if forwarded == nil || forwarded.Admission.RunnerID != admission.RunnerID || forwarded.NativeGeneration != initial.NativeGeneration || !bytes.Equal(forwarded.Origin, origin) {
		t.Fatalf("native bridge did not use fresh fenced admission with original source: %+v", forwarded)
	}
	if r := b.call(t, Request{Type: "bridge_result", Relay: &BridgeResult{ID: forwarded.ID, OK: true, Result: json.RawMessage(`{"fixture":"fresh-admission"}`)}}); r.Error != "" {
		t.Fatal(r.Error)
	}
	var nativeResponse map[string]any
	if err = json.NewDecoder(bufio.NewReader(control)).Decode(&nativeResponse); err != nil {
		t.Fatal(err)
	}
	proof, err := e2ee.ApprovalProof(secret, originalInspection.DetailAAD, scope.InstanceID, initial.NativeSessionID, originalInspection.NativeInteractionID, "proceed")
	if err != nil {
		t.Fatal(err)
	}
	choice := Operation{NativeGeneration: initial.NativeGeneration, NativeSessionID: initial.NativeSessionID, InteractionID: originalInspection.NativeInteractionID, OptionID: "proceed", InspectionProof: base64.StdEncoding.EncodeToString(proof)}
	bad := choice
	bad.InspectionProof = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0}, 32))
	if r := b.intent(t, 5, "bad-proof", "resolve", bad); r.Error != "" {
		t.Fatal(r.Error)
	}
	if out := b.outcome(t, 5); out.State != "failed" {
		t.Fatal("uninspected native approval was applied")
	}
	if r := b.intent(t, 6, "approve-once", "resolve", choice); r.Error != "" {
		t.Fatal(r.Error)
	}
	if out := b.outcome(t, 6); out.State != "completed" {
		t.Fatalf("original inspected proof did not survive controller handoff: %+v", out)
	}
	if out := b.outcome(t, 3); out.State != "completed" {
		t.Fatal(out)
	}
	if r := b.intent(t, 6, "approve-once", "resolve", choice); r.Error != "" || r.Outcome == nil || r.Outcome.State != "completed" {
		t.Fatal("native approval replay lost durable outcome")
	}
	if r := b.intent(t, 7, "duplicate-choice-new-command", "resolve", choice); r.Error != "" {
		t.Fatal(r.Error)
	}
	if out := b.outcome(t, 7); out.State != "failed" {
		t.Fatal("same native choice was applied twice")
	}
	// Exactly one memory turn, one long turn and one human terminal input.
	sessionPath := filepath.Join(state, "native-state", "sessions", scope.InstanceID, "session.json")
	deadline = time.Now().Add(5 * time.Second)
	var nativeState struct {
		Turns int               `json:"turns"`
		Vars  map[string]string `json:"vars"`
	}
	for time.Now().Before(deadline) {
		raw, _ := os.ReadFile(sessionPath)
		_ = json.Unmarshal(raw, &nativeState)
		if nativeState.Turns >= 3 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if nativeState.Turns != 3 || nativeState.Vars["keep"] != "preserved" || nativeState.Vars["via-terminal"] != "exactly-once" {
		t.Fatalf("native effects duplicated or lost: %+v", nativeState)
	}
	var terminal strings.Builder
	cursor := int64(0)
	last := int64(0)
	for {
		r := b.call(t, Request{Type: "output", Cursor: cursor, Limit: 64})
		if r.Error != "" || r.Output == nil {
			t.Fatal(r.Error)
		}
		for _, record := range r.Output.Records {
			if record.Sequence <= last || record.NativeGeneration != initial.NativeGeneration {
				t.Fatal("output sequence/source changed during handoff")
			}
			last = record.Sequence
			if record.Kind == "terminal" {
				var data []byte
				_ = json.Unmarshal(record.Data, &data)
				terminal.Write(data)
			}
		}
		if len(r.Output.Records) == 0 {
			break
		}
		cursor = last
	}
	if !strings.Contains(terminal.String(), "native-tick ") || strings.Count(terminal.String(), "you> let via-terminal exactly-once") != 1 {
		t.Fatal("native timer stopped or terminal input repeated during controller replacement")
	}
	b.close()
	_ = command.Process.Signal(os.Interrupt)
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("worker orderly shutdown: %v %s", err, workerStderr.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("whole native owner failed to stop")
	}
	// The same journal opens cleanly after actual worker shutdown: no live lock,
	// no native command can be accidentally treated as a fresh retry.
	journal, err := OpenJournal(state, scope)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	nextLease, err := journal.AdvanceLease(context.Background())
	if err != nil || nextLease <= b.lease {
		t.Fatal("durable controller fence was lost")
	}
}
