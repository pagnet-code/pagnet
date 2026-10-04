//go:build linux || darwin

package sessionworker

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/fabric"
	fabricidentity "github.com/pagnet-code/pagnet/fabric/identity"
	"github.com/pagnet-code/pagnet/internal/nativeauthority"
	"github.com/pagnet-code/pagnet/internal/sandbox"
)

func TestActualOfflineLocalOwnerOriginAndStreamAcrossControllerTakeover(t *testing.T) {
	testActualLocalOwner(t, false)
}
func TestActualOfflineLocalOwnerCancellationUsesOriginalSource(t *testing.T) {
	testActualLocalOwner(t, true)
}
func testActualLocalOwner(t *testing.T, cancellation bool) {
	root, e := filepath.Abs("../..")
	if e != nil {
		t.Fatal(e)
	}
	dir, e := os.MkdirTemp("", "pgn-local-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(dir)
	binaryDir := filepath.Join(dir, "bin")
	if e = os.Mkdir(binaryDir, 0700); e != nil {
		t.Fatal(e)
	}
	binary := filepath.Join(binaryDir, "pagnet")
	native := filepath.Join(binaryDir, "native")
	testBinary(t, root, binary, "./cmd/pagnet", "-X main.version=local-native-fixture")
	testBinary(t, root, native, "./cmd/pagnet-fake-runtime", "")
	f := newLocalAuthorityFixture(t)
	state := filepath.Join(dir, "worker")
	workspace := filepath.Join(dir, "workspace")
	if e = os.Mkdir(workspace, 0700); e != nil {
		t.Fatal(e)
	}
	spec := NativeSpec{Kind: "local", Runtime: domain.RuntimeFakePersistent, Binary: native, MCPExecutable: binary, Workspace: workspace, LocalAuthorityDirectory: f.directory, LocalFabricSocket: filepath.Join(dir, "fabric.sock"), Env: []string{"PATH=/usr/bin:/bin", "HOME=" + workspace}}
	if cancellation {
		spec.Env = append(spec.Env, "PAGNET_FAKE_FULL_OUTPUT=1", "PAGNET_FAKE_OUTPUT_CHUNK_BYTES=8")
	}
	probePath := filepath.Join(workspace, "native-fs-probe.json")
	spec.Env = append(spec.Env, "PAGNET_FAKE_FS_PROBE="+filepath.Join(f.directory, "genesis.key")+","+filepath.Join(state, "control.key"), "PAGNET_FAKE_FS_PROBE_FILE="+probePath)
	worker := f.binding.Worker
	worker.ProfileDigest = parseTestProfile(t, LocalNativeProfileFingerprint(spec))
	worker.OwnershipGeneration = "actual-local-binary-generation"
	binding, e := f.authority.BindWorker(context.Background(), f.owner, f.controller, f.binding.Proof.Revision, worker)
	if e != nil {
		t.Fatal(e)
	}
	scope, e := nativeauthority.NewLocalScope(f.authority.Identity(), binding)
	if e != nil {
		t.Fatal(e)
	}
	key := bytes.Repeat([]byte{41}, 32)
	if e = PrepareLocalBootstrap(state, LocalBootstrap{Protocol: LocalProtocol, Authority: scope, Native: spec}, key); e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(binary, Subcommand, "--state", state)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + workspace}
	var stderr localFixtureBuffer
	cmd.Stderr = &stderr
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { _ = cmd.Process.Signal(os.Interrupt); _ = cmd.Wait() }()
	path, e := SocketPath(state)
	if e != nil {
		t.Fatal(e)
	}
	waitPath(t, path)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, e := DialLocal(ctx, state, scope, key, "actual-A")
	if e != nil {
		t.Fatal(e, stderr.String())
	}
	defer func() { client.Close() }()
	kernel, e := client.OwnerProcess()
	if e != nil || kernel.PID != cmd.Process.Pid {
		t.Fatal("worker kernel owner", e)
	}
	initial, e := client.Call(ctx, LocalRequest{Type: "snapshot"})
	if e != nil || initial.Snapshot == nil || initial.Snapshot.PID != 0 {
		t.Fatal("native effect before admission", e)
	}
	deadline := time.Now().UTC().Add(time.Minute)
	envelope := fabric.Envelope{ProtocolVersion: fabric.CurrentProtocolVersion, ID: "actual-offline-original", Operation: fabric.OperationInvoke, Principal: f.owner.PrincipalView(), Source: f.owner.PrincipalView().Ref, Target: &binding.Scope.Endpoint, ExpectedRevision: binding.Scope.DescriptorRevision, CreatedAt: time.Now().UTC(), Payload: json.RawMessage(`{"input":"let proof genuine-local-once"}`), Context: fabric.EnvelopeContext{Origin: f.owner.PrincipalView().Ref, Deadline: &deadline}}
	if cancellation {
		payload, _ := json.Marshal(map[string]string{"input": strings.Repeat("genuine paid output ", 2048)})
		envelope.Payload = payload
	}
	raw, _ := json.Marshal(envelope)
	caller, e := fabric.NewAuthenticatedContext(f.owner.PrincipalView(), f.authority.Identity().Namespace, raw)
	if e != nil {
		t.Fatal(e)
	}
	source, e := f.authority.Admit(ctx, f.owner, f.controller, binding, caller, raw, raw, "actual-source-A", "attempt", "replay")
	if e != nil {
		t.Fatal(e)
	}
	controller, e := nativeauthority.NewLocalController(f.authority, f.owner, binding, nativeauthority.JSONPromptBinder{ProfileDigest: worker.ProfileDigest})
	if e != nil {
		t.Fatal(e)
	}
	var intent nativeauthority.VerifiedIntent
	ack, e := controller.AdmitIntent(ctx, f.controller, source, caller, raw, raw, func(c context.Context, i nativeauthority.VerifiedIntent) (fabricidentity.NativeIntentReceipt, error) {
		intent = i
		r, e := client.Call(c, LocalRequest{Type: "intent", Intent: pointerLocalRequest(i.Request())})
		if r.Receipt != nil {
			return *r.Receipt, e
		}
		return fabricidentity.NativeIntentReceipt{}, e
	})
	if e != nil {
		t.Fatal("actual FULL worker admission", e, stderr.String())
	}
	var activation *LocalActivationRequest
	for activation == nil {
		r, e := client.Call(ctx, LocalRequest{Type: "activation_poll"})
		if e != nil {
			t.Fatal(e, stderr.String())
		}
		activation = r.Activation
		if activation == nil {
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(10 * time.Millisecond):
			}
		}
	}
	before, e := client.Call(ctx, LocalRequest{Type: "snapshot"})
	if e != nil || before.Snapshot.PID != 0 {
		t.Fatal("paid activation preceded origin", e)
	}
	origin, e := f.authority.RegisterOrigin(ctx, f.owner, f.controller, binding, source, caller, raw, raw, "actual-source-origin", activation.NativeGeneration)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = client.Call(ctx, LocalRequest{Type: "activation_origin", ActivationOrigin: &LocalActivationOrigin{ID: activation.ID, NativeGeneration: activation.NativeGeneration, Origin: &origin}}); e != nil {
		t.Fatal(e)
	}
	B, e := f.authority.AcquireController(ctx, f.owner, binding.Scope, f.controller.Epoch(), "actual-controller-B", "actual-B")
	if e != nil {
		t.Fatal(e)
	}
	fresh, e := DialLocal(ctx, state, scope, key, "actual-B")
	if e != nil {
		t.Fatal(e)
	}
	client.Close()
	client = fresh
	control := nativeauthority.LocalControl{CurrentBinding: binding, CurrentController: B}
	if e = f.authority.FenceNativeControl(ctx, f.owner, B, binding, func(c context.Context) error {
		_, e := client.Call(c, LocalRequest{Type: "control", Control: &control})
		return e
	}); e != nil {
		t.Fatal(e)
	}
	cursor := int64(-1)
	seenStart, seenComplete := false, false
	cancelled := false
	var delivered bytes.Buffer
	frameCount := 0
	for !seenComplete {
		var r LocalResponse
		e = f.authority.FenceNativeControl(ctx, f.owner, B, binding, func(c context.Context) error {
			var e error
			r, e = client.Call(c, LocalRequest{Type: "stream_page", Control: &control, Sequence: ack.Sequence, Cursor: cursor, Limit: 4})
			return e
		})
		if e != nil {
			if r.Code == "not_ready" {
				select {
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				case <-time.After(10 * time.Millisecond):
				}
				continue
			}
			status, _ := client.Call(ctx, LocalRequest{Type: "outcome", Sequence: ack.Sequence})
			sourcePage, _ := client.Call(ctx, LocalRequest{Type: "observations", Control: &control, Limit: 16})
			originBytes, _ := json.Marshal(origin)
			for _, o := range sourcePage.Observations {
				t.Logf("event=%s interaction=%t source=%t", o.Event.Type, o.Event.Interaction != nil, o.TurnSource != nil)
			}
			t.Fatalf("actual source page: %v; outcome=%+v originBytes=%d stderr=%s", e, status.Outcome, len(originBytes), stderr.String())
		}
		if r.Stream == nil {
			t.Fatal("missing stream")
		}
		if len(r.Stream.Frames) == 0 {
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err(), stderr.String())
			case <-time.After(10 * time.Millisecond):
			}
			continue
		}
		for _, sealed := range r.Stream.Frames {
			frame, e := OpenLocalInvocationFrame(key, scope, state, r.Stream.Source, sealed)
			if e != nil {
				t.Fatal(e)
			}
			if r.Stream.Source.Original.Admission.ID != source.ID || r.Stream.Source.ActivationOrigin.NativeGeneration != activation.NativeGeneration {
				t.Fatal("original A source rewritten")
			}
			frameCount++
			if frame.Kind == fabric.FrameChunk {
				if delivered.Len()+len(frame.Data) > 256<<10 {
					t.Fatal("unbounded stream output")
				}
				delivered.Write(frame.Data)
			}
			seenStart = seenStart || frame.Kind == fabric.FrameStart
			if cancellation && seenStart && !cancelled {
				stop, err := controller.CancellationIntent(B, binding, source, intent.Reservation, raw)
				if err != nil {
					t.Fatal(err)
				}
				err = f.authority.FenceNativeCancellation(ctx, f.owner, f.owner, B, binding, binding, source, intent.Reservation, func(c context.Context) error {
					_, e := client.Call(c, LocalRequest{Type: "cancel", Intent: pointerLocalRequest(stop.Request())})
					return e
				})
				if err != nil {
					t.Fatal(err)
				}
				cancelled = true
			}

			if frame.Kind == fabric.FrameError {
				if !cancellation || !cancelled || frame.Error == nil || frame.Error.Effect != fabric.EffectUnknown {
					t.Fatal("native error", frame.Error, stderr.String())
				}
				seenComplete = true
			}
			seenComplete = seenComplete || frame.Kind == fabric.FrameComplete
			cursor = sealed.Cursor
		}
		last := r.Stream.Frames[len(r.Stream.Frames)-1]
		e = f.authority.FenceNativeControl(ctx, f.owner, B, binding, func(c context.Context) error {
			_, e := client.Call(c, LocalRequest{Type: "stream_ack", Control: &control, Sequence: ack.Sequence, Cursor: last.Cursor, Digest: last.Digest})
			return e
		})
		if e != nil {
			t.Fatalf("stream ACK: %v cursor=%d frames=%d bytes=%d cancelled=%t complete=%t", e, cursor, frameCount, delivered.Len(), cancelled, seenComplete)
		}
	}
	if !cancellation && delivered.String() != "[fake-persist local-native] let proof = genuine-local-once" {
		t.Fatal("original native output bytes changed")
	}
	if cancellation {
		expected := "[fake-persist local-native] handled " + strings.Repeat("genuine paid output ", 2048) + ": " + strings.Repeat("genuine paid output ", 2048)
		if !strings.HasPrefix(expected, delivered.String()) {
			t.Fatal("partial output is not exact original prefix")
		}
		t.Logf("genuine cancelled source frames=%d bytes=%d", frameCount, delivered.Len())
	}
	if !seenStart {
		t.Fatal("completion without genuine start")
	}
	intent.CurrentController = B
	replay, e := controller.AdmitIntent(ctx, B, source, caller, raw, raw, func(c context.Context, i nativeauthority.VerifiedIntent) (fabricidentity.NativeIntentReceipt, error) {
		r, e := client.Call(c, LocalRequest{Type: "intent", Intent: pointerLocalRequest(i.Request())})
		if r.Receipt != nil {
			return *r.Receipt, e
		}
		return fabricidentity.NativeIntentReceipt{}, e
	})
	if e != nil || replay != ack {
		t.Fatal("same accepted ACK changed or replayed", e)
	}
	if sandbox.MustSandbox() {
		probeBytes, err := os.ReadFile(probePath)
		if err != nil {
			t.Fatal(err)
		}
		var probes []struct {
			Path  string `json:"fs_probe"`
			OK    bool   `json:"ok"`
			Error string `json:"err"`
		}
		if json.Unmarshal(probeBytes, &probes) != nil || len(probes) != 2 {
			t.Fatal("missing actual native filesystem probe")
		}
		for _, probe := range probes {
			if probe.OK || (probe.Error != syscall.EACCES.Error() && probe.Error != syscall.EPERM.Error()) {
				t.Fatal("native runtime did not deny private root/worker key read")
			}
		}
	}
	if cancellation {
		// Repeating the stop-only receipt never starts another native operation.
		stop, err := controller.CancellationIntent(B, binding, source, intent.Reservation, raw)
		if err != nil {
			t.Fatal(err)
		}
		err = f.authority.FenceNativeCancellation(ctx, f.owner, f.owner, B, binding, binding, source, intent.Reservation, func(c context.Context) error {
			_, e := client.Call(c, LocalRequest{Type: "cancel", Intent: pointerLocalRequest(stop.Request())})
			return e
		})
		if err != nil {
			t.Fatal(err)
		}
		for {
			snap, err := client.Call(ctx, LocalRequest{Type: "snapshot"})
			if err != nil {
				t.Fatal(err)
			}
			if snap.Snapshot != nil && snap.Snapshot.PID == 0 {
				break
			}
			select {
			case <-ctx.Done():
				t.Fatal("cancel did not join real native process", ctx.Err())
			case <-time.After(10 * time.Millisecond):
			}
		}
	}
	sessionBytes, err := os.ReadFile(filepath.Join(state, "native-state", "sessions", scope.WorkerID(), "session.json"))
	if os.IsNotExist(err) && cancellation {
		return
	} // A stopped first turn may never materialize its native session.
	if err != nil {
		t.Fatal(err)
	}
	var nativeState struct {
		Turns int `json:"turns"`
	}
	if json.Unmarshal(sessionBytes, &nativeState) != nil || nativeState.Turns > 1 || (!cancellation && nativeState.Turns != 1) {
		t.Fatal("native effect replayed or completion invented")
	}
}
func pointerLocalRequest(i nativeauthority.IntentRequest) *nativeauthority.IntentRequest { return &i }

func parseTestProfile(t *testing.T, s string) (digest [32]byte) {
	t.Helper()
	b, e := hex.DecodeString(s)
	if e != nil || len(b) != 32 {
		t.Fatal("profile", e)
	}
	copy(digest[:], b)
	return
}

type localFixtureBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *localFixtureBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}
func (b *localFixtureBuffer) String() string { b.mu.Lock(); defer b.mu.Unlock(); return b.b.String() }
