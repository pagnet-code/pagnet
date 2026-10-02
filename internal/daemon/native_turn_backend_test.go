//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/e2ee"
	hostcrypto "github.com/pagnet-code/pagnet/internal/crypto"
	"github.com/pagnet-code/pagnet/internal/session"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/nativecontent"
	"github.com/pagnet-code/pagnet/transport"
)

type nativeTurnBackendStats struct {
	ReceiptCount      int     `json:"receiptCount"`
	Disposition       string  `json:"disposition"`
	Digest            string  `json:"digest"`
	TurnID            string  `json:"turnId"`
	TurnCount         int     `json:"turnCount"`
	TurnStatus        string  `json:"turnStatus"`
	TaskID            string  `json:"taskId"`
	SourceCommandID   string  `json:"sourceCommandId"`
	SourceAdmissionID string  `json:"sourceAdmissionId"`
	SourceRunnerID    string  `json:"sourceRunnerId"`
	NativeGeneration  string  `json:"nativeGeneration"`
	LifecycleSequence int64   `json:"lifecycleSequence"`
	PrivacyClean      bool    `json:"privacyClean"`
	OriginRetired     bool    `json:"originRetired"`
	ActiveOriginID    *string `json:"activeOriginId"`
	SessionState      string  `json:"sessionState"`
}

func TestNativeTurnDrainerActualOwnerBackendOriginalSourceAndRollback(t *testing.T) {
	if os.Getenv("PAGNET_NATIVE_SOURCE_BACKEND_TEST_BINARY") == "" {
		t.Skip("actual native turn proof requires isolated PostgreSQL server helper binary")
	}
	t.Setenv("PAGNET_NATIVE_SOURCE_HELPER_RUNTIME", string(domain.RuntimeFakePersistent))
	binary := filepath.Join(t.TempDir(), "native-fake")
	build := exec.Command("go", "build", "-o", binary, "./cmd/pagnet-fake-runtime")
	build.Dir = filepath.Clean("../..")
	build.Env = append(os.Environ(), "GOWORK=off")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("local native fake compile failed: %v %s", err, output)
	}
	for _, terminal := range []string{"completed", "failed"} {
		t.Run(terminal, func(t *testing.T) { proveNativeTurnOwnerBackend(t, binary, terminal) })
	}
}

func proveNativeTurnOwnerBackend(t *testing.T, binary, terminal string) {
	helper, fixture := startNativeBackendHelper(t)
	if fixture.Runtime != string(domain.RuntimeFakePersistent) {
		t.Fatal("paired turn helper lacks actual persistent native runtime fixture")
	}
	a := connectNativeBackend(t, fixture, false)
	var activation struct {
		CommandID string `json:"commandId"`
	}
	helper.call(t, map[string]any{"action": "seed_source", "runnerId": a.session.RunnerID, "runnerEpoch": a.session.RunnerEpoch, "bootId": a.session.BootID}, &activation)
	scope := sessionworker.Scope{ServerURL: a.connection.serverURL, TenantID: a.session.TenantID, AccountID: a.session.AccountID, HostID: fixture.HostID, InstanceID: fixture.InstanceID, Generation: domain.NewID().String()}
	dir, err := os.MkdirTemp("", "pgn-turn-proof-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	journal, err := sessionworker.OpenJournal(dir, scope)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	privateKey := bytes.Repeat([]byte{23}, 32)
	keydir := t.TempDir()
	taskKey := bytes.Repeat([]byte{29}, 32)
	ring := &hostcrypto.Keyring{NetworkID: fixture.NetworkID, Epochs: []hostcrypto.KeyEpoch{{ID: fixture.EpochID, State: hostcrypto.EpochActive, Key: taskKey, CreatedAt: time.Now().UTC()}}}
	if err = hostcrypto.SaveKeyring(keydir, ring); err != nil {
		t.Fatal(err)
	}
	spec := sessionworker.NativeSpec{Runtime: domain.RuntimeFakePersistent, Binary: binary, MCPExecutable: binary, Workspace: t.TempDir(), Kind: "worker", TenantID: scope.TenantID, NetworkID: fixture.NetworkID, NetworkTenantID: fixture.TenantID, NetworkStateDir: keydir}
	if terminal == "failed" {
		spec.Env = []string{"PAGNET_FAKE_RATELIMIT=1s"}
	} else {
		spec.Env = []string{"PAGNET_FAKE_FULL_OUTPUT_REPEAT=8"}
	}
	owner, err := sessionworker.NewSessionOwner(t.Context(), journal, spec, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	workerCtx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- sessionworker.ServeOwner(workerCtx, owner, privateKey, "actual-turn-worker") }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("actual owner private IPC did not stop")
		}
	})
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
	invoke := func(c *sessionworker.Controller, sequence int64, kind string, op sessionworker.Operation) {
		t.Helper()
		raw, _ := json.Marshal(op)
		r, err := c.Call(t.Context(), sessionworker.Request{Type: "intent", Sequence: sequence, CommandID: domain.NewID().String(), Kind: kind, Payload: raw})
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
	invoke(controllerA, 1, "activate", sessionworker.Operation{SourceCommandID: activation.CommandID, SourceAdmissionID: a.session.NativeAdmissionID, InputKind: "wake"})
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
	seed := func(peer *nativeBackendPeer) struct {
		CommandID  string                      `json:"commandId"`
		TaskID     string                      `json:"taskId"`
		TaskSource *transport.NativeTaskSource `json:"taskSource"`
	} {
		t.Helper()
		var seeded struct {
			CommandID  string                      `json:"commandId"`
			TaskID     string                      `json:"taskId"`
			TaskSource *transport.NativeTaskSource `json:"taskSource"`
		}
		taskID := domain.NewID().String()
		aad := e2ee.AAD{ProtocolVersion: transport.ProtocolVersion, TenantID: fixture.TenantID, NetworkID: fixture.NetworkID, ObjectType: e2ee.ObjectTypeTask, ObjectID: taskID, Sender: fixture.InstanceID, Recipient: fixture.InstanceID, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), KeyEpochID: fixture.EpochID}
		var key [32]byte
		copy(key[:], taskKey)
		envelope, err := e2ee.Encrypt([]byte("actual encrypted original task body"), key, aad)
		if err != nil {
			t.Fatal(err)
		}
		helper.call(t, map[string]any{"action": "seed_encrypted_task_source", "runnerId": peer.session.RunnerID, "runnerEpoch": peer.session.RunnerEpoch, "bootId": peer.session.BootID, "nativeAdmissionId": peer.session.NativeAdmissionID, "taskAAD": aad, "taskEnvelope": envelope}, &seeded)
		if seeded.TaskSource == nil || seeded.TaskSource.TaskID != taskID || !bytes.Equal(seeded.TaskSource.InputAAD.CanonicalBytes(), aad.CanonicalBytes()) {
			t.Fatal("backend did notretain actualoriginalencryptedtaskdescriptor")
		}

		if seeded.CommandID == "" || seeded.TaskID == "" {
			t.Fatal("backend original task command missing")
		}
		return seeded
	}
	originalTask := seed(a)
	secret := "actual-native-turn-private-" + terminal
	invoke(controllerA, 2, "prompt", sessionworker.Operation{Input: secret + strings.Repeat(" original full native task text €", 3000), InputKind: "task", SourceCommandID: originalTask.CommandID, SourceAdmissionID: a.session.NativeAdmissionID, SourceTask: originalTask.TaskSource})
	outcome(controllerA, 2)
	page, err := controllerA.Call(t.Context(), sessionworker.Request{Type: "observations", Limit: 32})
	if err != nil || page.Error != "" {
		t.Fatal(err)
	}
	var started, ended, output sessionworker.NativeObservation
	for _, o := range page.Observations {
		if o.Event.Type == session.EventTurnStarted {
			started = o
		}
		if o.Event.Type == session.EventTurnOutput && o.Event.NativeOutput {
			output = o
		}
		if o.Event.Type == session.EventTurnCompleted || o.Event.Type == session.EventTurnFailed {
			ended = o
		}
	}
	if started.ID == "" || ended.ID == "" || started.Capture == nil || ended.Capture == nil || started.TurnSource == nil || ended.TurnSource == nil || started.TurnSource.SourceCommandID != originalTask.CommandID || started.TurnSource.SourceAdmissionID != a.session.NativeAdmissionID || started.TurnSource.InputKind != "task" || !reflect.DeepEqual(started.TurnSource, ended.TurnSource) {
		t.Fatal("actual native events lost original accepted turn source")
	}
	if started.Event.Type != session.EventTurnStarted || (terminal == "completed" && ended.Event.Type != session.EventTurnCompleted) || (terminal == "failed" && ended.Event.Type != session.EventTurnFailed) {
		t.Fatal("actual terminal native event was synthesized")
	}
	capture := func(c *sessionworker.Controller, o sessionworker.NativeObservation) []byte {
		t.Helper()
		var raw []byte
		for len(raw) < o.Capture.CiphertextBytes {
			r, err := c.Call(t.Context(), sessionworker.Request{Type: "source_capture", ObservationID: o.ID, SourceDigest: o.SourceDigest, CaptureOffset: len(raw)})
			if err != nil || r.Error != "" || r.Capture == nil || r.Capture.Offset != len(raw) || len(r.Capture.Data) == 0 {
				t.Fatal("actual encrypted native source unavailable")
			}
			raw = append(raw, r.Capture.Data...)
		}
		return raw
	}
	originalCipher := capture(controllerA, ended)
	opened, err := sessionworker.OpenNativeSourceCapture(privateKey, scope, dir, ended, originalCipher)
	if err != nil || opened.Event.TurnID != ended.Event.TurnID {
		t.Fatal("actual original capture could not be authenticated")
	}
	if terminal == "failed" && (opened.Event.Error == "" || ended.Event.Error != "") {
		t.Fatal("native failure body was not retained exclusively encrypted")
	}
	// Drain the real busy record before inspecting the original started record.
	onePage := func(c *sessionworker.Controller) func(context.Context, sessionworker.Request) (sessionworker.Response, error) {
		return func(ctx context.Context, r sessionworker.Request) (sessionworker.Response, error) {
			if r.Type == "observations" {
				r.Limit = 1
			}
			return c.Call(ctx, r)
		}
	}
	if err = a.connection.DrainNativeWorkerSources(t.Context(), onePage(controllerA)); err != nil {
		t.Fatal(err)
	}
	var outputFragments []transport.NativeContentFragment
	if terminal == "completed" {
		if output.OutputContent == nil || output.OutputContent.FragmentCount <= transport.NativeContentMaxFragmentPage || output.SourceSequence != started.SourceSequence+1 {
			t.Fatal("actual producer did notcapture genuineorderedtext")
		}
		for ordinal := 0; ordinal < output.OutputContent.FragmentCount; ordinal++ {
			r, err := controllerA.Call(t.Context(), sessionworker.Request{Type: "content_fragment", ObservationID: output.ID, SourceDigest: output.SourceDigest, ContentID: output.OutputContent.ContentID, ContentOrdinal: ordinal})
			if err != nil || r.Error != "" || r.ContentFragment == nil {
				t.Fatal("actual original output ciphertext unavailable")
			}
			outputFragments = append(outputFragments, *r.ContentFragment)
		}
		var key [32]byte
		copy(key[:], taskKey)
		plain, _, err := nativecontent.Open(*output.OutputContent, outputFragments, key)
		input := strings.Repeat(secret+strings.Repeat(" original full native task text €", 3000), 8)
		if err != nil || string(plain) != "[fake-persist task] handled "+input+": "+input {
			t.Fatal("actual native output changed", err)
		}
		if _, err = ring.Rotate(time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
		if err = hostcrypto.SaveKeyring(keydir, ring); err != nil {
			t.Fatal(err)
		}
	}
	actualStarted, err := NativeWorkerWireObservation(started)
	if err != nil {
		t.Fatal(err)
	}
	// No caller-selected task or foreign command may substitute the actual
	// backend command's immutable task binding at this exact source sequence.
	for _, corruption := range []string{"wrong_task", "wrong_source"} {
		bad := actualStarted
		bad.ObservationID = domain.NewID().String()
		var p map[string]any
		_ = json.Unmarshal(bad.Payload, &p)
		if corruption == "wrong_task" {
			p["taskId"] = domain.NewID().String()
		} else {
			p["sourceCommandId"] = domain.NewID().String()
		}
		bad.Payload, _ = json.Marshal(p)
		digest := sha256.Sum256(bad.Payload)
		bad.Digest = hex.EncodeToString(digest[:])
		denyCtx, cancelDeny := context.WithTimeout(t.Context(), 500*time.Millisecond)
		reply, err := a.connection.deliverWorkerObservation(denyCtx, bad)
		cancelDeny()
		if (err != nil && !errors.Is(err, context.DeadlineExceeded)) || reply.Disposition == "committed" {
			t.Fatalf("actual backend task/source denial %s: disposition=%s err=%v", corruption, reply.Disposition, err)
		}
		var stats nativeTurnBackendStats
		helper.call(t, map[string]any{"action": "stats", "originId": origin.ID, "observationId": bad.ObservationID, "logicalTurnId": started.Event.TurnID}, &stats)
		if stats.ReceiptCount != 0 || stats.TurnCount != 0 || stats.LifecycleSequence != started.SourceSequence-1 {
			t.Fatal("bad source changed durable task turn/sequence")
		}
	}
	a.dropObservationID.Store(&started.ID)
	if err = a.connection.DrainNativeWorkerSources(t.Context(), controllerA.Call); !errors.Is(err, ErrNativeOriginAdmissionDeferred) {
		t.Fatal("lost actual started receipt did not preserve original evidence", err)
	}
	var stats nativeTurnBackendStats
	check := map[string]any{"action": "stats", "originId": origin.ID, "observationId": started.ID, "logicalTurnId": started.Event.TurnID, "forbiddenPlaintext": secret}
	helper.call(t, check, &stats)
	expectedTurn := uuid.NewSHA1(uuid.NameSpaceOID, []byte("pagnet-native-turn:"+origin.ID+":"+started.Event.TurnID)).String()
	if stats.ReceiptCount != 1 || stats.Disposition != "committed" || stats.TurnID != expectedTurn || stats.TurnStatus != "running" || stats.TaskID != originalTask.TaskID || stats.SourceCommandID != originalTask.CommandID || stats.SourceAdmissionID != a.session.NativeAdmissionID || stats.SourceRunnerID != a.session.RunnerID || !stats.PrivacyClean {
		t.Fatal("actual backend lost immutable original task turn after reply loss")
	}
	b := connectNativeBackend(t, fixture, false)
	controllerB, err := sessionworker.DialOwnerController(t.Context(), dir, scope, privateKey, "turn-controller-B")
	if err != nil {
		t.Fatal(err)
	}
	defer controllerB.Close()
	admit(b, controllerB)
	survived, err := snapshot(controllerB)(t.Context())
	if err != nil || survived.PID != initial.PID || survived.NativeStartIdentity != initial.NativeStartIdentity || survived.NativeGeneration != initial.NativeGeneration || survived.NativeSessionID != initial.NativeSessionID || !bytes.Equal(survived.Origin, initial.Origin) {
		t.Fatal("actual native process/source changed through B")
	}
	if !bytes.Equal(originalCipher, capture(controllerB, ended)) {
		t.Fatal("controller B rewrote private original capture ciphertext")
	}
	if err = b.connection.ConfirmNativeWorkerSession(t.Context(), scope, origin, hex.EncodeToString(profile[:]), snapshot(controllerB)); err != nil {
		t.Fatal("actual B native kernel/session proof failed", err)
	}
	// Replay the started receipt only, then force terminal transaction rollback.
	if err = b.connection.DrainNativeWorkerSources(t.Context(), onePage(controllerB)); err != nil {
		t.Fatal("B original started receipt recovery failed", err)
	}
	if terminal == "completed" {
		var operation map[string]any
		helper.call(t, map[string]any{"action": "fail_receipt", "observationId": output.ID}, &operation)
		// Stage the bounded pages before putting a receipt timeout on the
		// actual transactional publication; writing the large ciphertext is
		// independently measured and must not poison the websocket deadline.
		for ready := false; !ready; {
			budget := transport.NativeContentMaxFragmentPage
			ready, err = b.connection.stageWorkerContent(t.Context(), output, *output.OutputContent, controllerB.Call, &budget)
			if err != nil {
				t.Fatal(err)
			}
		}
		failureCtx, cancel := context.WithTimeout(t.Context(), 700*time.Millisecond)
		rollback := b.connection.DrainNativeWorkerSources(failureCtx, controllerB.Call)
		cancel()
		if !errors.Is(rollback, context.DeadlineExceeded) {
			t.Fatal("actual task output rollback inventedreceipt", rollback)
		}
		var rolledBack nativeBackendStats
		helper.call(t, map[string]any{"action": "stats", "originId": origin.ID, "observationId": output.ID, "contentId": output.OutputContent.ContentID, "forbiddenPlaintext": secret}, &rolledBack)
		if rolledBack.ReceiptCount != 0 || rolledBack.Attachments != 0 || !rolledBack.PrivacyClean {
			t.Fatal("actual failed task output transaction partiallyattached content")
		}
		retained, err := controllerB.Call(t.Context(), sessionworker.Request{Type: "content_fragment", ObservationID: output.ID, SourceDigest: output.SourceDigest, ContentID: output.OutputContent.ContentID, ContentOrdinal: 0})
		if err != nil || retained.Error != "" || retained.ContentFragment == nil || !reflect.DeepEqual(*retained.ContentFragment, outputFragments[0]) {
			t.Fatal("actual failed task output COMMIT deleted/re-encrypted original ciphertext")
		}
		helper.call(t, map[string]any{"action": "clear_failure"}, &operation)
		b.dropObservationID.Store(&output.ID)
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		var lost error
		for lost == nil {
			lost = b.connection.DrainNativeWorkerSources(ctx, controllerB.Call)
		}
		cancel()
		if !errors.Is(lost, ErrNativeOriginAdmissionDeferred) {
			t.Fatal("lost real tasktext receipt didnotretain cipher", lost)
		}
		var committed nativeBackendStats
		helper.call(t, map[string]any{"action": "stats", "originId": origin.ID, "observationId": output.ID, "contentId": output.OutputContent.ContentID, "forbiddenPlaintext": secret}, &committed)
		if committed.ReceiptCount != 1 || committed.Attachments != 1 || !committed.PrivacyClean || !reflect.DeepEqual(committed.Fragments, outputFragments) {
			t.Fatal("real dropped text receipt altered original committed ciphertext")
		}
		c := connectNativeBackend(t, fixture, false)
		controllerC, err := sessionworker.DialOwnerController(t.Context(), dir, scope, privateKey, "turn-controller-C")
		if err != nil {
			t.Fatal(err)
		}
		defer controllerC.Close()
		admit(c, controllerC)
		if err = c.connection.ConfirmNativeWorkerSession(t.Context(), scope, origin, hex.EncodeToString(profile[:]), snapshot(controllerC)); err != nil {
			t.Fatal(err)
		}
		for ordinal, fragment := range outputFragments {
			retained, err := controllerC.Call(t.Context(), sessionworker.Request{Type: "content_fragment", ObservationID: output.ID, SourceDigest: output.SourceDigest, ContentID: output.OutputContent.ContentID, ContentOrdinal: ordinal})
			if err != nil || retained.Error != "" || retained.ContentFragment == nil || !reflect.DeepEqual(*retained.ContentFragment, fragment) {
				t.Fatal("freshC rewrote/lost original output ciphertext")
			}
		}
		b = c
		controllerB = controllerC
		if err = b.connection.DrainNativeWorkerSources(t.Context(), onePage(controllerB)); err != nil {
			t.Fatal("freshC matching original text receipt replay failed", err)
		}
	}
	var operation map[string]any
	helper.call(t, map[string]any{"action": "fail_receipt", "observationId": ended.ID}, &operation)
	failureCtx, cancelFailure := context.WithTimeout(t.Context(), 500*time.Millisecond)
	failureErr := b.connection.DrainNativeWorkerSources(failureCtx, controllerB.Call)
	cancelFailure()
	if !errors.Is(failureErr, context.DeadlineExceeded) {
		t.Fatal("terminal receipt rollback emitted a false success", failureErr)
	}
	check["observationId"] = ended.ID
	stats = nativeTurnBackendStats{}
	helper.call(t, check, &stats)
	if stats.ReceiptCount != 0 || stats.TurnStatus != "running" || stats.TurnCount != 1 || stats.TaskID != originalTask.TaskID || !stats.PrivacyClean {
		t.Fatal("rolled back terminal source partially mutated original task turn")
	}
	if !bytes.Equal(originalCipher, capture(controllerB, ended)) {
		t.Fatal("failed backend commit removed or rewrote actual original source")
	}
	helper.call(t, map[string]any{"action": "clear_failure"}, &operation)
	if err = b.connection.DrainNativeWorkerSources(t.Context(), controllerB.Call); err != nil {
		t.Fatal("same actual original terminal source retry failed", err)
	}
	stats = nativeTurnBackendStats{}
	helper.call(t, check, &stats)
	if stats.ReceiptCount != 1 || stats.Disposition != "committed" || stats.TurnCount != 1 || stats.TurnStatus != terminal || stats.TurnID != expectedTurn || stats.TaskID != originalTask.TaskID || stats.SourceCommandID != originalTask.CommandID || stats.SourceAdmissionID != a.session.NativeAdmissionID || stats.SourceRunnerID != a.session.RunnerID || !stats.PrivacyClean {
		t.Fatal("actual terminal source through B changed original A task binding")
	}
	if terminal == "completed" {
		var contentStats nativeBackendStats
		helper.call(t, map[string]any{"action": "stats", "originId": origin.ID, "observationId": output.ID, "contentId": output.OutputContent.ContentID, "logicalTurnId": output.Event.TurnID, "forbiddenPlaintext": secret}, &contentStats)
		if contentStats.ReceiptCount != 1 || contentStats.Disposition != "committed" || contentStats.Attachments != 1 || !contentStats.PrivacyClean || !reflect.DeepEqual(contentStats.Reference, output.OutputContent) || !reflect.DeepEqual(contentStats.Fragments, outputFragments) {
			t.Fatal("actual backendtasktextcommit changedoriginalcipher")
		}
	}
	missing, err := controllerB.Call(t.Context(), sessionworker.Request{Type: "source_capture", ObservationID: ended.ID, SourceDigest: ended.SourceDigest})
	if err != nil || missing.Error == "" || missing.Capture != nil {
		t.Fatal("real matching terminal receipt did not atomically retire encrypted source")
	}
	page, err = controllerB.Call(t.Context(), sessionworker.Request{Type: "observations", Limit: 32})
	if err != nil || page.Error != "" || len(page.Observations) != 0 {
		t.Fatal("real actual native source backlog did not drain")
	}
	// Only this isolated test native process is stopped. No user/original host
	// process or API is touched. Real reader retirement precedes watermark GC.
	invoke(controllerB, 3, "stop", sessionworker.Operation{NativeGeneration: initial.NativeGeneration})
	outcome(controllerB, 3)
	local, err := sql.Open("sqlite", filepath.Join(dir, "intents.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	count := func(table string) int {
		t.Helper()
		var n int
		if err := local.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	deadline = time.Now().Add(3 * time.Second)
	for {
		var closed int
		err = local.QueryRow(`SELECT quiesced FROM worker_source_registration WHERE origin_id=?`, origin.ID).Scan(&closed)
		if err == nil && closed == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("actual native reader did not retire original registration", err)
		}
		time.Sleep(5 * time.Millisecond)
	}
	page, err = controllerB.Call(t.Context(), sessionworker.Request{Type: "observations", Limit: 32})
	if err != nil || page.Error != "" || len(page.Observations) != 1 || page.Observations[0].Event.Type != session.EventSessionStopped {
		t.Fatal("actual supervised EOF did not retain an original source", err)
	}
	stopped := page.Observations[0]
	if stopped.NativeSessionID != ended.NativeSessionID || stopped.NativeGeneration != ended.NativeGeneration || stopped.SourceSequence <= ended.SourceSequence {
		t.Fatal("actual EOF changed original generation/session/sequence")
	}
	if err = b.connection.DrainNativeWorkerSources(t.Context(), controllerB.Call); err != nil {
		t.Fatal("actual backend did not commit supervised EOF source", err)
	}
	stoppedWire, err := NativeWorkerWireObservation(stopped)
	if err != nil || stoppedWire.MessageType != transport.MsgAgentStopped {
		t.Fatal("original EOF wire adapter changed message type", err)
	}
	var stoppedStats nativeTurnBackendStats
	helper.call(t, map[string]any{"action": "stats", "originId": origin.ID, "observationId": stopped.ID, "logicalTurnId": ended.Event.TurnID, "forbiddenPlaintext": secret}, &stoppedStats)
	if stoppedStats.ReceiptCount != 1 || stoppedStats.Disposition != "committed" || stoppedStats.Digest != stoppedWire.Digest || stoppedStats.NativeGeneration != stopped.NativeGeneration || stoppedStats.LifecycleSequence != stopped.SourceSequence || stoppedStats.SourceRunnerID != a.session.RunnerID || !stoppedStats.PrivacyClean || !stoppedStats.OriginRetired || stoppedStats.ActiveOriginID != nil || stoppedStats.SessionState != "invalid" {
		t.Fatal("actual EOF receipt lost original source authority")
	}
	if count("worker_source_stream") != 1 || count("worker_turn_sources") != 1 {
		t.Fatal("reader exit ignored original unACKed source outcomes")
	}
	for _, sequence := range []int64{3, 1, 2} {
		reply, err := controllerB.Call(t.Context(), sessionworker.Request{Type: "ack", Sequence: sequence})
		if err != nil || reply.Error != "" {
			t.Fatal("original native outcome acknowledgement failed")
		}
	}
	if count("worker_source_stream") != 0 || count("worker_source_registration") != 0 || count("worker_turn_sources") != 0 {
		t.Fatal("actual settled retired generation retained lifetime watermark")
	}
	// Private controller transport cannot recreate retired native observation.
	reply, err := controllerB.Call(t.Context(), sessionworker.Request{Type: "append_observation", Payload: json.RawMessage(`{}`)})
	if err != nil || reply.Error == "" {
		t.Fatal("controller gained original source append capability")
	}
	for _, name := range []string{"intents.sqlite", "intents.sqlite-wal"} {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err == nil && (bytes.Contains(raw, []byte(secret)) || (terminal == "failed" && bytes.Contains(raw, []byte(opened.Event.Error)))) {
			t.Fatal("private native task/failure body leaked into worker SQLite")
		}
	}
}
