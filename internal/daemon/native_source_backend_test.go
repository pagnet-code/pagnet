//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/internal/session"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/nativecontent"
	"github.com/pagnet-code/pagnet/transport"
)

type nativeBackendFixture struct {
	PrincipalID       string `json:"principalId"`
	Ready             bool   `json:"ready"`
	URL               string `json:"endpoint"`
	Credential        string `json:"credential"`
	ForeignCredential string `json:"foreignCredential"`
	TenantID          string `json:"tenantId"`
	HostID            string `json:"hostId"`
	NetworkID         string `json:"networkId"`
	InstanceID        string `json:"instanceId"`
	Runtime           string `json:"runtime"`
	CommandID         string `json:"commandId"`
	EpochID           string `json:"keyEpochId"`
}
type nativeBackendHelper struct {
	in      *json.Encoder
	out     *json.Decoder
	command *exec.Cmd
}

func startNativeBackendHelper(t *testing.T) (*nativeBackendHelper, nativeBackendFixture) {
	t.Helper()
	binary := os.Getenv("PAGNET_NATIVE_SOURCE_BACKEND_TEST_BINARY")
	if binary == "" {
		t.Skip("paired native source proof requires isolated PostgreSQL server helper test binary")
	}
	if !filepath.IsAbs(binary) {
		t.Fatal("server helper executable must have an absolute path")
	}
	command := exec.CommandContext(t.Context(), binary, "-test.run=^TestNativeSourceDeliveryBackendHelper$", "-test.timeout=90s")
	command.Env = append(os.Environ(), "PAGNET_NATIVE_SOURCE_HELPER=1")
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	// Server/helper diagnostics must never print pipe-delivered test credentials.
	command.Stderr = io.Discard
	if err = command.Start(); err != nil {
		t.Fatal("isolated server helper start failed")
	}
	h := &nativeBackendHelper{in: json.NewEncoder(stdin), out: json.NewDecoder(stdout), command: command}
	t.Cleanup(func() {
		_ = h.in.Encode(map[string]string{"action": "shutdown"})
		_ = stdin.Close()
		done := make(chan error, 1)
		go func() { done <- command.Wait() }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = command.Process.Kill()
			<-done
		}
	})
	var fixture nativeBackendFixture
	if err = h.out.Decode(&fixture); err != nil || !fixture.Ready {
		t.Fatal("isolated server helper did not publish fixture")
	}
	endpoint, err := url.Parse(fixture.URL)
	if err != nil || (endpoint.Scheme != "http" && endpoint.Scheme != "https") || !net.ParseIP(endpoint.Hostname()).IsLoopback() {
		t.Fatal("server helper endpoint must be loopback")
	}
	endpoint.Scheme = "ws"
	endpoint.Path = "/api/v1/hosts/ws"
	fixture.URL = endpoint.String()
	return h, fixture
}
func (h *nativeBackendHelper) call(t *testing.T, p any, result any) {
	t.Helper()
	if err := h.in.Encode(p); err != nil {
		t.Fatal("server helper pipe write failed")
	}
	if err := h.out.Decode(result); err != nil {
		t.Fatal("server helper pipe response failed")
	}
}

type nativeBackendPeer struct {
	agentDaemon       atomic.Pointer[Daemon]
	socket            *websocket.Conn
	connection        *NativeObservationConnection
	session           transport.HostSessionPayload
	done              chan struct{}
	writes            sync.Mutex
	dropReceipt       bool
	dropObservationID atomic.Pointer[string]
}

func connectNativeBackend(t *testing.T, fixture nativeBackendFixture, dropReceipt bool) *nativeBackendPeer {
	t.Helper()
	u, _ := url.Parse(fixture.URL)
	q := u.Query()
	boot := domain.NewID().String()
	q.Set("boot_id", boot)
	q.Set("native_observations", transport.NativeObservationReceiptProtocol)
	q.Set("native_task_content", transport.NativeTaskContentProtocol)
	q.Set("native_agent_source", transport.NativeAgentSourceProtocol)
	q.Set("native_ownership", transport.NativeWorkerOwnershipProtocol)
	u.RawQuery = q.Encode()
	header := http.Header{"Authorization": []string{"Bearer " + fixture.Credential}}
	socket, _, err := websocket.DefaultDialer.DialContext(t.Context(), u.String(), header)
	if err != nil {
		t.Fatal("real backend authenticated websocket failed")
	}
	peer := &nativeBackendPeer{socket: socket, done: make(chan struct{}), dropReceipt: dropReceipt}
	httpBase := *u
	httpBase.Scheme = "http"
	httpBase.Path = ""
	httpBase.RawQuery = ""
	peer.connection = NewNativeObservationConnection(httpBase.String(), fixture.HostID, boot, func(ctx context.Context, typ string, p any) error {
		peer.writes.Lock()
		defer peer.writes.Unlock()
		env, err := transport.NewEnvelope(typ, p)
		if err != nil {
			return err
		}
		if deadline, ok := ctx.Deadline(); ok {
			_ = socket.SetWriteDeadline(deadline)
		}
		return socket.WriteJSON(env)
	})
	admitted := make(chan error, 1)
	go func() {
		defer close(peer.done)
		defer peer.connection.Close()
		for {
			var env transport.Envelope
			if err := socket.ReadJSON(&env); err != nil {
				return
			}
			switch env.Type {
			case transport.MsgHostSession:
				var p transport.HostSessionPayload
				if err := env.DecodePayload(&p); err != nil {
					admitted <- err
					return
				}
				peer.session = p
				admitted <- peer.connection.Admit(p)
			case transport.MsgAgentResponse:
				if d := peer.agentDaemon.Load(); d != nil {
					d.deliverAgentResponse(env)
				}
			case transport.MsgNativeOwnershipRegistered, transport.MsgNativeOwnershipRetired:
				var p transport.NativeOwnershipRegisteredPayload
				if env.DecodePayload(&p) == nil {
					peer.connection.OwnershipDisposition(p)
				}
			case transport.MsgNativeTaskInputRead:
				_, _ = peer.connection.HandleEnvelope(env)
			case transport.MsgNativeOriginRegistered:
				var p transport.NativeOriginRegisteredPayload
				if env.DecodePayload(&p) == nil {
					peer.connection.OriginRegistered(p)
				}
			case transport.MsgNativeOriginSessionConfirmed:
				var p transport.NativeOriginSessionConfirmedPayload
				if env.DecodePayload(&p) == nil {
					peer.connection.SessionConfirmed(p)
				}
			case transport.MsgNativeContentStaged, transport.MsgNativeContentRejected:
				var p transport.NativeContentStagedPayload
				if env.DecodePayload(&p) == nil {
					peer.connection.NativeContentDisposition(p)
				}
			case transport.MsgNativeObservationReceipt, transport.MsgNativeObservationRejected:
				var p transport.NativeObservationReceiptPayload
				if env.DecodePayload(&p) != nil {
					return
				}
				dropID := peer.dropObservationID.Load()
				if (peer.dropReceipt || (dropID != nil && *dropID == p.ObservationID)) && env.Type == transport.MsgNativeObservationReceipt && p.Disposition == "committed" {
					peer.connection.Close()
					_ = socket.Close()
					return
				}
				peer.connection.NativeWorkerObservationDisposition(env.Type, p)
			}
		}
	}()
	t.Cleanup(func() {
		peer.connection.Close()
		_ = socket.Close()
		select {
		case <-peer.done:
		case <-time.After(time.Second):
			t.Error("backend websocket reader did not stop")
		}
	})
	select {
	case err := <-admitted:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("backend host session admission missing")
	}
	return peer
}

func nativeBackendSourceDigest(o sessionworker.NativeObservation) string {
	o.SourceDigest = ""
	o.SourceSequence = 0
	raw, _ := json.Marshal(o)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

type nativeBackendStats struct {
	LifecycleSequence int64                             `json:"lifecycleSequence"`
	ReceiptCount      int                               `json:"receiptCount"`
	Disposition       string                            `json:"disposition"`
	Attachments       int                               `json:"attachments"`
	SourceRunnerID    string                            `json:"sourceRunnerId"`
	NativeGeneration  string                            `json:"nativeGeneration"`
	ProjectedCount    int                               `json:"projectedCount"`
	PrivacyClean      bool                              `json:"privacyClean"`
	Digest            string                            `json:"digest"`
	Reference         *transport.NativeContentReference `json:"reference"`
	Fragments         []transport.NativeContentFragment `json:"fragments"`
	InstanceStatus    string                            `json:"instanceStatus"`
}

func TestNativeSourceDrainerActualBackendReconnectAndCiphertextProof(t *testing.T) {
	helper, fixture := startNativeBackendHelper(t)
	a := connectNativeBackend(t, fixture, true)
	var seeded struct {
		OK        bool   `json:"ok"`
		CommandID string `json:"commandId"`
	}
	helper.call(t, map[string]any{"action": "seed_source", "runnerId": a.session.RunnerID, "runnerEpoch": a.session.RunnerEpoch, "bootId": a.session.BootID}, &seeded)
	if seeded.CommandID != "" {
		fixture.CommandID = seeded.CommandID
	}
	generation := "fixture-original-native-A"
	origin, err := a.connection.RegisterOrigin(t.Context(), fixture.CommandID, fixture.InstanceID, fixture.Runtime, generation)
	if err != nil {
		t.Fatal("real original source registration failed", err)
	}
	nativeSession := "fixture-native-session-A"
	if err = a.connection.ConfirmSession(t.Context(), *origin, nativeSession, func(context.Context) error { return nil }); err != nil {
		t.Fatal("fixture session admission failed", err)
	}
	// This is an admitted isolated source fixture. No claim is made that the
	// no-op verifier proves a real provider process's live kernel birth identity.
	scope := sessionworker.Scope{ServerURL: "http://127.0.0.1", TenantID: a.session.TenantID, AccountID: a.session.AccountID, HostID: fixture.HostID, InstanceID: fixture.InstanceID, Generation: domain.NewID().String()}
	dir, err := os.MkdirTemp("", "pgn-source-proof-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	journal, err := sessionworker.OpenJournal(dir, scope)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	privateKey := bytes.Repeat([]byte{19}, 32)
	owner, err := sessionworker.NewSessionOwner(t.Context(), journal, sessionworker.NativeSpec{Runtime: domain.RuntimeFakePersistent, Binary: executable, MCPExecutable: executable, Workspace: t.TempDir(), Kind: "worker", TenantID: scope.TenantID, NetworkID: fixture.NetworkID, NetworkTenantID: fixture.TenantID}, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	workerCtx, cancelWorker := context.WithCancel(t.Context())
	defer cancelWorker()
	workerDone := make(chan error, 1)
	go func() { workerDone <- sessionworker.ServeOwner(workerCtx, owner, privateKey, "paired-test") }()
	t.Cleanup(func() {
		cancelWorker()
		select {
		case <-workerDone:
		case <-time.After(5 * time.Second):
			t.Error("private worker IPC did not stop")
		}
	})
	var controllerA *sessionworker.Controller
	deadline := time.Now().Add(5 * time.Second)
	for {
		controllerA, err = sessionworker.DialOwnerController(t.Context(), dir, scope, privateKey, "controller-A")
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("private worker A authentication failed")
		}
		time.Sleep(5 * time.Millisecond)
	}
	defer controllerA.Close()
	originalTime := time.Now().UTC()
	interactionID := domain.NewID().String()
	observationID := domain.NewID().String()
	secretSentinel := "source-fixture-private-never-on-server"
	plaintext := bytes.Repeat([]byte(secretSentinel+"\n"), 40000)
	aad := e2ee.AAD{ProtocolVersion: transport.ProtocolVersion, TenantID: fixture.TenantID, NetworkID: fixture.NetworkID, ObjectType: e2ee.ObjectTypeRuntimeInteraction, ObjectID: interactionID, Sender: fixture.InstanceID, CreatedAt: originalTime.Format(time.RFC3339Nano), KeyEpochID: fixture.EpochID}
	key := [32]byte{17, 21}
	binding := e2ee.NativeContentBinding{ContentID: domain.NewID().String(), ObservationID: observationID, OriginID: origin.ID, InstanceID: fixture.InstanceID, NativeGeneration: generation, NativeSessionID: nativeSession, SubjectType: e2ee.ObjectTypeRuntimeInteraction, SubjectID: interactionID, Purpose: "interaction_detail"}
	transfer, err := nativecontent.Build(plaintext, key, aad, binding, "text/plain")
	if err != nil {
		t.Fatal(err)
	}
	if len(transfer.Fragments) <= 16 {
		t.Fatal("fixture did not cross bounded fragment budget")
	}
	originRaw, _ := json.Marshal(origin)
	observed := sessionworker.NativeObservation{ID: observationID, NativeGeneration: generation, NativeSessionID: nativeSession, Origin: originRaw, ObservedAt: originalTime, InteractionID: interactionID, Event: session.SessionEvent{Type: session.EventInteractionStarted, SessionID: nativeSession, Interaction: &session.InteractionEvent{Kind: "question", NativeInteractionID: "original-native-question"}}, Inspection: &sessionworker.Inspection{InteractionID: interactionID, NativeGeneration: generation, NativeSessionID: nativeSession, NativeInteractionID: "original-native-question", Kind: "question", DetailContent: &transfer.Reference}}
	observed.SourceDigest = nativeBackendSourceDigest(observed)
	if err = journal.JournalCapturedObservation(t.Context(), observed, nil, transfer); err != nil {
		t.Fatal(err)
	}
	originalWire, err := NativeWorkerWireObservation(observed)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.connection.DrainNativeWorkerSources(t.Context(), controllerA.Call); err != nil {
		t.Fatal("real first bounded fragment batch failed", err)
	}
	page, err := controllerA.Call(t.Context(), sessionworker.Request{Type: "observations", Limit: 32})
	if err != nil || len(page.Observations) != 1 {
		t.Fatal("staged content prematurely acknowledged")
	}
	if err = a.connection.DrainNativeWorkerSources(t.Context(), controllerA.Call); !errors.Is(err, ErrNativeOriginAdmissionDeferred) {
		t.Fatalf("lost actual committed receipt did not defer: %v", err)
	}
	page, err = controllerA.Call(t.Context(), sessionworker.Request{Type: "observations", Limit: 32})
	if err != nil || len(page.Observations) != 1 {
		t.Fatal("disconnect before receipt retired original evidence")
	}
	var stats nativeBackendStats
	check := map[string]any{"action": "stats", "originId": origin.ID, "observationId": observationID, "contentId": transfer.Reference.ContentID, "forbiddenPlaintext": secretSentinel}
	helper.call(t, check, &stats)
	if stats.ReceiptCount != 1 || stats.Disposition != "committed" || stats.Attachments != 1 || stats.SourceRunnerID != a.session.RunnerID || stats.NativeGeneration != generation || !stats.PrivacyClean {
		t.Fatal("actual backend did not preserve source/protected commit")
	}
	if stats.Digest != originalWire.Digest {
		t.Fatal("actual backend mutated immutable observation bytes")
	}
	expectedRef, _ := json.Marshal(transfer.Reference)
	actualRef, _ := json.Marshal(stats.Reference)
	if !bytes.Equal(expectedRef, actualRef) || len(stats.Fragments) != len(transfer.Fragments) {
		t.Fatal("backend ciphertext reference/fragments changed")
	}
	for i, f := range transfer.Fragments {
		expected, _ := json.Marshal(f)
		actual, _ := json.Marshal(stats.Fragments[i])
		if !bytes.Equal(expected, actual) {
			t.Fatal("backend changed original fragment")
		}
	}
	b := connectNativeBackend(t, fixture, false)
	if b.session.RunnerID == a.session.RunnerID || b.session.BootID == a.session.BootID {
		t.Fatal("B reused original transport authority")
	}
	controllerB, err := sessionworker.DialOwnerController(t.Context(), dir, scope, privateKey, "controller-B")
	if err != nil {
		t.Fatal(err)
	}
	defer controllerB.Close()
	if err = b.connection.DrainNativeWorkerSources(t.Context(), controllerB.Call); err != nil {
		t.Fatal("B did not recover exact durable receipt", err)
	}
	page, err = controllerB.Call(t.Context(), sessionworker.Request{Type: "observations", Limit: 32})
	if err != nil || len(page.Observations) != 0 {
		t.Fatal("matching actual DB receipt did not acknowledge source")
	}
	missing, err := controllerB.Call(t.Context(), sessionworker.Request{Type: "content_fragment", ObservationID: observed.ID, SourceDigest: observed.SourceDigest, ContentID: transfer.Reference.ContentID, ContentOrdinal: 0})
	if err != nil || missing.ContentFragment != nil || missing.Error == "" {
		t.Fatal("receipt ACK did not atomically remove original fragments")
	}
	helper.call(t, check, &stats)
	if stats.ReceiptCount != 1 || stats.SourceRunnerID != a.session.RunnerID {
		t.Fatal("B duplicated receipt or rewrote source A")
	}
	// Same original origin receives fresh B session admission before new lifecycle projection.
	if err = b.connection.ConfirmSession(t.Context(), *origin, nativeSession, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}

	// A database failure after attachment staging must roll back the source
	// transaction and emit no invented receipt or worker acknowledgement.
	faulted := observed
	faulted.ID = domain.NewID().String()
	faulted.InteractionID = domain.NewID().String()
	faulted.ObservedAt = time.Now().UTC()
	faulted.Event.Interaction = &session.InteractionEvent{Kind: "question", NativeInteractionID: "rollback-native-question"}
	faultAAD := aad
	faultAAD.ObjectID = faulted.InteractionID
	faultAAD.CreatedAt = faulted.ObservedAt.Format(time.RFC3339Nano)
	faultBinding := binding
	faultBinding.ContentID = domain.NewID().String()
	faultBinding.ObservationID = faulted.ID
	faultBinding.SubjectID = faulted.InteractionID
	faultTransfer, err := nativecontent.Build([]byte(secretSentinel), key, faultAAD, faultBinding, "text/plain")
	if err != nil {
		t.Fatal(err)
	}
	faulted.Inspection = &sessionworker.Inspection{InteractionID: faulted.InteractionID, NativeGeneration: generation, NativeSessionID: nativeSession, NativeInteractionID: "rollback-native-question", Kind: "question", DetailContent: &faultTransfer.Reference}
	faulted.SourceDigest = nativeBackendSourceDigest(faulted)
	if err = journal.JournalCapturedObservation(t.Context(), faulted, nil, faultTransfer); err != nil {
		t.Fatal(err)
	}
	var operation map[string]any
	helper.call(t, map[string]any{"action": "fail_receipt", "observationId": faulted.ID}, &operation)
	failedContext, cancelFailure := context.WithTimeout(t.Context(), 500*time.Millisecond)
	failureErr := b.connection.DrainNativeWorkerSources(failedContext, controllerB.Call)
	cancelFailure()
	if !errors.Is(failureErr, context.DeadlineExceeded) {
		t.Fatalf("database rollback emitted a disposition: %v", failureErr)
	}
	faultCheck := map[string]any{"action": "stats", "originId": origin.ID, "observationId": faulted.ID, "contentId": faultTransfer.Reference.ContentID, "forbiddenPlaintext": secretSentinel}
	helper.call(t, faultCheck, &stats)
	if stats.ReceiptCount != 0 || stats.Attachments != 0 || !stats.PrivacyClean {
		t.Fatal("failed backend source transaction partially committed")
	}
	retained, err := controllerB.Call(t.Context(), sessionworker.Request{Type: "content_fragment", ObservationID: faulted.ID, SourceDigest: faulted.SourceDigest, ContentID: faultTransfer.Reference.ContentID, ContentOrdinal: 0})
	if err != nil || retained.Error != "" || retained.ContentFragment == nil {
		t.Fatal("failed source COMMIT retired original ciphertext")
	}
	helper.call(t, map[string]any{"action": "clear_failure"}, &operation)
	if err = b.connection.DrainNativeWorkerSources(t.Context(), controllerB.Call); err != nil {
		t.Fatal("same ciphertext retry after rollback failed", err)
	}
	helper.call(t, faultCheck, &stats)
	if stats.ReceiptCount != 1 || stats.Disposition != "committed" || stats.Attachments != 1 {
		t.Fatal("rollback retry did not commit once")
	}
	lifecycle := sessionworker.NativeObservation{ID: domain.NewID().String(), NativeGeneration: generation, NativeSessionID: nativeSession, Origin: originRaw, ObservedAt: time.Now().UTC(), Event: session.SessionEvent{Type: session.EventBusy, SessionID: nativeSession}}
	lifecycle.SourceDigest = nativeBackendSourceDigest(lifecycle)
	if err = journal.JournalObservation(t.Context(), lifecycle); err != nil {
		t.Fatal(err)
	}
	if err = b.connection.DrainNativeWorkerSources(t.Context(), controllerB.Call); err != nil {
		t.Fatal("actual lifecycle commit failed", err)
	}
	check["observationId"] = lifecycle.ID
	helper.call(t, check, &stats)
	if stats.ReceiptCount != 1 || stats.Disposition != "committed" || stats.InstanceStatus != "working" || stats.SourceRunnerID != a.session.RunnerID {
		t.Fatal("lifecycle did not preserve original A while projecting through B")
	}
	// Retain unsupported private records beyond one entire bounded scan. They
	// must never receive ACK, acquire a lifecycle sequence, or starve real sources.
	for i := 0; i < 160; i++ {
		unsupported := sessionworker.NativeObservation{ID: domain.NewID().String(), NativeGeneration: generation, NativeSessionID: nativeSession, Origin: originRaw, ObservedAt: time.Now().UTC(), Event: session.SessionEvent{Type: session.EventPlanUpdated, SessionID: nativeSession}}
		unsupported.SourceDigest = nativeBackendSourceDigest(unsupported)
		if err = journal.JournalObservation(t.Context(), unsupported); err != nil {
			t.Fatal(err)
		}
	}
	idle := sessionworker.NativeObservation{ID: domain.NewID().String(), NativeGeneration: generation, NativeSessionID: nativeSession, Origin: originRaw, ObservedAt: time.Now().UTC(), Event: session.SessionEvent{Type: session.EventIdle, SessionID: nativeSession}}
	idle.SourceDigest = nativeBackendSourceDigest(idle)
	if err = journal.JournalObservation(t.Context(), idle); err != nil {
		t.Fatal(err)
	}
	after, err := b.connection.DrainNativeWorkerSourcesPage(t.Context(), controllerB.Call, 0)
	if err != nil || after <= 0 {
		t.Fatal("unsupported source scan did not retain bounded cursor", err)
	}
	check["observationId"] = idle.ID
	helper.call(t, check, &stats)
	if stats.ReceiptCount != 0 {
		t.Fatal("bounded scan exceeded128 rows")
	}
	after, err = b.connection.DrainNativeWorkerSourcesPage(t.Context(), controllerB.Call, after)
	if err != nil || after != 0 {
		t.Fatal("retained unsupported records starved actual lifecycle", err)
	}
	helper.call(t, check, &stats)
	if stats.ReceiptCount != 1 || stats.Disposition != "committed" || stats.InstanceStatus != "idle" || stats.LifecycleSequence != 2 || stats.SourceRunnerID != a.session.RunnerID {
		t.Fatal("paged lifecycle changed original source/sequence")
	}
	pending, err := journal.PendingObservations(t.Context(), 32)
	if err != nil || len(pending) != 32 {
		t.Fatal("paging discarded unsupported evidence", err)
	}
	for _, o := range pending {
		if o.Event.Type != session.EventPlanUpdated || o.SourceSequence != 0 || nativeBackendSourceDigest(o) != o.SourceDigest {
			t.Fatal("cursor mutated unsupported private source")
		}
	}
	foreignFixture := fixture
	foreignFixture.Credential = fixture.ForeignCredential
	// Foreign host cannot negotiate this original host through our wrapper;
	// direct real websocket sends the exact original content status and waits for denial.
	u, _ := url.Parse(fixture.URL)
	q := u.Query()
	q.Set("boot_id", domain.NewID().String())
	q.Set("native_observations", transport.NativeObservationReceiptProtocol)
	u.RawQuery = q.Encode()
	foreign, _, err := websocket.DefaultDialer.DialContext(t.Context(), u.String(), http.Header{"Authorization": []string{"Bearer " + foreignFixture.Credential}})
	if err != nil {
		t.Fatal("foreign fixture websocket failed")
	}
	defer foreign.Close()
	_ = foreign.SetReadDeadline(time.Now().Add(5 * time.Second))
	frame, _ := transport.NewEnvelope(transport.MsgNativeContentStatus, transport.NativeContentStatusPayload{ContentID: transfer.Reference.ContentID, CiphertextDigest: transfer.Reference.CiphertextDigest})
	if err = foreign.WriteJSON(frame); err != nil {
		t.Fatal(err)
	}
	for {
		var reply transport.Envelope
		if err = foreign.ReadJSON(&reply); err != nil {
			t.Fatal("foreign scope denial missing")
		}
		if reply.Type == transport.MsgNativeContentRejected {
			var rejected transport.NativeContentStagedPayload
			if reply.DecodePayload(&rejected) != nil || rejected.PublicError == "" || len(rejected.MissingOrdinals) != 0 {
				t.Fatal("foreign scope returned private staging progress")
			}
			break
		}
		if reply.Type == transport.MsgNativeContentStaged {
			t.Fatal("foreign host received original staging status")
		}
	}
	for _, name := range []string{"intents.sqlite", "intents.sqlite-wal"} {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err == nil && bytes.Contains(raw, []byte(secretSentinel)) {
			t.Fatal("private plaintext leaked into worker SQLite")
		}
	}
}
