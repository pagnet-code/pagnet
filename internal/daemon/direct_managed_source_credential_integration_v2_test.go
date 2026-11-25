//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	agentruntime "github.com/pagnet-code/pagnet/internal/runtime"
	sessioncore "github.com/pagnet-code/pagnet/internal/session"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

func TestDirectSourceCredentialV2ProductionOwnershipIPC(t *testing.T) {
	const childEnv = "PAGNET_TEST_SOURCE_V2_CREDENTIAL_WORKER"
	if dir := os.Getenv(childEnv); dir != "" {
		os.Exit(sessionworker.RunMain([]string{"--state", dir}, "credential-original-worker"))
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	// Like the runtime package's Qwen lifecycle fixture, the CLI stub only
	// emits session_start and stays alive. The owner, driver, supervisor,
	// ownership verifier, authenticated IPC and credential executor are real.
	root, err := os.MkdirTemp("", "pgn-credential-v2-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	if err := os.MkdirAll(filepath.Join(root, "b", "bin"), 0700); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(root, "b", "bin", "qwen")
	const cli = `#!/usr/bin/env bash
while [ "$#" -gt 0 ]; do
  case "$1" in --json-file) json_file="$2"; shift ;; esac
  shift
done
printf '{"type":"system","subtype":"session_start","session_id":"11111111-aaaa-bbbb-cccc-111111111111","data":{"session_id":"11111111-aaaa-bbbb-cccc-111111111111","cwd":"%s","protocol_version":2,"version":"0.23.4","supported_events":["system","user","assistant","stream_event","control_request","control_response"]}}\n' "$PWD" > "$json_file"
sleep 3600
`
	if err := os.WriteFile(script, []byte(cli), 0700); err != nil {
		t.Fatal(err)
	}
	_, _, command, session := directSourceStoreFixtureV2(t)
	session.ProtocolFeatures = []string{transport.NativeObservationReceiptProtocol, transport.NativeWorkerOwnershipProtocol, transport.DirectManagedSourcePrepareProtocolV2, transport.DirectManagedSourcePoPProtocolV2, transport.DirectManagedSourceCredentialProtocolV2}
	if err := os.Mkdir(filepath.Join(root, "daemon"), 0700); err != nil {
		t.Fatal(err)
	}
	registry, err := OpenNativeWorkerRegistry(filepath.Join(root, "daemon"))
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	scope := sessionworker.Scope{ServerURL: "https://example.test", TenantID: session.TenantID, AccountID: session.AccountID, HostID: session.HostID, InstanceID: command.Subject.InstanceID.String(), Generation: command.Subject.OwnershipGeneration}
	workspace := filepath.Join(root, "workspace")
	if err := os.Mkdir(workspace, 0700); err != nil {
		t.Fatal(err)
	}
	spec := sessionworker.NativeSpec{Runtime: domain.RuntimeQwenCode, Binary: script, MCPExecutable: "/bin/true", NativeDirs: []string{filepath.Join(root, "native")}, Workspace: workspace, Kind: "worker", TenantID: scope.TenantID, NetworkTenantID: scope.TenantID, NetworkID: domain.NewID().String()}
	record, err := registry.Reserve(scope, spec, "credential-qwen", "")
	if err != nil {
		t.Fatal(err)
	}
	ownership := transport.NativeWorkerOwnership{ID: command.Subject.OwnershipID.String(), InstanceID: scope.InstanceID, OwnershipGeneration: scope.Generation, Runtime: string(spec.Runtime), Profile: record.Profile, ProfileFingerprint: record.ProfileFingerprint, OriginalAdmissionID: session.NativeAdmissionID, State: "active", LastDispatchSequence: 1}
	if err := registry.BindOwnership(record, ownership); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.db.Exec(`UPDATE native_workers SET launch_state='launched' WHERE instance_id=?`, scope.InstanceID); err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{37}, 32)
	defer clear(key)
	if err := sessionworker.PrepareBootstrap(record.Dir, sessionworker.Bootstrap{Protocol: sessionworker.Protocol, Scope: scope, Native: spec}, key); err != nil {
		t.Fatal(err)
	}
	child := exec.Command(os.Args[0], "-test.run=^TestDirectSourceCredentialV2ProductionOwnershipIPC$")
	child.Env = append(os.Environ(), childEnv+"="+record.Dir)
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	childDone := make(chan struct{})
	var childErr error
	go func() { childErr = child.Wait(); close(childDone) }()
	defer func() {
		_ = child.Process.Signal(os.Interrupt)
		select {
		case <-childDone:
		case <-time.After(10 * time.Second):
			_ = child.Process.Kill()
			<-childDone
			t.Error("original worker failed to stop")
		}
	}()
	socket, peer := nativeBindingSocketPair(t)
	var native *NativeObservationConnection
	native = NewNativeObservationConnection(scope.ServerURL, scope.HostID, session.BootID, func(_ context.Context, typ string, payload any) error {
		if typ == transport.MsgNativeOriginSession {
			request := payload.(transport.NativeOriginSessionPayload)
			native.SessionConfirmed(transport.NativeOriginSessionConfirmedPayload{RequestID: request.RequestID, OriginID: request.OriginID, NativeGeneration: request.NativeGeneration, SessionID: request.SessionID, RunnerID: request.RunnerID, RunnerEpoch: request.RunnerEpoch})
			return nil
		}
		if typ != transport.MsgNativeOriginRegister {
			t.Errorf("unexpected remote effect %s", typ)
			return ErrNativeOriginAdmissionDeferred
		}
		request := payload.(transport.NativeOriginRegisterPayload)
		native.OriginRegistered(transport.NativeOriginRegisteredPayload{RequestID: request.RequestID, Origin: &transport.NativeObservationOrigin{ID: domain.NewID().String(), CommandID: request.CommandID, TenantID: scope.TenantID, HostID: scope.HostID, InstanceID: scope.InstanceID, Runtime: string(spec.Runtime), NativeGeneration: request.NativeGeneration, NativeAdmissionID: request.NativeAdmissionID, RunnerID: session.RunnerID, RunnerEpoch: session.RunnerEpoch, BootID: session.BootID, CreatedAt: time.Now().UTC()}})
		return nil
	})
	defer native.Close()
	native.offeredDirectManagedSourceV2 = directManagedSourceProtocolsV2
	if err := native.Admit(session); err != nil {
		t.Fatal(err)
	}
	var proxy *NativeWorkerProxy
	for {
		proxy, err = AttachNativeWorker(ctx, native, record.Dir, scope, "credential-controller")
		if err == nil {
			break
		}
		select {
		case <-childDone:
			t.Fatal("original owner exited before attach", childErr)
		case <-ctx.Done():
			t.Fatal("attach original owner", err)
		case <-time.After(time.Millisecond):
		}
	}
	defer proxy.Close()
	originalLease := proxy.controller.Lease
	proof := transport.NativeDispatchProof{OwnershipID: ownership.ID, OwnershipGeneration: scope.Generation, DispatchSequence: 1, SourceCommandID: domain.NewID().String(), SourceAdmissionID: session.NativeAdmissionID, SourceRunnerID: session.RunnerID, SourceRunnerEpoch: session.RunnerEpoch, SourceBootID: session.BootID}
	activation, err := proxy.AcceptDispatch(ctx, ownership, proof, "attach", sessionworker.Operation{InputKind: "user_input"})
	if err != nil {
		t.Fatal(err)
	}
	var before sessionworker.NativeSnapshot
	for {
		if err := proxy.Reconcile(ctx); err != nil {
			t.Fatal("activate Qwen fixture", err)
		}
		before, err = proxy.Snapshot(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if before.PID > 0 && before.NativeSessionID != "" {
			break
		}
		outcome, err := proxy.call(ctx, sessionworker.Request{Type: "outcome", Sequence: activation.Sequence})
		if err != nil {
			t.Fatal(err)
		}
		if outcome.Outcome != nil && outcome.Outcome.State != "admitted" {
			t.Fatalf("Qwen fixture activation ended: %+v", *outcome.Outcome)
		}

		select {
		case <-ctx.Done():
			t.Fatal("Qwen activation timed out")
		case <-time.After(time.Millisecond):
		}
	}
	var origin transport.NativeObservationOrigin
	if err := json.Unmarshal(before.Origin, &origin); err != nil {
		t.Fatal(err)
	}
	command.Subject.NativeGeneration, command.Subject.NativeSessionID = before.NativeGeneration, before.NativeSessionID
	command.Subject.OriginID = domain.ID(origin.ID)
	state, err := OpenState(filepath.Join(root, "state.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	if err := state.UpsertInstance(InstanceRow{InstanceID: scope.InstanceID, Runtime: string(spec.Runtime), Profile: record.Profile, AgentPrincipalID: command.Subject.PrincipalID.String()}); err != nil {
		t.Fatal(err)
	}
	serveLock, err := os.Create(filepath.Join(root, "serve.lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer serveLock.Close()
	link := &nativeWorkerLink{conn: socket, proxy: proxy, ownership: ownership}
	d := &Daemon{state: state, nativeRegistry: registry, serveLockFile: serveLock, nativeWorkers: map[string]*nativeWorkerLink{scope.InstanceID: link}, curConn: socket, nativeConn: native, writeTimeout: time.Second}
	d.Config = Config{ServerURL: scope.ServerURL, DirectManagedSourceV2Enabled: true}
	d.sessions = sessioncore.NewManager()
	d.sessions.RegisterDriver(agentruntime.NewQwenPersistent(""))
	d.initDirectManagedSourceV2()
	executor, ok := d.directManagedSourceCredentialV2.(*localDirectManagedSourceCredentialV2)
	if !ok {
		t.Fatal("runtime did not compose full V2 suite")
	}
	handlers, closeHandlers := d.directManagedSourceV2Handlers(socket, native)
	dispatch := &directManagedSourceDispatch{v2: handlers, closeV2: closeHandlers}
	defer dispatch.close()
	exchange := func(typ string, payload any, id domain.ID) []byte {
		t.Helper()
		if !dispatch.handle(nativeBindingEnvelope(t, typ, payload)) {
			t.Fatal("source command escaped dispatch")
		}
		peer.SetReadDeadline(time.Now().Add(5 * time.Second))
		var env transport.Envelope
		if err := peer.ReadJSON(&env); err != nil {
			t.Fatal("runtime ACK", err)
		}
		var outer struct {
			CommandID domain.ID       `json:"commandId"`
			Error     string          `json:"error"`
			Result    json.RawMessage `json:"result"`
		}
		if env.Type != transport.MsgCommandAck || json.Unmarshal(env.Payload, &outer) != nil || outer.CommandID != id || outer.Error != "" {
			t.Fatal("invalid runtime ACK", string(env.Payload))
		}
		return outer.Result
	}
	// Use the production dispatch and bounded queues for all three phases.
	prepareRaw := exchange(transport.MsgDirectManagedSourcePrepareV2, command, command.CommandID)
	prepare, err := transport.DecodeDirectManagedSourcePrepareACKV2(prepareRaw, command)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := transport.NewDirectManagedSourcePrepareReceiptReferenceV2(prepare)
	if err != nil {
		t.Fatal(err)
	}
	serverKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := command.Subject.Digest()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	pop := transport.DirectManagedSourcePoPChallengeV2{ProtocolVersion: transport.DirectManagedSourcePoPProtocolV2, Suite: transport.DirectManagedSourcePoPSuiteV2, ChallengeID: domain.NewID(), Nonce: strings.Repeat("ab", 32), ServerEphemeralX25519: hex.EncodeToString(serverKey.PublicKey().Bytes()), IssuedAt: now, ExpiresAt: now.Add(time.Minute), Prepare: command, ACK: prepare, Receipt: receipt, SourceBindingDigest: digest}
	popRaw := exchange(transport.MsgDirectManagedSourcePoPV2, pop, pop.ChallengeID)
	popProof, err := transport.DecodeDirectManagedSourcePoPProofV2(popRaw)
	if err != nil {
		t.Fatal(err)
	}
	issueKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issue, err := transport.NewDirectManagedSourceCredentialIssueV2(transport.DirectManagedSourceCredentialIssueV2{CredentialID: domain.NewID(), ChannelGeneration: "1", Nonce: strings.Repeat("cd", 32), ServerEphemeralX25519: hex.EncodeToString(issueKey.PublicKey().Bytes()), IssuedAt: time.Now().UTC(), InstallExpiresAt: command.Subject.EnrollmentExpiresAt, CredentialExpiresAt: command.Subject.AuthorizationExpiresAt, BudgetExpiresAt: command.Subject.AuthorizationExpiresAt}, pop, popProof)
	if err != nil {
		t.Fatal(err)
	}
	lane := newDirectManagedSourceCredentialPublicationLane()
	ack := exchange(transport.MsgDirectManagedSourceCredentialV2, issue, issue.CredentialID)
	verify := func(retained transport.DirectManagedSourceCredentialIssueV2, server string, host transport.HostSessionPayload) error {
		_, err := executor.verifyCredentialPublication(ctx, socket, native, host, server, retained)
		return err
	}
	evidence, err := executor.keys.CredentialEvidence(issue, scope.ServerURL, session, verify)
	if err != nil || evidence.State != "installed" || !bytes.Equal(evidence.ACK, ack) {
		t.Fatal("installed evidence", err)
	}
	replay, err := executor.installCredential(ctx, socket, native, session, scope.ServerURL, issue, lane)
	if err != nil || !bytes.Equal(replay, ack) {
		t.Fatal("production retry changed ACK", err)
	}
	d.directManagedSourcePrepareV2, d.directManagedSourcePoPV2, d.directManagedSourceCredentialV2 = executor.localDirectManagedSourcePrepareV2, executor.localDirectManagedSourcePoPV2, executor
	connection := newDirectManagedSourceCredentialConnectionV2(d, socket, native, &directManagedSourceCredentialNegotiationV2{socket: socket, native: native, session: session})
	if connection == nil {
		t.Fatal("captured full suite rejected")
	}
	defer connection.close()
	connection.ack(ack, session, issue)
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	var env transport.Envelope
	if err := peer.ReadJSON(&env); err != nil {
		t.Fatal("guarded ACK", err)
	}
	var outer struct {
		CommandID domain.ID       `json:"commandId"`
		Error     string          `json:"error"`
		Result    json.RawMessage `json:"result"`
	}
	if env.Type != transport.MsgCommandAck || json.Unmarshal(env.Payload, &outer) != nil || outer.CommandID != issue.CredentialID || outer.Error != "" || !bytes.Equal(outer.Result, ack) {
		t.Fatal("guarded ACK changed retained result")
	}
	after, err := proxy.Snapshot(ctx)
	if err != nil || after.PID != before.PID || after.NativeStartIdentity != before.NativeStartIdentity || after.NativeGeneration != before.NativeGeneration || after.NativeSessionID != before.NativeSessionID || !bytes.Equal(after.Origin, before.Origin) || d.nativeWorkers[scope.InstanceID] != link || proxy.controller.WorkerBuild != "credential-original-worker" || proxy.controller.Lease != originalLease {
		t.Fatal("credential phase restarted or replaced original session", err)
	}
	select {
	case <-childDone:
		t.Fatal("credential phase stopped original owner", childErr)
	default:
	}
	// Pin a genuinely IPC-verified token before supersession. The shared ACK
	// fence must reject it after acquiring the writer and storage reservation.
	token, err := executor.verifyCredentialPublication(ctx, socket, native, session, scope.ServerURL, issue)
	if err != nil {
		t.Fatal(err)
	}
	replacement, _ := nativeBindingSocketPair(t)
	d.connMu.Lock()
	d.curConn = replacement
	d.connMu.Unlock()
	wrote := false
	d.writeMu.Lock()
	err = executor.publishCredentialACK(ctx, token, socket, native, session, scope.ServerURL, issue, lane, ack, func() error { wrote = true; return nil })
	d.writeMu.Unlock()
	if err == nil || wrote {
		t.Fatal("superseded socket reached guarded ACK writer")
	}
}
