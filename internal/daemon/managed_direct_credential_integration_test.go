//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

func TestManagedCredentialProductionOwnershipIPC(t *testing.T) {
	const childEnv = "PAGNET_TEST_TARGET_V1_CREDENTIAL_WORKER"
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
	_, subject, session := managedEndpointFixture(t)
	command := transport.ManagedEndpointPrepareCommand{ProtocolVersion: transport.ManagedEndpointPrepareProtocol, CommandID: domain.NewID(), Subject: subject}
	session.ProtocolFeatures = []string{transport.NativeObservationReceiptProtocol, transport.NativeWorkerOwnershipProtocol, transport.ManagedEndpointPrepareProtocol, transport.ManagedEndpointPoPProtocol, transport.ManagedDirectCredentialProtocol}
	if err := os.Mkdir(filepath.Join(root, "daemon"), 0700); err != nil {
		t.Fatal(err)
	}
	registry, err := OpenNativeWorkerRegistry(filepath.Join(root, "daemon"))
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	configuredServer := "https://example.test"
	configured := &Daemon{Config: Config{ServerURL: configuredServer, ManagedEndpointPrepareEnabled: true, ManagedEndpointPoPEnabled: true, ManagedDirectCredentialEnabled: true}}
	scope := sessionworker.Scope{ServerURL: configured.nativeServerURL(), TenantID: session.TenantID, AccountID: session.AccountID, HostID: session.HostID, InstanceID: command.Subject.InstanceID.String(), Generation: command.Subject.OwnershipGeneration}
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
	child := exec.Command(os.Args[0], "-test.run=^TestManagedCredentialProductionOwnershipIPC$")
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
	native.offeredManagedEndpointPrepare = true
	native.offeredManagedEndpointPoP = true
	native.offeredManagedDirectCredential = true
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
	d.Config = configured.Config

	// Construct during transient startup unavailability, retaining the original
	// real ownership IPC worker. Reconnect URL construction retries initialization
	// and offers only after dependency and executor readiness recover.
	d.serveLockFile = nil
	d.initManagedDirectCredential()
	executor, ok := d.managedDirectCredential.(*localManagedDirectCredential)
	if !ok || executor.ready() {
		t.Fatal("unready startup custody was not retained")
	}
	reconnectOffer := func() []string {
		t.Helper()
		endpoint, err := url.Parse(d.wsURL(ctx))
		if err != nil {
			t.Fatal(err)
		}
		return endpoint.Query()["managed_direct_credential"]
	}
	if got := reconnectOffer(); len(got) != 0 {
		t.Fatal("unready startup offered credential", got)
	}
	d.serveLockFile = serveLock
	d.managedEndpointPrepare = executor.localManagedEndpointPrepare
	d.managedEndpointPoP = executor.localManagedEndpointPrepare
	if got := reconnectOffer(); len(got) != 1 || got[0] != transport.ManagedDirectCredentialProtocol || d.managedDirectCredential != executor {
		t.Fatal("healthy reconnect failed to retain and offer custody", got)
	}
	prepareRaw, err := executor.prepare(ctx, socket, native, session, scope.ServerURL, command)
	if err != nil {
		t.Fatal("prepare", err)
	}
	prepare, err := transport.DecodeManagedEndpointPrepareACK(prepareRaw, command)
	if err != nil {
		t.Fatal(err)
	}
	receipt, _ := transport.NewManagedEndpointPrepareReceiptReference(prepare)
	var authorization transport.DirectAuthorizationSnapshotV1
	raw, err := os.ReadFile("../../transport/testdata/managed_endpoint_pop_v1/authorization.json")
	if err != nil || json.Unmarshal(raw, &authorization) != nil {
		t.Fatal("authorization fixture", err)
	}
	authorization.DirectIntentID = command.Subject.DirectIntentID
	authorization.InviteeTenantID = command.Subject.TenantID
	authorization.InviteeAccountID = command.Subject.AccountID
	authorization.Target.PrincipalID = command.Subject.PrincipalID
	authorization.CreatedAt = command.Subject.CreatedAt
	authorization.ExpiresAt = command.Subject.ExpiresAt
	authorization.GrantExpiresAt = command.Subject.ExpiresAt.Add(time.Hour)
	digest, err := authorization.Digest()
	if err != nil {
		t.Fatal(err)
	}
	serverKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	pop := transport.ManagedEndpointPoPChallenge{ProtocolVersion: transport.ManagedEndpointPoPProtocol, Suite: transport.ManagedEndpointPoPSuite, ChallengeID: domain.NewID(), Nonce: strings.Repeat("ab", 32), ServerEphemeralX25519: hex.EncodeToString(serverKey.PublicKey().Bytes()), IssuedAt: now, ExpiresAt: now.Add(time.Minute), Prepare: command, ACK: prepare, Receipt: receipt, Authorization: authorization, AuthorizationDigest: digest}
	proofRaw, err := executor.confirmPoP(ctx, socket, native, session, scope.ServerURL, pop)
	if err != nil {
		t.Fatal("pop", err)
	}
	popProof, _, err := transport.DecodeManagedEndpointPoPProofVerifier(proofRaw)
	if err != nil {
		t.Fatal(err)
	}
	issueKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issue, err := transport.NewManagedDirectCredentialIssue(transport.ManagedDirectCredentialIssue{CredentialID: domain.NewID(), ChannelGeneration: 1, Nonce: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{64}, 32)), ServerEphemeralX25519: hex.EncodeToString(issueKey.PublicKey().Bytes()), IssuedAt: time.Now().UTC(), InstallExpiresAt: pop.ExpiresAt, CredentialExpiresAt: now.Add(2 * time.Minute), Budget: transport.ManagedDirectCredentialBudgetReference{AgreementID: domain.NewID(), AcceptedRevision: 2, TermsDigest: strings.Repeat("ef", 32), ExpiresAt: now.Add(3 * time.Minute)}}, pop, popProof)
	if err != nil {
		t.Fatal(err)
	}
	issueRaw, _ := issue.CanonicalBytes()
	d.managedEndpointPrepare = executor.localManagedEndpointPrepare
	d.managedEndpointPoP = executor.localManagedEndpointPrepare
	d.managedDirectCredential = executor
	connection := newManagedDirectCredentialConnection(d, socket, native, &managedDirectCredentialNegotiation{socket: socket, native: native, session: session})
	if connection == nil {
		t.Fatal("target runtime negotiation")
	}
	defer connection.close()
	var ack []byte
	for attempt := 0; attempt < 2; attempt++ {
		connection.handle(nativeBindingEnvelope(t, transport.MsgManagedDirectCredential, issue))
		_ = peer.SetReadDeadline(time.Now().Add(5 * time.Second))
		var envelope transport.Envelope
		if err := peer.ReadJSON(&envelope); err != nil {
			t.Fatal("runtime ACK", err)
		}
		var outer struct {
			CommandID domain.ID       `json:"commandId"`
			Error     string          `json:"error"`
			Result    json.RawMessage `json:"result"`
		}
		if envelope.Type != transport.MsgCommandAck || json.Unmarshal(envelope.Payload, &outer) != nil || outer.CommandID != issue.CredentialID || outer.Error != "" {
			t.Fatal("runtime ACK envelope")
		}
		if _, err := transport.DecodeManagedDirectCredentialACK(outer.Result); err != nil {
			t.Fatal(err)
		}
		if attempt == 0 {
			ack = append([]byte(nil), outer.Result...)
		} else if !bytes.Equal(ack, outer.Result) {
			t.Fatal("server redelivery changed retained ACK")
		}
	}
	verify := func(retained transport.ManagedDirectCredentialIssue, server string, host transport.HostSessionPayload) error {
		_, err := executor.verifyCredentialPublication(ctx, socket, native, host, server, retained)
		return err
	}
	evidence, err := executor.keys.CredentialEvidence(issue, scope.ServerURL, session, verify)
	if err != nil || evidence.State != "installed" || !bytes.Equal(ack, evidence.ACK) {
		t.Fatal("custody evidence", err)
	}
	for _, reason := range []string{"session", "ownership", "scope", "restart", "cancel", "kind", "canonical"} {
		t.Run(reason, func(t *testing.T) {
			host, endpoint, kind, payload := session, scope.ServerURL, "host.managed_direct_credential", issueRaw
			lane := newDirectManagedSourceCredentialPublicationLane()
			switch reason {
			case "session":
				host.BootID += "stale"
			case "ownership":
				link.mu.Lock()
				link.ownership.State = "retired"
				link.mu.Unlock()
				defer func() { link.mu.Lock(); link.ownership = ownership; link.mu.Unlock() }()
			case "scope":
				endpoint = "https://untrusted.test"
			case "restart":
				old := d.curConn
				d.curConn = nil
				defer func() { d.curConn = old }()
			case "cancel":
				lane.cancel()
			case "kind":
				kind = transport.MsgDirectManagedSourceCredentialV2
			case "canonical":
				payload = append([]byte(" "), issueRaw...)
			}
			got, err := executor.executeCredential(ctx, socket, native, host, endpoint, kind, payload, lane)
			if reason == "kind" || reason == "canonical" {
				if err == nil || got != nil {
					t.Fatal("invalid wire input accepted")
				}
				return
			}
			failure, decodeErr := transport.DecodeManagedDirectCredentialFailureACK(got)
			if err != nil || decodeErr != nil || failure.CredentialID != issue.CredentialID || failure.Error != transport.ManagedDirectCredentialInstallFailure {
				t.Fatal("fixed failure ACK", err, decodeErr)
			}
		})
	}
	after, err := proxy.Snapshot(ctx)
	if err != nil || after.PID != before.PID || after.NativeStartIdentity != before.NativeStartIdentity || after.NativeGeneration != before.NativeGeneration || after.NativeSessionID != before.NativeSessionID || !bytes.Equal(after.Origin, before.Origin) || d.nativeWorkers[scope.InstanceID] != link || proxy.controller.Lease != originalLease {
		t.Fatal("credential phase replaced original session", err)
	}

	// Capture real ownership IPC authority, then hold it through the store's
	// reserved transaction while a current-socket mutation attempts to enter.
	token, err := executor.verifyCredentialPublication(ctx, socket, native, session, scope.ServerURL, issue)
	if err != nil {
		t.Fatal("fresh ownership IPC", err)
	}
	captured := ManagedEndpointPrepareScope{Socket: socket, Connection: native, Session: session}
	lane := newDirectManagedSourceCredentialPublicationLane()
	fence := d.managedDirectCredentialPublicationFence(token, captured, lane)
	started, mutated := make(chan struct{}), make(chan struct{})
	err = executor.keys.withCredentialLockedScoped(func(conn *sql.Conn, _ *os.File, release *func()) error {
		var err error
		*release, err = fence(conn, issue, scope.ServerURL, session)
		if err != nil {
			return err
		}
		go func() { close(started); d.connMu.Lock(); d.curConn = nil; d.connMu.Unlock(); close(mutated) }()
		<-started
		if d.connMu.TryLock() {
			d.connMu.Unlock()
			t.Error("current session escaped publication guard")
		}
		select {
		case <-mutated:
			t.Error("session changed before commit")
		default:
		}
		return nil
	})
	if err != nil {
		t.Fatal("real publication guard", err)
	}
	<-mutated
	err = executor.keys.withCredentialLockedScoped(func(conn *sql.Conn, _ *os.File, release *func()) error {
		var err error
		*release, err = fence(conn, issue, scope.ServerURL, session)
		return err
	})
	if err == nil {
		t.Fatal("previous IPC token survived final session fence")
	}
	select {
	case <-childDone:
		t.Fatal("original owner stopped", childErr)
	default:
	}
}
