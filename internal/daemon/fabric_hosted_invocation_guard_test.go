//go:build linux || darwin

package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/localinstallation"
	"github.com/pagnet-code/pagnet/fabric/registry"
	hostcrypto "github.com/pagnet-code/pagnet/internal/crypto"
	"github.com/pagnet-code/pagnet/internal/fabricagent"
	"github.com/pagnet-code/pagnet/internal/fabricauth"
	agentruntime "github.com/pagnet-code/pagnet/internal/runtime"
	"github.com/pagnet-code/pagnet/transport"
)

// pagnetWorkerBinary builds (when stale/missing) the real pagnet binary the
// detached native worker is launched from, into the shared scratch bin dir
// (NEVER into the repo's bin/).
func pagnetWorkerBinary(t *testing.T) string {
	t.Helper()
	dir := os.Getenv("PAGNET_P0_BIN_DIR")
	if dir == "" {
		abs, err := filepath.Abs(filepath.Join("..", "..", "..", ".qwen", "tmp", "p0-bin"))
		if err != nil {
			t.Fatalf("resolve scratch bin dir: %v", err)
		}
		dir = abs
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir scratch bin dir: %v", err)
	}
	bin := filepath.Join(dir, "pagnet-worker-bin")
	needBuild := true
	if fi, err := os.Stat(bin); err == nil {
		srcFiles, gerr := filepath.Glob(filepath.Join("..", "..", "cmd", "pagnet", "*.go"))
		if gerr == nil {
			var newest time.Time
			for _, f := range srcFiles {
				if s, serr := os.Stat(f); serr == nil && s.ModTime().After(newest) {
					newest = s.ModTime()
				}
			}
			if !newest.IsZero() && fi.ModTime().After(newest) {
				needBuild = false
			}
		}
	}
	if needBuild {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, "go", "build", "-o", bin, "./cmd/pagnet")
		cmd.Dir = filepath.Join("..", "..")
		cmd.Env = append(os.Environ(), "GOWORK=off")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build pagnet worker binary: %v\n%s", err, out)
		}
	}
	return bin
}

// hostedGuardFixture is the real end-to-end delivery fixture: an actual
// daemon with a launched detached native worker (real pagnet worker binary,
// real fake-persistent endpoint), a genuine local installation (real
// registry/authority/keys behind a 0700 socket dir with a real
// fabricauth.BindOwner session), the step-1 signed initial-effect journal,
// and the daemon guard composed over it.
type hostedGuardFixture struct {
	t          *testing.T
	d          *Daemon
	conn       *websocket.Conn
	server     *websocket.Conn
	ownerConn  *NativeObservationConnection
	record     NativeWorkerRecord
	session    *fabricauth.Session
	owner      fabric.ExecutionContext
	root       registry.AuthorityIdentity
	ref        fabric.EndpointRef
	revision   fabric.Revision
	scope      registry.DescriptorBatchScope
	profile    fabricagent.HostedProfile
	principal  fabric.Principal
	journal    *fabricagent.HostedInvocations
	profiles   *fabricagent.HostedProfiles
	admission  transport.HostSessionPayload
	networkID  string
	keyEpochID string
	key        [32]byte
	plan       [32]byte
	// installation is the genuine local installation the fixture bootstraps
	// (step 3's sideport tests compose the real node over its store).
	installation *localinstallation.Installation
	// workerEnv is applied to the daemon before the native worker is
	// launched (the fake runtime's deterministic output knobs).
	workerEnv []string
	// catalogServer is the test-side server half of the hosted catalog
	// import pair (step 5); nil = the fixture serves no catalog pages.
	// Atomic: the responder reads it from the importer's goroutine while
	// the test goroutine (re)queues a generation.
	catalogServer atomic.Pointer[hostedCatalogTestServer]
}

type hostedGuardFixtureOption func(*hostedGuardFixture)

// withWorkerEnv appends env to the daemon's RuntimeEnv before the native
// worker is launched (the fake runtime's deterministic output knobs, e.g.
// PAGNET_FAKE_OUTPUT_CHUNK_BYTES / PAGNET_FAKE_FULL_OUTPUT_REPEAT).
func withWorkerEnv(env ...string) hostedGuardFixtureOption {
	return func(f *hostedGuardFixture) { f.workerEnv = env }
}

func newHostedGuardFixture(t *testing.T, opts ...hostedGuardFixtureOption) *hostedGuardFixture {
	t.Helper()
	ctx := t.Context()
	d := newTestDaemon(t)
	f := &hostedGuardFixture{t: t, d: d}
	for _, opt := range opts {
		opt(f)
	}
	if len(f.workerEnv) > 0 {
		d.RuntimeEnv = append([]string(nil), f.workerEnv...)
	}
	d.ServerURL = "https://app.pagnet.dev"
	d.HostID = domain.NewID().String()
	pf, ok := d.sessions.DriverFor(domain.RuntimeFakePersistent).(*agentruntime.PersistentFake)
	if !ok {
		t.Fatal("expected the PersistentFake driver to be registered (debug mode)")
	}
	pf.Binary = p0FakeBinary(t)
	d.selfExe = pagnetWorkerBinary(t)

	tenantID := domain.NewID().String()
	networkID := domain.NewID().String()
	st := setupActiveNetCrypto(t, d, tenantID, networkID)
	ring, err := hostcrypto.LoadKeyring(d.StateDir, networkID)
	if err != nil {
		t.Fatal(err)
	}
	epoch, ok := ring.EpochByID(st.EpochID)
	if !ok {
		t.Fatal("active epoch missing from local keyring")
	}
	key, err := epoch.KeyArray()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key[:])

	client, server := newMemWS(t)
	d.connMu.Lock()
	d.curConn = client
	d.connMu.Unlock()

	// The observation lane: a direct test responder committing activation
	// origin, session renewal and ownership registration, exactly like the
	// control plane would.
	admission := transport.HostSessionPayload{TenantID: tenantID, AccountID: tenantID, OwnershipScope: "personal", HostID: d.HostID, BootID: d.bootID, NativeAdmissionID: domain.NewID().String(), RunnerID: domain.NewID().String(), RunnerEpoch: time.Now().UTC(), ProtocolFeatures: []string{transport.NativeObservationReceiptProtocol, transport.NativeWorkerOwnershipProtocol, transport.FabricHostedProtocol}}
	ownershipID := domain.NewID().String()
	var ownerConn *NativeObservationConnection
	ownerConn = NewNativeObservationConnection(d.ServerURL, d.HostID, d.bootID, func(_ context.Context, typ string, payload any) error {
		switch typ {
		case transport.MsgNativeOriginRegister:
			p := payload.(transport.NativeOriginRegisterPayload)
			ownerConn.OriginRegistered(transport.NativeOriginRegisteredPayload{RequestID: p.RequestID, Origin: &transport.NativeObservationOrigin{ID: domain.NewID().String(), NativeAdmissionID: admission.NativeAdmissionID, TenantID: tenantID, HostID: d.HostID, InstanceID: p.InstanceID, CommandID: p.CommandID, Runtime: p.Runtime, NativeGeneration: p.NativeGeneration, RunnerID: admission.RunnerID, RunnerEpoch: admission.RunnerEpoch, BootID: d.bootID, CreatedAt: time.Now().UTC()}})
		case transport.MsgNativeOriginSession:
			p := payload.(transport.NativeOriginSessionPayload)
			ownerConn.SessionConfirmed(transport.NativeOriginSessionConfirmedPayload{RequestID: p.RequestID, OriginID: p.OriginID, NativeGeneration: p.NativeGeneration, SessionID: p.SessionID, RunnerID: admission.RunnerID, RunnerEpoch: admission.RunnerEpoch})
		case transport.MsgNativeObservation:
			p := payload.(transport.NativeObservationPayload)
			ownerConn.NativeWorkerObservationDisposition(transport.MsgNativeObservationReceipt, transport.NativeObservationReceiptPayload{ObservationID: p.ObservationID, OriginID: p.OriginID, Digest: p.Digest, Disposition: "committed"})
		case transport.MsgNativeOwnershipRegister:
			p := payload.(transport.NativeOwnershipRegisterPayload)
			o := transport.NativeWorkerOwnership{ID: ownershipID, InstanceID: p.InstanceID, OwnershipGeneration: p.OwnershipGeneration, Runtime: p.Runtime, Profile: p.Profile, ProfileFingerprint: p.ProfileFingerprint, OriginalAdmissionID: p.NativeAdmissionID, State: "active"}
			ownerConn.OwnershipDisposition(transport.NativeOwnershipRegisteredPayload{RequestID: p.RequestID, Ownership: &o})
		case transport.MsgFabricHostedCatalogRequest:
			if cs := f.catalogServer.Load(); cs != nil {
				cs.serveRequest(payload.(transport.FabricHostedCatalogRequest))
			}
		default:
			t.Errorf("unexpected observation message %s", typ)
		}
		return nil
	})
	if err := ownerConn.Admit(admission); err != nil {
		t.Fatal(err)
	}
	d.connMu.Lock()
	d.nativeConn = ownerConn
	d.connMu.Unlock()

	repo := t.TempDir()
	gitInitRepo(t, repo)
	instanceID := domain.NewID().String()
	definitionID := domain.NewID().String()
	principalID := domain.NewID().String()
	launch := transport.LaunchAgentPayload{CommandID: domain.NewID().String(), InstanceID: instanceID, DefinitionID: definitionID, AgentPrincipalID: principalID, Runtime: string(domain.RuntimeFakePersistent), WorkspacePath: repo, AgentName: "guard", NetworkID: networkID}
	prep := transport.NativeOwnershipPreparePayload{SourceCommandID: launch.CommandID, SourceCommandType: transport.MsgLaunchAgent, InstanceID: instanceID, Runtime: string(domain.RuntimeFakePersistent), Launch: &launch}
	if err := d.prepareNativeOwnership(client, prep); err != nil {
		t.Fatalf("prepare native ownership: %v", err)
	}
	record, err := d.nativeRegistry.Lookup(instanceID)
	if err != nil {
		t.Fatal(err)
	}
	if record.LaunchState != "launched" || record.Ownership == nil || record.Ownership.ID != ownershipID {
		t.Fatalf("worker not launched with the registered ownership: state=%q ownership=%+v", record.LaunchState, record.Ownership)
	}

	// Genuine local installation behind a 0700 socket dir (kernel peer
	// binding requires owner-only directories), with a real owner session.
	parent, err := os.MkdirTemp("", "pgn-hosted-guard-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(parent) })
	socketDir := filepath.Join(parent, "run")
	if err := os.Mkdir(socketDir, 0700); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(socketDir, "guard.sock")
	installation, err := localinstallation.Bootstrap(ctx, filepath.Join(parent, "local"), localinstallation.Options{Settings: localinstallation.DefaultSettings(socket)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { installation.Close() })
	owner, err := installation.Operator(ctx)
	if err != nil {
		t.Fatal(err)
	}
	root := installation.Store.AuthorityIdentity()
	ref, err := fabric.NewEndpointRef(root.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := fabric.EndpointDescriptor{Ref: ref, Kind: "actor.agent", Name: "Guard", Description: "Exact hosted guard target", Bindings: []fabric.BindingSummary{{ID: "original", Protocol: "pagnet.agent.hosted-native.v1", Version: "1"}}}
	descriptorBytes, err := json.Marshal(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	revision, err := installation.Store.Register(ctx, owner, fabric.RegistryUpdate{Descriptor: descriptor})
	if err != nil {
		t.Fatal(err)
	}
	// The hosted caller is the LOCAL actor bound to the local endpoint — a
	// distinct principal from the installation owner, which the journal
	// rejects as a hosted caller. The authenticated context is node-composed
	// from the signed registered descriptor, never from delivery data.
	principal := fabric.Principal{Ref: ref.String(), Kind: descriptor.Kind, Issuer: root.Namespace}
	caller, err := fabric.NewAuthenticatedContext(principal, root.Namespace, descriptorBytes)
	if err != nil {
		t.Fatal(err)
	}
	var nativeProfile [32]byte
	decoded, err := hex.DecodeString(record.ProfileFingerprint)
	if err != nil || len(decoded) != 32 {
		t.Fatalf("decode worker profile fingerprint: %v", err)
	}
	copy(nativeProfile[:], decoded)
	profile := fabricagent.HostedProfile{DefinitionID: definitionID, PrincipalID: principalID, NetworkID: networkID, OwnershipID: record.Ownership.ID, NativeProfile: nativeProfile, WorkerDirectory: record.Dir, Scope: record.Scope}
	if err := profile.Validate(); err != nil {
		t.Fatalf("daemon record does not form a valid hosted profile: %v", err)
	}
	scope := registry.DescriptorBatchScope{Endpoint: ref, ExpectedEndpointRevision: revision, BindingID: "original"}
	// The probe is the daemon's real original-worker inspection: the
	// registry profile is only trusted against the live local record.
	profiles, err := fabricagent.NewHostedProfiles(ctx, installation.Store, func(context.Context) (fabric.ExecutionContext, error) { return owner, nil }, installation.Keys, d.ProbeHostedProfile)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	listener.SetUnlinkOnClose(false)
	if err := os.Chmod(socket, 0600); err != nil {
		t.Fatal(err)
	}
	peer, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { peer.Close() })
	accepted, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { accepted.Close() })
	auth, err := fabricauth.New(fabricauth.Config{Root: root, RootOwner: root.Owner, Audience: root.Namespace, SocketPath: socket, CurrentRoot: installation.Store.CurrentAuthorityIdentity})
	if err != nil {
		t.Fatal(err)
	}
	session, err := auth.BindOwner(ctx, accepted)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { session.Close() })
	if err := session.WithOwnerAdministration(ctx, []byte(`{"operation":"agent.hosted.invocation.guard"}`), func(ctx context.Context, access *fabricauth.OwnerAdministration) error {
		_, e := profiles.Install(ctx, access, scope, profile)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	journal, err := fabricagent.NewHostedInvocations(ctx, installation.Store, profiles, installation.Keys, fabricagent.HostedInvocationLimits{MaxInvocations: 16, MaxBytes: 768 << 10})
	if err != nil {
		t.Fatal(err)
	}
	// The resolve port models the node's selected-binding wiring: the exact
	// registered descriptor, its hosted-native binding and the installed
	// profile — never a value taken from the delivery payload.
	resolve := func(ctx context.Context, instanceID string) (registry.DescriptorBatchScope, fabricagent.HostedProfile, error) {
		descriptor, err := installation.Store.GetEndpoint(ctx, ref, revision)
		if err != nil {
			return registry.DescriptorBatchScope{}, fabricagent.HostedProfile{}, err
		}
		binding := ""
		for _, b := range descriptor.Bindings {
			if b.Protocol == "pagnet.agent.hosted-native.v1" {
				if binding != "" {
					return registry.DescriptorBatchScope{}, fabricagent.HostedProfile{}, errors.New("ambiguous hosted binding")
				}
				binding = b.ID
			}
		}
		if binding == "" {
			return registry.DescriptorBatchScope{}, fabricagent.HostedProfile{}, errors.New("no hosted native binding")
		}
		s := registry.DescriptorBatchScope{Endpoint: ref, ExpectedEndpointRevision: descriptor.Revision, BindingID: binding}
		p, _, err := profiles.Get(ctx, s)
		if err != nil {
			return s, fabricagent.HostedProfile{}, err
		}
		if p.Scope.InstanceID != instanceID {
			return s, fabricagent.HostedProfile{}, errors.New("instance not bound to the selected binding")
		}
		return s, p, nil
	}
	d.HostedInvocationGuard = NewHostedInvocationGuard(journal, func(context.Context) (fabric.ExecutionContext, error) { return caller, nil }, resolve)

	f.conn, f.server, f.ownerConn, f.record = client, server, ownerConn, record
	f.session, f.owner, f.root, f.ref, f.revision = session, owner, root, ref, revision
	f.scope, f.profile, f.principal, f.journal, f.profiles = scope, profile, principal, journal, profiles
	f.admission, f.networkID, f.keyEpochID, f.key = admission, networkID, st.EpochID, key
	f.installation = installation
	f.plan[0], f.plan[31] = 0x01, 0x02
	return f
}

// reserve journals one exact invocation whose retained ciphertext is the
// encrypted prompt (or an explicit plaintext override) under the daemon's
// active network epoch, and returns the delivered packet + dispatch proof.
func (f *hostedGuardFixture) reserve(invocation, prompt string, plaintextOverride []byte) (transport.FabricHostedInvocation, transport.NativeDispatchProof) {
	f.t.Helper()
	ctx := f.t.Context()
	inputJSON, err := json.Marshal(prompt)
	if err != nil {
		f.t.Fatal(err)
	}
	env := fabric.Envelope{
		ProtocolVersion:  fabric.CurrentProtocolVersion,
		ID:               invocation,
		Operation:        fabric.OperationInvoke,
		Principal:        f.principal,
		Source:           f.principal.Ref,
		Target:           &f.ref,
		ExpectedRevision: f.revision,
		CreatedAt:        time.Now().UTC(),
		Payload:          json.RawMessage(`{"input":` + string(inputJSON) + `}`),
		Context:          fabric.EnvelopeContext{Origin: f.principal.Ref},
	}
	original, err := json.Marshal(env)
	if err != nil {
		f.t.Fatal(err)
	}
	finalized := original
	caller, err := fabric.NewAuthenticatedContext(f.principal, f.root.Namespace, original)
	if err != nil {
		f.t.Fatal(err)
	}
	aad := e2ee.AAD{
		ProtocolVersion: transport.ProtocolVersion,
		TenantID:        f.profile.Scope.TenantID,
		NetworkID:       f.networkID,
		ObjectType:      e2ee.ObjectTypeInvocationInput,
		ObjectID:        invocation,
		Sender:          f.profile.Scope.HostID,
		Recipient:       f.profile.Scope.InstanceID,
		CreatedAt:       "2026-10-05T00:00:00Z",
		KeyEpochID:      f.keyEpochID,
	}
	plaintext, err := json.Marshal(map[string]string{"input": prompt})
	if err != nil {
		f.t.Fatal(err)
	}
	if plaintextOverride != nil {
		plaintext = plaintextOverride
	}
	cipher, err := e2ee.Encrypt(plaintext, f.key, aad)
	if err != nil {
		f.t.Fatal(err)
	}
	commandID := domain.NewID().String()
	frame := fabric.DispatchAdmissionFrame{SourceDomain: f.root.Namespace, AudienceDomain: f.root.Namespace, CallerRef: f.principal.Ref, InvocationID: invocation, AttemptID: "guard-attempt", ReplayID: "guard-replay", FinalizedDispatchDigest: sha256.Sum256(finalized)}
	if _, fresh, err := f.journal.Reserve(ctx, f.scope, caller, original, finalized, frame, fabricagent.InvokedInput{Ciphertext: cipher, AAD: aad, CommandID: commandID}, f.plan); err != nil || !fresh {
		f.t.Fatalf("reserve: %v fresh=%v", err, fresh)
	}
	delivered := transport.FabricHostedInvocation{RequestID: commandID, CommandID: commandID, Ref: f.scope.Endpoint, Revision: f.scope.ExpectedEndpointRevision, InvocationID: invocation, NetworkID: f.networkID, InstanceID: f.profile.Scope.InstanceID, OwnershipID: f.profile.OwnershipID, OwnershipGeneration: f.profile.Scope.Generation, Envelope: cipher, AAD: aad}
	proof := transport.NativeDispatchProof{
		InvocationSource:    &transport.NativeInvocationSource{InvocationID: invocation, InputAAD: aad},
		SourceBootID:        f.d.bootID,
		OwnershipID:         f.profile.OwnershipID,
		OwnershipGeneration: f.profile.Scope.Generation,
		DispatchSequence:    1,
		SourceCommandID:     commandID,
		SourceAdmissionID:   f.admission.NativeAdmissionID,
		SourceRunnerID:      f.admission.RunnerID,
		SourceRunnerEpoch:   f.admission.RunnerEpoch,
	}
	return delivered, proof
}

// deliver drives one delivery through the daemon's real command flow and
// returns the ack payload.
func (f *hostedGuardFixture) deliver(p transport.NetworkEventPayload) map[string]any {
	f.t.Helper()
	env, err := transport.NewEnvelope(transport.MsgDeliverNetworkEvent, p)
	if err != nil {
		f.t.Fatal(err)
	}
	f.d.handleCommand(f.conn, env)
	_, ack := readUntilAck(f.t, f.server, p.CommandID)
	return ack
}

func ackError(t *testing.T, ack map[string]any) string {
	t.Helper()
	errMsg, _ := ack["error"].(string)
	if errMsg == "" {
		t.Fatalf("delivery was accepted, want a refusal: %+v", ack)
	}
	return errMsg
}

// waitForTurns polls the worker-side fake session state until the runtime
// has executed the expected turn. The worker's own on-disk state is the
// execution oracle: a native worker runs turns inside the worker process,
// and its output crosses only the observation lane, never the host wire.
func (f *hostedGuardFixture) waitForTurns(wantTurns int, wantLastInput string) {
	f.t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		turns, last := f.fakeTurns()
		if turns >= wantTurns && (wantLastInput == "" || last == wantLastInput) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	turns, last := f.fakeTurns()
	f.t.Fatalf("fake turn state = %d/%q, want %d turns with last input %q", turns, last, wantTurns, wantLastInput)
}

// fakeTurns reads the fake persistent endpoint's on-disk turn count (the
// worker-side driver state, never a daemon cache).
func (f *hostedGuardFixture) fakeTurns() (int, string) {
	f.t.Helper()
	path := filepath.Join(f.record.Dir, "native-state", "sessions", f.profile.Scope.InstanceID, "session.json")
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		// No session file: the runtime never executed a turn.
		return 0, ""
	}
	if err != nil {
		f.t.Fatalf("read fake session file: %v", err)
	}
	var s struct {
		Turns     int    `json:"turns"`
		LastInput string `json:"lastInput"`
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		f.t.Fatalf("parse fake session file: %v", err)
	}
	return s.Turns, s.LastInput
}

func TestDaemonHostedInvocationDeliveryInterceptsAndAcceptsRetainedPrompt(t *testing.T) {
	f := newHostedGuardFixture(t)
	invocation := domain.NewID().String()
	prompt := "exact retained hosted prompt"
	delivered, proof := f.reserve(invocation, prompt, nil)

	p := transport.NetworkEventPayload{CommandID: delivered.CommandID, InstanceID: f.profile.Scope.InstanceID, NetworkID: f.networkID, Kind: "invocation", Envelope: &delivered.Envelope, AAD: &delivered.AAD, NativeDispatch: &proof}
	if errMsg, _ := f.deliver(p)["error"].(string); errMsg != "" {
		t.Fatalf("canonical invocation delivery refused: %s", errMsg)
	}
	// The accepted turn executed the retained prompt text verbatim as the
	// worker's turn input (the worker-side session state is the oracle).
	f.waitForTurns(1, prompt)

	// A replayed identical delivery (ack lost, server re-sends) is idempotent:
	// clean re-ack, no second execution.
	if errMsg, _ := f.deliver(p)["error"].(string); errMsg != "" {
		t.Fatalf("replayed identical delivery refused: %s", errMsg)
	}
	// Grace window: an unlawful re-execution would land in the worker within
	// milliseconds; a stable count is the idempotency proof.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if turns, _ := f.fakeTurns(); turns != 1 {
			t.Fatalf("replay executed a second turn: %d", turns)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestDaemonHostedInvocationDeliveryRejectsTamperedOriginals(t *testing.T) {
	f := newHostedGuardFixture(t)
	// The daemon dedups deliveries by CommandID, so every variant reserves
	// its own exact original and delivers under its own fresh command.
	invocation := domain.NewID().String()
	delivered, proof := f.reserve(invocation, "tamper check prompt", nil)

	// 1. Consistently re-stamped AAD (wire and proof agree, but the sealed
	// original does not): the journal reports the stale reference conflict.
	reamped := delivered
	reamped.AAD.CreatedAt = "2026-10-05T00:00:01Z"
	proofReamped := proof
	proofReamped.InvocationSource = &transport.NativeInvocationSource{InvocationID: invocation, InputAAD: reamped.AAD}
	p := transport.NetworkEventPayload{CommandID: delivered.CommandID, InstanceID: f.profile.Scope.InstanceID, NetworkID: f.networkID, Kind: "invocation", Envelope: &reamped.Envelope, AAD: &reamped.AAD, NativeDispatch: &proofReamped}
	errMsg := ackError(t, f.deliver(p))
	if !strings.Contains(errMsg, "retained original") {
		t.Fatalf("re-stamped AAD ack error = %q, want the retained-original conflict", errMsg)
	}

	// 2. Substituted ciphertext under the same epoch (a different retained
	// invocation's content): the sealed ciphertext binding fails.
	second := domain.NewID().String()
	third := domain.NewID().String()
	secondDelivered, secondProof := f.reserve(second, "second prompt", nil)
	thirdDelivered, thirdProof := f.reserve(third, "third prompt", nil)
	p = transport.NetworkEventPayload{CommandID: secondDelivered.CommandID, InstanceID: f.profile.Scope.InstanceID, NetworkID: f.networkID, Kind: "invocation", Envelope: &thirdDelivered.Envelope, AAD: &secondDelivered.AAD, NativeDispatch: &secondProof}
	errMsg = ackError(t, f.deliver(p))
	if !strings.Contains(errMsg, "retained original") {
		t.Fatalf("substituted ciphertext ack error = %q, want the retained-original conflict", errMsg)
	}

	// 3. Wrong object type on the wire (never an invocation input): the
	// exact-AAD byte check refuses it before the journal is consulted.
	p = transport.NetworkEventPayload{CommandID: thirdDelivered.CommandID, InstanceID: f.profile.Scope.InstanceID, NetworkID: f.networkID, Kind: "invocation", Envelope: &thirdDelivered.Envelope, NativeDispatch: &thirdProof}
	wrongType := thirdDelivered.AAD
	wrongType.ObjectType = e2ee.ObjectTypeMessage
	p.AAD = &wrongType
	_ = ackError(t, f.deliver(p))

	// 4. Missing invocation source (a task-shaped proof): refused at the
	// shape check.
	proofBare := proof
	proofBare.InvocationSource = nil
	p = transport.NetworkEventPayload{CommandID: domain.NewID().String(), InstanceID: f.profile.Scope.InstanceID, NetworkID: f.networkID, Kind: "invocation", Envelope: &delivered.Envelope, AAD: &delivered.AAD, NativeDispatch: &proofBare}
	_ = ackError(t, f.deliver(p))

	// 5. A message reference on an invocation delivery (server contract
	// violation): refused at the shape check.
	p = transport.NetworkEventPayload{CommandID: domain.NewID().String(), InstanceID: f.profile.Scope.InstanceID, NetworkID: f.networkID, Kind: "invocation", MessageID: domain.NewID().String(), Envelope: &delivered.Envelope, AAD: &delivered.AAD, NativeDispatch: &proof}
	_ = ackError(t, f.deliver(p))

	// No turn ran for any of the refusals.
	if turns, _ := f.fakeTurns(); turns != 0 {
		t.Fatalf("a tampered delivery executed a turn: %d", turns)
	}
}

func TestDaemonHostedInvocationDeliveryRejectsMalformedPlaintext(t *testing.T) {
	f := newHostedGuardFixture(t)
	// The sealed original's plaintext is NOT the exact single-field prompt
	// binding (an extra local-native tag): journal-verified, grammar-rejected.
	invocation := domain.NewID().String()
	malformed := []byte(`{"input":"tagged","inputKind":"local-native"}`)
	delivered, proof := f.reserve(invocation, "tagged", malformed)
	p := transport.NetworkEventPayload{CommandID: delivered.CommandID, InstanceID: f.profile.Scope.InstanceID, NetworkID: f.networkID, Kind: "invocation", Envelope: &delivered.Envelope, AAD: &delivered.AAD, NativeDispatch: &proof}
	errMsg := ackError(t, f.deliver(p))
	if !strings.Contains(errMsg, "not the exact prompt binding") {
		t.Fatalf("malformed plaintext ack error = %q, want the prompt-binding refusal", errMsg)
	}
	if turns, _ := f.fakeTurns(); turns != 0 {
		t.Fatalf("a malformed plaintext executed a turn: %d", turns)
	}
}

func TestDaemonHostedInvocationDeliveryLeavesOrdinaryDeliveryUnchanged(t *testing.T) {
	f := newHostedGuardFixture(t)
	// An ordinary content-free notice on the same native instance still runs
	// the legacy path (kind mapping + compact input), untouched by the guard.
	commandID := domain.NewID().String()
	proof := transport.NativeDispatchProof{
		SourceBootID:        f.d.bootID,
		OwnershipID:         f.profile.OwnershipID,
		OwnershipGeneration: f.profile.Scope.Generation,
		DispatchSequence:    1,
		SourceCommandID:     commandID,
		SourceAdmissionID:   f.admission.NativeAdmissionID,
		SourceRunnerID:      f.admission.RunnerID,
		SourceRunnerEpoch:   f.admission.RunnerEpoch,
	}
	p := transport.NetworkEventPayload{CommandID: commandID, InstanceID: f.profile.Scope.InstanceID, NetworkID: f.networkID, Kind: "notice", NativeDispatch: &proof}
	if errMsg, _ := f.deliver(p)["error"].(string); errMsg != "" {
		t.Fatalf("ordinary notice delivery refused: %s", errMsg)
	}
	// The legacy path ran one real worker turn (content-free notice).
	f.waitForTurns(1, "")
}
