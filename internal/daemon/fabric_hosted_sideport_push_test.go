//go:build linux || darwin

package daemon

// Phase A step 6d — the daemon-side hosted Fabric sideport push (gap G2):
// the strict owner-administration push onto the live worker, rollback on
// push failure, attach-time restore, process-death clear, and the pump's
// per-tick reconciliation.
//
// Tests 7/9/10 run the FULL guarded fixture (real daemon, real worker
// binary, fake-persistent endpoint with the interactive bridge-control
// socket): the "the live worker's next bridge auth_ok carries the triple"
// assertion drives the control socket exactly the way the black-box e2e
// harness does (the auth op dials a fresh bridge connection, so it is a
// genuine second session seeing the advertisement). Tests 8/11 run a
// mini-fixture: a real daemon with a real registry record, real state row,
// real observation-connection admission and real NativeWorkerProxy — with
// the WORKER side of the controller protocol implemented in-process as a
// faithful server (genuine mutual HMAC handshake over a real unix socket)
// that counts the request types it observes (the fake-controller harness
// pattern from native_task_input_backend_test.go).

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/agentbridge"
	"github.com/pagnet-code/pagnet/internal/fabricagent"
	"github.com/pagnet-code/pagnet/internal/localpeer"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

// ---------------------------------------------------------------------------
// Fake worker: the in-process server of the worker's controller protocol.

// swHandshake mirrors the sessionworker controller handshake field order —
// the JSON byte order is significant to the HMAC proof.
type swHandshake struct {
	NativeGeneration string              `json:"nativeGeneration,omitempty"`
	Error            string              `json:"error,omitempty"`
	Mode             string              `json:"mode,omitempty"`
	Ownership        string              `json:"ownership,omitempty"`
	WorkerBuild      string              `json:"workerBuild,omitempty"`
	Protocol         string              `json:"protocol"`
	Scope            sessionworker.Scope `json:"scope"`
	ControllerID     string              `json:"controllerId,omitempty"`
	ServerNonce      string              `json:"serverNonce"`
	ClientNonce      string              `json:"clientNonce,omitempty"`
	Lease            int64               `json:"lease,omitempty"`
	Proof            string              `json:"proof,omitempty"`
}

func swProof(key []byte, role string, h swHandshake) string {
	h.Proof = ""
	b, _ := json.Marshal(struct {
		Domain    string      `json:"domain"`
		Role      string      `json:"role"`
		Handshake swHandshake `json:"handshake"`
	}{"pagnet.session-worker.authentication.v1", role, h})
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(b)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func swWriteFrame(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil || len(b) == 0 || len(b) > 1<<20 {
		return errors.New("fake worker frame exceeds bound")
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(b)))
	if _, err := io.Copy(w, bytes.NewReader(header[:])); err != nil {
		return err
	}
	_, err = io.Copy(w, bytes.NewReader(b))
	return err
}

func swReadFrame(r io.Reader, v any) error {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(header[:])
	if n == 0 || n > 1<<20 {
		return errors.New("fake worker frame exceeds bound")
	}
	b := make([]byte, int(n))
	if _, err := io.ReadFull(r, b); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return errors.New("fake worker frame has trailing data")
	}
	return nil
}

func swFreshNonce() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func swValidNonce(s string) bool {
	b, err := base64.RawURLEncoding.DecodeString(s)
	return err == nil && len(b) == 32
}

// sideportFakeWorker is a fake WORKER (not a fake daemon): it serves the
// genuine controller protocol — same-uid kernel peer check, mutual HMAC
// handshake, length-framed JSON — on a real unix socket, and counts the
// request types it observes so a test can assert the exact wire traffic.
type sideportFakeWorker struct {
	t       *testing.T
	key     []byte
	scope   sessionworker.Scope
	accepts bool // true: accept hosted_sideport_set; false: refuse it

	mu         sync.Mutex
	types      []string
	setCount   int
	clearCount int
}

func (fw *sideportFakeWorker) record(typ string) {
	fw.mu.Lock()
	defer fw.mu.Unlock()
	fw.types = append(fw.types, typ)
	switch typ {
	case "hosted_sideport_set":
		fw.setCount++
	case "hosted_sideport_clear":
		fw.clearCount++
	}
}

func (fw *sideportFakeWorker) counts() (sets, clears int, types []string) {
	fw.mu.Lock()
	defer fw.mu.Unlock()
	return fw.setCount, fw.clearCount, append([]string(nil), fw.types...)
}

func (fw *sideportFakeWorker) serve(t *testing.T, dir string) {
	t.Helper()
	sock, err := sessionworker.SocketPath(dir)
	if err != nil {
		t.Fatalf("fake worker socket path: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(sock), 0o700); err != nil {
		t.Fatalf("fake worker socket dir: %v", err)
	}
	// The path is per-fixture (hashed scope); a leftover file from an
	// earlier run of the SAME test is a stale socket, remove it.
	if fi, err := os.Lstat(sock); err == nil && fi.Mode()&os.ModeSocket != 0 {
		_ = os.Remove(sock)
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatalf("fake worker listen %s: %v", sock, err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			c, err := listener.AcceptUnix()
			if err != nil {
				return
			}
			go fw.handle(c)
		}
	}()
}

func (fw *sideportFakeWorker) handle(c net.Conn) {
	defer c.Close()
	if _, _, err := localpeer.Owner(c); err != nil {
		return
	}
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	serverNonce, err := swFreshNonce()
	if err != nil {
		return
	}
	hello := swHandshake{Protocol: sessionworker.Protocol, Scope: fw.scope, ServerNonce: serverNonce, Ownership: sessionworker.NativeOwnershipProtocol, WorkerBuild: "sideport-fake-worker"}
	if swWriteFrame(c, hello) != nil {
		return
	}
	var auth swHandshake
	if swReadFrame(c, &auth) != nil || auth.Protocol != sessionworker.Protocol || auth.Ownership != hello.Ownership || auth.WorkerBuild != hello.WorkerBuild || auth.Scope != fw.scope || auth.ServerNonce != serverNonce || auth.Mode != "" || auth.Lease != 0 || auth.NativeGeneration != "" || auth.Error != "" || !swValidNonce(auth.ClientNonce) || auth.ControllerID == "" || len(auth.ControllerID) > 256 || !hmac.Equal([]byte(auth.Proof), []byte(swProof(fw.key, "controller", auth))) {
		return
	}
	auth.Lease = 1
	auth.Proof = swProof(fw.key, "worker", auth)
	if swWriteFrame(c, auth) != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})
	for {
		var req sessionworker.Request
		if swReadFrame(c, &req) != nil {
			return
		}
		resp := sessionworker.Response{}
		fw.record(req.Type)
		switch req.Type {
		case "ownership_bind":
			// The Associate probe's inspection of the existing dispatch
			// lane: it exists.
		case "hosted_sideport_set":
			if !fw.accepts {
				resp.Error = "fake worker refused the sideport set"
			} else if req.HostedSideport == nil {
				resp.Error = "sideport set without a payload"
			}
		case "hosted_sideport_clear":
			// Idempotent no-op, like the real worker.
		default:
			resp.Error = "unsupported fake worker request"
		}
		if swWriteFrame(c, resp) != nil {
			return
		}
	}
}

// ---------------------------------------------------------------------------
// Mini-fixture: real daemon + real registry/state/observation lane, fake
// worker on the controller socket.

// sideportMiniFixture wires one reserved-then-launched native worker record
// into a real daemon with the fake worker as its controller peer. No pump
// is started: tests drive the extracted reconcile step and push helper
// directly, which is what pins the wire behavior.
type sideportMiniFixture struct {
	t          *testing.T
	d          *Daemon
	fw         *sideportFakeWorker
	proxy      *NativeWorkerProxy
	link       *nativeWorkerLink
	scope      sessionworker.Scope
	ownership  transport.NativeWorkerOwnership
	profile    fabricagent.HostedProfile
	resolveRef fabric.EndpointRef
	client     *websocket.Conn
}

func newSideportMiniFixture(t *testing.T, accepts bool) *sideportMiniFixture {
	t.Helper()
	d := newTestDaemon(t)
	d.ServerURL = "https://app.pagnet.dev"
	d.HostID = domain.NewID().String()
	tenantID := domain.NewID().String()
	scope := sessionworker.Scope{ServerURL: d.ServerURL, TenantID: tenantID, AccountID: tenantID, HostID: d.HostID, InstanceID: domain.NewID().String(), Generation: domain.NewID().String()}
	networkID := domain.NewID().String()
	spec := sessionworker.NativeSpec{
		Runtime:         domain.RuntimeFakePersistent,
		Binary:          p0FakeBinary(t),
		MCPExecutable:   p0FakeBinary(t),
		Workspace:       t.TempDir(),
		Kind:            "worker",
		NetworkID:       networkID,
		TenantID:        scope.TenantID,
		NetworkTenantID: scope.TenantID,
	}
	record, err := d.nativeRegistry.Reserve(scope, spec, "", "")
	if err != nil {
		t.Fatalf("reserve native worker: %v", err)
	}
	if err := os.Mkdir(record.Dir, 0o700); err != nil {
		t.Fatalf("worker dir: %v", err)
	}
	// The fake worker below owns the controller socket: mark the record
	// launched without starting a real process (EnsureNativeWorker is the
	// no-op idempotency path when the state is already "launched").
	if _, err := d.nativeRegistry.db.Exec(`UPDATE native_workers SET launch_state='launched' WHERE instance_id=?`, scope.InstanceID); err != nil {
		t.Fatalf("mark launched: %v", err)
	}
	ownership := transport.NativeWorkerOwnership{
		ID:                  domain.NewID().String(),
		OriginalAdmissionID: domain.NewID().String(),
		InstanceID:          scope.InstanceID,
		OwnershipGeneration: scope.Generation,
		Runtime:             string(domain.RuntimeFakePersistent),
		ProfileFingerprint:  record.ProfileFingerprint,
		State:               "active",
	}
	if err := d.nativeRegistry.BindOwnership(record, ownership); err != nil {
		t.Fatalf("bind ownership: %v", err)
	}
	record.LaunchState = "launched"
	record.Ownership = &ownership

	var nativeProfile [32]byte
	decoded, err := hex.DecodeString(record.ProfileFingerprint)
	if err != nil || len(decoded) != 32 {
		t.Fatalf("decode profile fingerprint: %v", err)
	}
	copy(nativeProfile[:], decoded)
	profile := fabricagent.HostedProfile{
		DefinitionID:    domain.NewID().String(),
		PrincipalID:     domain.NewID().String(),
		NetworkID:       networkID,
		Scope:           scope,
		OwnershipID:     ownership.ID,
		NativeProfile:   nativeProfile,
		WorkerDirectory: record.Dir,
	}
	if err := profile.Validate(); err != nil {
		t.Fatalf("mini profile invalid: %v", err)
	}
	if err := d.state.UpsertInstance(InstanceRow{InstanceID: scope.InstanceID, DefinitionID: profile.DefinitionID, AgentPrincipalID: profile.PrincipalID, NetworkID: networkID}); err != nil {
		t.Fatalf("upsert instance row: %v", err)
	}
	ownerConn := NewNativeObservationConnection(d.ServerURL, d.HostID, d.bootID, func(context.Context, string, any) error { return nil })
	admission := transport.HostSessionPayload{TenantID: scope.TenantID, AccountID: scope.AccountID, OwnershipScope: "personal", HostID: d.HostID, BootID: d.bootID, NativeAdmissionID: domain.NewID().String(), RunnerID: domain.NewID().String(), RunnerEpoch: time.Now().UTC(), ProtocolFeatures: []string{transport.NativeObservationReceiptProtocol}}
	if err := ownerConn.Admit(admission); err != nil {
		t.Fatalf("admit host session: %v", err)
	}
	client, _ := newMemWS(t)

	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	fw := &sideportFakeWorker{t: t, key: key[:], scope: scope, accepts: accepts}
	fw.serve(t, record.Dir)

	var (
		ctrl    *sessionworker.Controller
		dialErr error
	)
	deadline := time.Now().Add(10 * time.Second)
	for {
		ctrl, dialErr = sessionworker.DialOwnerController(context.Background(), record.Dir, scope, key[:], "sideport-mini-controller")
		if dialErr == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("dial fake worker controller: %v", dialErr)
		}
		time.Sleep(10 * time.Millisecond)
	}
	proxy := &NativeWorkerProxy{connection: ownerConn, controller: ctrl, scope: scope, profile: record.ProfileFingerprint, bootstrap: sessionworker.Bootstrap{Protocol: sessionworker.Protocol, Scope: scope, Native: spec}, done: make(chan struct{})}
	link := &nativeWorkerLink{proxy: proxy, conn: client, ownership: ownership}
	d.nativeWorkersMu.Lock()
	if d.nativeWorkers == nil {
		d.nativeWorkers = map[string]*nativeWorkerLink{}
	}
	d.nativeWorkers[scope.InstanceID] = link
	d.nativeWorkersMu.Unlock()
	t.Cleanup(func() { _ = proxy.Close() })

	ref, err := fabric.NewEndpointRef(make([]byte, 32))
	if err != nil {
		t.Fatalf("endpoint ref: %v", err)
	}
	// The resolve port models the node's selected-binding wiring for this
	// mini instance: the exact profile, the endpoint the test selects.
	d.HostedFabricSideports = NewHostedFabricSideports(func(_ context.Context, instanceID string) (registry.DescriptorBatchScope, fabricagent.HostedProfile, error) {
		if instanceID != scope.InstanceID {
			return registry.DescriptorBatchScope{}, fabricagent.HostedProfile{}, errors.New("instance not bound to the selected binding")
		}
		return registry.DescriptorBatchScope{Endpoint: ref, BindingID: "original"}, profile, nil
	})
	return &sideportMiniFixture{t: t, d: d, fw: fw, proxy: proxy, link: link, scope: scope, ownership: ownership, profile: profile, resolveRef: ref, client: client}
}

func (f *sideportMiniFixture) validSideport(t *testing.T) agentbridge.HostedFabricSideport {
	t.Helper()
	return agentbridge.HostedFabricSideport{
		Socket:     filepath.Join(t.TempDir(), "node.sock"),
		Endpoint:   f.resolveRef,
		Generation: f.scope.Generation,
	}
}

// ---------------------------------------------------------------------------
// Guarded-fixture helpers: one turn (so the fake endpoint dials the worker's
// bridge and binds the control socket) + the control-socket auth assertion.

func sideportBridgeControl(t *testing.T, f *hostedGuardFixture, resultFile string) (*controlFixtureClient, string) {
	t.Helper()
	instanceID := f.profile.Scope.InstanceID
	prompt := "sideport fixture turn"
	delivered, proof := f.reserve(domain.NewID().String(), prompt, nil)
	p := transport.NetworkEventPayload{CommandID: delivered.CommandID, InstanceID: instanceID, NetworkID: f.networkID, Kind: "invocation", Envelope: &delivered.Envelope, AAD: &delivered.AAD, NativeDispatch: &proof}
	if errMsg, _ := f.deliver(p)["error"].(string); errMsg != "" {
		t.Fatalf("invocation delivery refused: %s", errMsg)
	}
	f.waitForTurns(1, prompt)
	sock := filepath.Join(filepath.Dir(resultFile), "bc-"+strings.ReplaceAll(instanceID, "-", "")+".sock")
	return dialControlSocket(t, sock), instanceID
}

// assertAuthOKSideport drives a fresh bridge session through the control
// socket and pins the auth_ok shape: absent sideport → EXACTLY the two
// pre-6d keys; present → the sideport key parses to the exact triple in
// the exact {socket, endpoint, generation} shape.
func assertAuthOKSideport(t *testing.T, cc *controlFixtureClient, instanceID, networkID string, want *agentbridge.HostedFabricSideport) {
	t.Helper()
	reply := cc.op(t, map[string]any{"op": "auth", "instanceId": instanceID, "networkId": networkID})
	resp, ok := reply["response"].(map[string]any)
	if !ok {
		t.Fatalf("auth op reply = %v, want response", reply)
	}
	if resp["type"] != "auth_ok" {
		t.Fatalf("auth op = %v, want auth_ok", resp)
	}
	if id, _ := resp["instanceId"].(string); id != instanceID {
		t.Fatalf("auth_ok instanceId = %q, want %q", id, instanceID)
	}
	if want == nil {
		if _, has := resp["sideport"]; has {
			t.Fatalf("auth_ok carries a sideport: %v", resp)
		}
		if len(resp) != 2 {
			t.Fatalf("auth_ok keys = %v, want exactly {type, instanceId}", resp)
		}
		return
	}
	raw, err := json.Marshal(resp["sideport"])
	if err != nil {
		t.Fatalf("sideport key not marshalable: %v", err)
	}
	var got agentbridge.HostedFabricSideport
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("sideport key does not parse as the triple: %v", err)
	}
	if got != *want {
		t.Fatalf("sideport = %+v, want the exact stored triple %+v", got, *want)
	}
	if len(resp) != 3 {
		t.Fatalf("auth_ok keys = %v, want {type, instanceId, sideport}", resp)
	}
}

// Test 7 (G2 end-to-end at the daemon level): the REAL Associate op —
// resolve port, profile validation, genuine worker re-probe — pushes the
// association onto the live worker, whose next bridge auth_ok carries the
// exact triple. The existing step-3 test only seeds the registry and proves
// the managed bridge path + node refusal; this is the advertisement
// crossing the daemon→worker boundary.
func TestHostedSideportAssociatePushesToLiveWorker(t *testing.T) {
	resultFile := filepath.Join(t.TempDir(), "sideport-g2-result.json")
	f := newHostedGuardFixture(t, withWorkerEnv("PAGNET_FAKE_BRIDGE_CONTROL=1", "PAGNET_FAKE_BRIDGE_RESULT_FILE="+resultFile))
	d := f.d
	d.HostedFabricSideports = NewHostedFabricSideports(f.hostedNativeResolvePort)
	cc, instanceID := sideportBridgeControl(t, f, resultFile)

	// Baseline: no association yet — the pre-6d two-key handshake.
	assertAuthOKSideport(t, cc, instanceID, f.networkID, nil)

	sp := agentbridge.HostedFabricSideport{
		Socket:     filepath.Join(t.TempDir(), "node.sock"),
		Endpoint:   f.ref,
		Generation: f.profile.Scope.Generation,
	}
	if err := d.AssociateHostedFabricSideport(t.Context(), instanceID, sp); err != nil {
		t.Fatalf("genuine owner administration refused: %v", err)
	}
	if got, ok := d.HostedFabricSideports.For(instanceID); !ok || got != sp {
		t.Fatalf("association = %+v ok=%v, want the exact stored triple", got, ok)
	}
	// The G2 assertion: the live worker's NEXT bridge session carries the
	// exact triple — the advertisement reached the worker's own bridge.
	assertAuthOKSideport(t, cc, instanceID, f.networkID, &sp)
}

// Test 8: the strict associate contract under push failure and missing
// peers. (i) A worker that REFUSES the set (the fake-worker seam) → the op
// returns the worker's error AND the just-stored association is rolled
// back; the wire trace proves the genuine probe (ownership_bind) and the
// real push (hosted_sideport_set) both happened. (ii) No live link →
// conflict before anything is stored. (iii) The push helper: no link →
// conflict; a dead proxy → deferred.
func TestHostedSideportStrictAssociateRollsBackOnPushFailure(t *testing.T) {
	ctx := t.Context()
	f := newSideportMiniFixture(t, false)
	sp := f.validSideport(t)
	if err := f.d.AssociateHostedFabricSideport(ctx, f.scope.InstanceID, sp); err == nil {
		t.Fatal("associate succeeded against a worker that refused the push")
	}
	if _, ok := f.d.HostedFabricSideports.For(f.scope.InstanceID); ok {
		t.Fatal("push failure did not roll back the stored association")
	}
	sets, clears, types := f.fw.counts()
	if sets != 1 || clears != 0 {
		t.Fatalf("wire traffic = sets %d clears %d, want exactly one set and no clear", sets, clears)
	}
	want := []string{"ownership_bind", "hosted_sideport_set"}
	if !reflect.DeepEqual(types, want) {
		t.Fatalf("request types = %v, want %v (the genuine probe, then the real push)", types, want)
	}

	// No live link: the contract refuses before resolve/probe/store.
	stub := &Daemon{Config: Config{HostedFabricSideports: NewHostedFabricSideports(func(context.Context, string) (registry.DescriptorBatchScope, fabricagent.HostedProfile, error) {
		return registry.DescriptorBatchScope{}, fabricagent.HostedProfile{}, errors.New("resolve must not be reached without a live link")
	})}}
	if err := stub.AssociateHostedFabricSideport(ctx, f.scope.InstanceID, f.validSideport(t)); !errors.Is(err, ErrNativeObservationConflict) {
		t.Fatalf("no-link associate err = %v, want conflict", err)
	}
	if _, ok := stub.HostedFabricSideports.For(f.scope.InstanceID); ok {
		t.Fatal("no-link associate stored an association")
	}

	// Push helper: unknown instance → conflict; closed proxy → deferred.
	if err := f.d.pushHostedSideportToWorker(ctx, domain.NewID().String(), &sp); !errors.Is(err, ErrNativeObservationConflict) {
		t.Fatalf("no-link push err = %v, want conflict", err)
	}
	closed := newSideportMiniFixture(t, true)
	_ = closed.proxy.Close()
	if err := closed.d.pushHostedSideportToWorker(ctx, closed.scope.InstanceID, &sp); !errors.Is(err, ErrNativeOriginAdmissionDeferred) {
		t.Fatalf("closed-proxy push err = %v, want deferred", err)
	}
}

// Test 9: attach-time restore. The daemon's association registry survives
// a worker restart; the worker's in-memory advertisement does not. A fresh
// attach must push any pre-existing association to the newly attached
// worker. The daemon-side half of the worker restart (link replacement +
// the documented connectNativeWorker path) is driven directly against the
// live worker: the same code path a genuine re-attach takes.
// (Named short: t.TempDir() derives from the test name, and the control
// socket in the result file's dir must stay under the AF_UNIX path limit.)
func TestHostedSideportAttachRestore(t *testing.T) {
	resultFile := filepath.Join(t.TempDir(), "sideport-attach-result.json")
	f := newHostedGuardFixture(t, withWorkerEnv("PAGNET_FAKE_BRIDGE_CONTROL=1", "PAGNET_FAKE_BRIDGE_RESULT_FILE="+resultFile))
	d := f.d
	d.HostedFabricSideports = NewHostedFabricSideports(f.hostedNativeResolvePort)
	cc, instanceID := sideportBridgeControl(t, f, resultFile)

	// The worker attached at fixture construction, before any association
	// existed: no advertisement.
	assertAuthOKSideport(t, cc, instanceID, f.networkID, nil)

	sp := agentbridge.HostedFabricSideport{
		Socket:     filepath.Join(t.TempDir(), "node.sock"),
		Endpoint:   f.ref,
		Generation: f.profile.Scope.Generation,
	}
	// A pre-existing association in the daemon registry whose advertisement
	// the (restarted) worker no longer holds.
	d.HostedFabricSideports.Store(instanceID, sp)

	d.nativeWorkersMu.Lock()
	old := d.nativeWorkers[instanceID]
	delete(d.nativeWorkers, instanceID)
	d.nativeWorkersMu.Unlock()
	if old == nil {
		t.Fatal("no live link to replace")
	}
	_ = old.proxy.Close()
	if err := d.connectNativeWorker(f.conn, f.ownerConn, f.record); err != nil {
		t.Fatalf("re-attach: %v", err)
	}
	// The attach-time restore pushed the pre-existing association onto the
	// freshly attached worker: its next bridge session carries the triple.
	assertAuthOKSideport(t, cc, instanceID, f.networkID, &sp)
}

// Test 10: invalidation at the process-death seam. invalidateHostedSideport
// is the exact helper every boundary call site (stop, forget, restart,
// native removal) funnels through: it drops the registry association AND
// pushes the clear to the live worker. With the worker alive the clear
// lands and the next bridge session advertises nothing. (Driving a full
// stop/forget boundary here would require the out-of-scope teardown flows;
// the helper IS the shared boundary behavior.)
func TestHostedSideportInvalidateClearsLiveWorker(t *testing.T) {
	resultFile := filepath.Join(t.TempDir(), "sideport-invalidate-result.json")
	f := newHostedGuardFixture(t, withWorkerEnv("PAGNET_FAKE_BRIDGE_CONTROL=1", "PAGNET_FAKE_BRIDGE_RESULT_FILE="+resultFile))
	d := f.d
	d.HostedFabricSideports = NewHostedFabricSideports(f.hostedNativeResolvePort)
	cc, instanceID := sideportBridgeControl(t, f, resultFile)

	assertAuthOKSideport(t, cc, instanceID, f.networkID, nil)
	sp := agentbridge.HostedFabricSideport{
		Socket:     filepath.Join(t.TempDir(), "node.sock"),
		Endpoint:   f.ref,
		Generation: f.profile.Scope.Generation,
	}
	if err := d.AssociateHostedFabricSideport(t.Context(), instanceID, sp); err != nil {
		t.Fatalf("genuine owner administration refused: %v", err)
	}
	assertAuthOKSideport(t, cc, instanceID, f.networkID, &sp)

	d.invalidateHostedSideport(instanceID)
	if _, ok := d.HostedFabricSideports.For(instanceID); ok {
		t.Fatal("invalidation did not drop the association")
	}
	// The worker is alive: the clear push landed, new sessions see nothing.
	assertAuthOKSideport(t, cc, instanceID, f.networkID, nil)
}

// Test 11: the pump's reconciliation unit. The link's tracked last-pushed
// state is forced wrong and the extracted reconcile step is invoked
// directly: exactly one corrective frame is sent and the tracked state
// converges; a second pass sends NO frame. Invalidation while tracked
// present sends exactly one clear. A daemon without the composition never
// pushes (fail-closed) and leaves the tracked state untouched.
func TestHostedSideportPumpReconciliationConverges(t *testing.T) {
	ctx := t.Context()
	f := newSideportMiniFixture(t, true)
	sp := f.validSideport(t)
	f.d.HostedFabricSideports.Store(f.scope.InstanceID, sp)

	// Drift: the registry has the association, the link tracked nothing.
	f.link.mu.Lock()
	f.link.sideportPushed = agentbridge.HostedFabricSideport{Socket: "stale", Generation: "stale"}
	f.link.sideportPushedPresent = false
	f.link.mu.Unlock()
	f.d.reconcileHostedSideport(ctx, f.link)
	sets, clears, _ := f.fw.counts()
	if sets != 1 || clears != 0 {
		t.Fatalf("first reconciliation = sets %d clears %d, want exactly one set", sets, clears)
	}
	f.link.mu.Lock()
	tracked, present := f.link.sideportPushed, f.link.sideportPushedPresent
	f.link.mu.Unlock()
	if !present || tracked != sp {
		t.Fatalf("tracked state = %+v present=%v, want converged to the stored triple", tracked, present)
	}

	// Converged: a second pass sends no frame.
	f.d.reconcileHostedSideport(ctx, f.link)
	sets, clears, _ = f.fw.counts()
	if sets != 1 || clears != 0 {
		t.Fatalf("converged reconciliation re-pushed (sets %d clears %d)", sets, clears)
	}

	// Replace drift: the registry now holds a different triple while the
	// link tracks the old one → one set (never a clear + set pair).
	sp2 := f.validSideport(t)
	sp2.Generation = "second-generation"
	f.d.HostedFabricSideports.Store(f.scope.InstanceID, sp2)
	f.d.reconcileHostedSideport(ctx, f.link)
	sets, clears, _ = f.fw.counts()
	if sets != 2 || clears != 0 {
		t.Fatalf("replace reconciliation = sets %d clears %d, want one more set", sets, clears)
	}
	f.link.mu.Lock()
	tracked, present = f.link.sideportPushed, f.link.sideportPushedPresent
	f.link.mu.Unlock()
	if !present || tracked != sp2 {
		t.Fatalf("tracked state = %+v present=%v, want the replaced triple", tracked, present)
	}

	// Invalidation while tracked present: exactly one clear.
	f.d.HostedFabricSideports.Invalidate(f.scope.InstanceID)
	f.d.reconcileHostedSideport(ctx, f.link)
	sets, clears, _ = f.fw.counts()
	if sets != 2 || clears != 1 {
		t.Fatalf("invalidation reconciliation = sets %d clears %d, want one clear", sets, clears)
	}
	f.link.mu.Lock()
	present = f.link.sideportPushedPresent
	f.link.mu.Unlock()
	if present {
		t.Fatal("tracked state still present after the clear")
	}

	// No composition: no push ever happens, tracked state untouched.
	f.d.HostedFabricSideports = nil
	f.link.mu.Lock()
	f.link.sideportPushed = sp2
	f.link.sideportPushedPresent = true
	f.link.mu.Unlock()
	f.d.reconcileHostedSideport(ctx, f.link)
	sets, clears, _ = f.fw.counts()
	if sets != 2 || clears != 1 {
		t.Fatal("a daemon without the sideport composition pushed a frame")
	}
	f.link.mu.Lock()
	tracked, present = f.link.sideportPushed, f.link.sideportPushedPresent
	f.link.mu.Unlock()
	if tracked != sp2 || !present {
		t.Fatal("composition-less reconciliation mutated the tracked state")
	}
}
