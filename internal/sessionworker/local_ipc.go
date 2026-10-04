package sessionworker

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/internal/localpeer"
	"github.com/pagnet-code/pagnet/internal/nativeauthority"
)

type localHandshake struct {
	Mode         string         `json:"mode,omitempty"`
	Protocol     string         `json:"protocol"`
	Authority    AuthorityScope `json:"authority"`
	WorkerBuild  string         `json:"workerBuild"`
	ControllerID string         `json:"controllerId,omitempty"`
	ServerNonce  string         `json:"serverNonce"`
	ClientNonce  string         `json:"clientNonce,omitempty"`
	Lease        int64          `json:"lease,omitempty"`
	Proof        string         `json:"proof,omitempty"`
}

func localAuthenticationProof(key []byte, role string, h localHandshake) string {
	h.Proof = ""
	raw, _ := json.Marshal(struct {
		Domain, Role string
		Handshake    localHandshake
	}{"pagnet.session-worker.local-authentication.v1", role, h})
	mac := hmac.New(sha256.New, key)
	mac.Write(raw)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// ServeLocalOwner exposes only the explicit genuine local ownership profile.
// Native execution is detached from controller connection lifetime and begins
// after the FULL admission transaction returns, never inside the registry fence.
func ServeLocalOwner(ctx context.Context, owner *SessionOwner, key []byte, build string, binder nativeauthority.OperationBinder) error {
	if ctx == nil || owner == nil || !owner.journal.isLocal() || len(key) != 32 || binder == nil || owner.localActivation == nil {
		return ErrFenced
	}
	key = append([]byte(nil), key...)
	defer clear(key)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	path, e := SocketPath(owner.journal.dir)
	if e != nil {
		return e
	}
	if e = removeStaleSocket(path); e != nil {
		return e
	}
	listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if e != nil {
		return e
	}
	defer listener.Close()
	if e = privateSocket(path); e != nil {
		return e
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
		case <-owner.retirement:
			cancel()
		case <-done:
			return
		}
		listener.Close()
	}()
	var wg sync.WaitGroup
	controllers := &currentController{}
	slots := make(chan struct{}, 36)
	defer func() { cancel(); wg.Wait() }()
	for {
		conn, e := listener.AcceptUnix()
		if e != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return e
		}
		select {
		case slots <- struct{}{}:
		default:
			conn.Close()
			continue
		}
		wg.Go(func() {
			defer func() { <-slots }()
			defer conn.Close()
			serveLocalController(ctx, conn, owner, key, build, binder, controllers)
		})
	}
}
func serveLocalController(ctx context.Context, c *net.UnixConn, owner *SessionOwner, key []byte, build string, binder nativeauthority.OperationBinder, controllers *currentController) {
	if _, _, e := localpeer.Owner(c); e != nil {
		return
	}
	c.SetDeadline(time.Now().Add(handshakeTimeout))
	nonce, e := freshNonce()
	if e != nil {
		return
	}
	hello := localHandshake{Protocol: LocalProtocol, Authority: owner.journal.authority, WorkerBuild: build, ServerNonce: nonce}
	if writeFrame(c, hello) != nil {
		return
	}
	var auth localHandshake
	if readFrame(c, &auth) != nil {
		return
	}
	if auth.Mode == "readiness" {
		serveLocalReadiness(ctx, c, owner, key, build, hello, auth, controllers)
		return
	}
	if auth.Mode != "" || auth.Protocol != hello.Protocol || auth.Authority != hello.Authority || auth.WorkerBuild != build || auth.ServerNonce != nonce || !validNonce(auth.ClientNonce) || auth.ControllerID == "" || len(auth.ControllerID) > 256 || auth.Lease != 0 || !equalProof(auth.Proof, localAuthenticationProof(key, "controller", auth)) {
		return
	}
	auth.Lease, e = controllers.advanceAndInstall(ctx, owner.journal, auth.ControllerID, c)
	if e != nil {
		return
	}
	defer controllers.release(auth.Lease, c)
	defer owner.localActivation.disconnect(auth.Lease)
	auth.Proof = localAuthenticationProof(key, "worker", auth)
	if writeFrame(c, auth) != nil {
		return
	}
	c.SetDeadline(time.Time{})
	watcherDone := make(chan struct{})
	defer close(watcherDone)
	go func() {
		select {
		case <-ctx.Done():
			c.Close()
		case <-watcherDone:
		}
	}()
	for {
		var req LocalRequest
		if readFrame(c, &req) != nil {
			return
		}
		response := LocalResponse{}
		if e = owner.journal.CurrentLease(ctx, auth.Lease); e != nil {
			return
		}
		var execute *nativeauthority.VerifiedIntent
		switch req.Type {
		case "control":
			if req.Control == nil {
				e = ErrConflict
				break
			}
			e = owner.journal.CommitLocalControl(ctx, auth.Lease, *req.Control)
			if e == nil {
				e = owner.localActivation.bindControl(auth.Lease, *req.Control)
			}
		case "intent":
			if req.Intent == nil {
				e = ErrConflict
				break
			}
			var intent nativeauthority.VerifiedIntent
			intent, e = req.Intent.Verify(owner.journal.authority, binder)
			if e != nil {
				break
			}
			var out Outcome
			var fresh bool
			out, receipt, isFresh, err := owner.journal.AdmitLocal(ctx, auth.Lease, binder, intent)
			e = err
			fresh = isFresh
			if e == nil {
				e = owner.localActivation.bindCurrent(auth.Lease, intent)
			}
			if e == nil {
				response.Outcome = &out
				response.Receipt = &receipt
				if fresh {
					execute = &intent
				}
			}
		case "cancel":
			if req.Intent == nil {
				e = ErrConflict
				break
			}
			var intent nativeauthority.VerifiedIntent
			intent, e = req.Intent.VerifyCancellation(owner.journal.authority, binder)
			if e != nil {
				break
			}
			controllers.mu.Lock()
			if controllers.lease != auth.Lease || controllers.conn != c {
				e = ErrFenced
			} else {
				e = owner.CancelLocalInvocation(ctx, auth.Lease, binder, intent)
			}
			controllers.mu.Unlock()
		case "stream_page", "stream_ack":
			if req.Control == nil {
				e = ErrFenced
				break
			}
			// Trusted composition must hold the actual root/source read fence through
			// each call; this proof plus private MAC is never external policy itself.
			e = owner.journal.CommitLocalControl(ctx, auth.Lease, *req.Control)
			if e != nil {
				break
			}
			if req.Type == "stream_page" {
				var page LocalInvocationPage
				page, e = owner.journal.LocalStreamPage(ctx, owner.captureKey, auth.Lease, req.Sequence, req.Cursor, req.Limit)
				response.Readiness = &page.Readiness
				if e == nil {
					response.Stream = &page
				}
			} else {
				e = owner.journal.AckLocalStream(ctx, owner.captureKey, auth.Lease, req.Sequence, req.Cursor, req.Digest)
			}
		case "observations", "source_capture":
			if req.Control == nil {
				e = ErrFenced
				break
			}
			e = owner.journal.CommitLocalControl(ctx, auth.Lease, *req.Control)
			if e != nil {
				break
			}
			if req.Type == "observations" {
				response.Observations, e = owner.journal.PendingObservationsForLease(ctx, auth.Lease, req.Limit)
			} else {
				response.Capture, e = owner.journal.ReadCaptureChunk(ctx, auth.Lease, req.ObservationID, req.SourceDigest, req.CaptureOffset)
			}
		case "snapshot":
			var s LocalNativeSnapshot
			s, e = owner.LocalSnapshot()
			if e == nil {
				response.Snapshot = &s
			}
		case "activation_poll":
			response.Activation, e = owner.localActivation.poll(auth.Lease)
		case "activation_origin":
			if req.ActivationOrigin == nil {
				e = ErrConflict
			} else {
				e = owner.localActivation.complete(auth.Lease, *req.ActivationOrigin)
			}
		case "outcome":
			var out Outcome
			out, e = owner.journal.Outcome(ctx, req.Sequence)
			if e == nil {
				response.Outcome = &out
			}
		case "ack":
			e = owner.journal.Acknowledge(ctx, auth.Lease, req.Sequence)
		default:
			e = ErrConflict
		}
		if e != nil {
			response.Error = "Local worker request was rejected"
			switch {
			case errors.Is(e, ErrLocalInvocationNotReady):
				response.Code = "not_ready"
			case errors.Is(e, ErrFenced):
				response.Code = "fenced"
			case errors.Is(e, ErrRetired):
				response.Code = "retired"
			case errors.Is(e, ErrConflict):
				response.Code = "conflict"
			case errors.Is(e, ErrFull):
				response.Code = "capacity"
			case errors.Is(e, ErrNativeBusy):
				response.Code = "busy"
			case errors.Is(e, sql.ErrNoRows):
				response.Code = "not_found"
			default:
				response.Code = "unavailable"
			}
		}
		// Known accepted work belongs to worker even if writing ACK loses its socket.
		// Its real activation still waits for genuine registry origin registration.
		if execute != nil {
			owner.Execute(*response.Outcome, execute.Operation.Payload)
		}
		if writeFrame(c, response) != nil {
			return
		}
	}
}

// LocalClient is mutually authenticated to the pinned original physical worker,
// not a fabricated cloud account. Private MAC possession is not current registry
// authorization: AdmitIntent must run under LocalController's actual fence.
type LocalClient struct {
	controllerID string
	directory    string
	mu           sync.Mutex
	conn         net.Conn
	Lease        int64
	WorkerBuild  string
	authority    AuthorityScope
	ownerProcess localpeer.ProcessSnapshot
}

func DialLocal(ctx context.Context, dir string, scope AuthorityScope, key []byte, id string) (*LocalClient, error) {
	if ctx == nil || scope.Kind() != nativeauthority.Local || scope.Validate() != nil || len(key) != 32 || id == "" || len(id) > 256 {
		return nil, ErrFenced
	}
	path, e := SocketPath(dir)
	if e != nil {
		return nil, e
	}
	c, e := (&net.Dialer{}).DialContext(ctx, "unix", path)
	if e != nil {
		return nil, e
	}
	fail := func(e error) (*LocalClient, error) { c.Close(); return nil, e }
	stopHandshake := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stopHandshake()
	if _, _, e = localpeer.Owner(c); e != nil {
		return fail(e)
	}
	pid, uid, e := localpeer.Owner(c)
	if e != nil {
		return fail(e)
	}
	ownerProcess, e := localpeer.ReadProcess(pid)
	if e != nil || ownerProcess.UID != uid || ownerProcess.Start <= 0 {
		return fail(ErrFenced)
	}
	deadline := time.Now().Add(handshakeTimeout)
	if requested, ok := ctx.Deadline(); ok && requested.Before(deadline) {
		deadline = requested
	}
	c.SetDeadline(deadline)
	var h localHandshake
	if e = readFrame(c, &h); e != nil {
		return fail(e)
	}
	if h.Protocol != LocalProtocol || h.Authority != scope || !validNonce(h.ServerNonce) || h.ControllerID != "" || h.ClientNonce != "" || h.Lease != 0 || h.Proof != "" {
		return fail(ErrFenced)
	}
	h.ControllerID = id
	h.ClientNonce, e = freshNonce()
	if e != nil {
		return fail(e)
	}
	h.Proof = localAuthenticationProof(key, "controller", h)
	if e = writeFrame(c, h); e != nil {
		return fail(e)
	}
	var reply localHandshake
	if e = readFrame(c, &reply); e != nil {
		return fail(e)
	}
	if reply.Protocol != h.Protocol || reply.Authority != h.Authority || reply.WorkerBuild != h.WorkerBuild || reply.ControllerID != h.ControllerID || reply.ServerNonce != h.ServerNonce || reply.ClientNonce != h.ClientNonce || reply.Lease <= 0 || !equalProof(reply.Proof, localAuthenticationProof(key, "worker", reply)) {
		return fail(ErrFenced)
	}
	c.SetDeadline(time.Time{})
	fresh, e := localpeer.ReadProcess(pid)
	if e != nil || fresh.PID != ownerProcess.PID || fresh.UID != ownerProcess.UID || fresh.Start != ownerProcess.Start {
		return fail(ErrFenced)
	}
	if !stopHandshake() {
		if e = ctx.Err(); e == nil {
			e = ErrFenced
		}
		return fail(e)
	}
	return &LocalClient{controllerID: id, directory: dir, conn: c, Lease: reply.Lease, WorkerBuild: reply.WorkerBuild, authority: scope, ownerProcess: ownerProcess}, nil
}
func (c *LocalClient) Close() error { return c.conn.Close() }
func (c *LocalClient) Call(ctx context.Context, req LocalRequest) (LocalResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out LocalResponse
	if ctx == nil {
		return out, ErrConflict
	}
	if e := ctx.Err(); e != nil {
		return out, e
	}
	cancelled := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = c.conn.SetDeadline(time.Now()); close(cancelled) })
	defer func() {
		if !stop() {
			<-cancelled
		}
		_ = c.conn.SetDeadline(time.Time{})
	}()
	deadline := time.Now().Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	c.conn.SetDeadline(deadline)
	if e := ctx.Err(); e != nil {
		return out, e
	}
	if e := writeFrame(c.conn, req); e != nil {
		c.conn.Close()
		return out, e
	}
	if e := readFrame(c.conn, &out); e != nil {
		c.conn.Close()
		return out, e
	}
	if out.Error != "" {
		return out, fabric.NewError(fabric.CodeTargetUnavailable, "Local worker request was rejected ("+out.Code+")")
	}
	return out, nil
}

// OwnerProcess rechecks the actual mutually authenticated IPC server's kernel
// birth identity. It never trusts a native snapshot PID or asserted wire root.
func (c *LocalClient) OwnerProcess() (localpeer.ProcessSnapshot, error) {
	if c == nil || c.authority.Kind() != nativeauthority.Local {
		return localpeer.ProcessSnapshot{}, ErrFenced
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	pid, uid, e := localpeer.Owner(c.conn)
	if e != nil {
		return localpeer.ProcessSnapshot{}, e
	}
	fresh, e := localpeer.ReadProcess(pid)
	if e != nil {
		return fresh, e
	}
	if fresh.PID != c.ownerProcess.PID || fresh.UID != uid || fresh.UID != c.ownerProcess.UID || fresh.Start != c.ownerProcess.Start {
		return localpeer.ProcessSnapshot{}, ErrFenced
	}
	return fresh, nil
}
