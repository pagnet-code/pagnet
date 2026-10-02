package sessionworker

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"path/filepath"
	"sync"
	"time"

	"github.com/pagnet-code/pagnet/internal/localpeer"
)

const maxFrame = 1 << 20
const handshakeTimeout = 5 * time.Second

type handshake struct {
	NativeGeneration string `json:"nativeGeneration,omitempty"`
	Error            string `json:"error,omitempty"`
	Mode             string `json:"mode,omitempty"`
	Ownership        string `json:"ownership,omitempty"`
	WorkerBuild      string `json:"workerBuild,omitempty"`
	Protocol         string `json:"protocol"`
	Scope            Scope  `json:"scope"`
	ControllerID     string `json:"controllerId,omitempty"`
	ServerNonce      string `json:"serverNonce"`
	ClientNonce      string `json:"clientNonce,omitempty"`
	Lease            int64  `json:"lease,omitempty"`
	Proof            string `json:"proof,omitempty"`
}

type Request struct {
	CaptureOffset    int               `json:"captureOffset,omitempty"`
	ReplayGeneration string            `json:"replayGeneration,omitempty"`
	ActivationOrigin *ActivationOrigin `json:"activationOrigin,omitempty"`
	ObservationID    string            `json:"observationId,omitempty"`
	SourceDigest     string            `json:"sourceDigest,omitempty"`
	Admission        *Admission        `json:"admission,omitempty"`
	Relay            *BridgeResult     `json:"relay,omitempty"`
	Cursor           int64             `json:"cursor,omitempty"`
	Limit            int               `json:"limit,omitempty"`
	Type             string            `json:"type"`
	Sequence         int64             `json:"sequence,omitempty"`
	CommandID        string            `json:"commandId,omitempty"`
	Kind             string            `json:"kind,omitempty"`
	Payload          json.RawMessage   `json:"payload,omitempty"`
}

type Response struct {
	Capture      *NativeCaptureChunk `json:"capture,omitempty"`
	Activation   *ActivationRequest  `json:"activation,omitempty"`
	Observations []NativeObservation `json:"observations,omitempty"`
	Snapshot     *NativeSnapshot     `json:"snapshot,omitempty"`
	Output       *OutputPage         `json:"output,omitempty"`
	Bridge       *BridgeCall         `json:"bridge,omitempty"`
	Outcome      *Outcome            `json:"outcome,omitempty"`
	Error        string              `json:"error,omitempty"`
}

// IntentExecutor must transfer ownership to the worker lifetime immediately.
// It must never use the controller socket's lifetime as the native turn context.
// The journal has already fsync'd admission before this callback is invoked.
type IntentExecutor func(Outcome, json.RawMessage)

func writeFrame(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(b) == 0 || len(b) > maxFrame {
		return errors.New("worker frame exceeds bound")
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(b)))
	if _, err = io.Copy(w, bytes.NewReader(header[:])); err != nil {
		return err
	}
	_, err = io.Copy(w, bytes.NewReader(b))
	return err
}
func readFrame(r io.Reader, v any) error { return readBoundedFrame(r, v, maxFrame) }
func readBoundedFrame(r io.Reader, v any, limit uint32) error {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(header[:])
	if n == 0 || n > limit {
		return errors.New("worker frame exceeds bound")
	}
	b := make([]byte, int(n))
	if _, err := io.ReadFull(r, b); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(v); err != nil {
		return err
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return errors.New("worker frame has trailing data")
	}
	return nil
}
func freshNonce() (string, error) {
	var b [32]byte
	_, err := rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:]), err
}
func validNonce(s string) bool {
	b, err := base64.RawURLEncoding.DecodeString(s)
	return err == nil && len(b) == 32
}
func authenticationProof(key []byte, role string, h handshake) string {
	h.Proof = ""
	b, _ := json.Marshal(struct {
		Domain    string    `json:"domain"`
		Role      string    `json:"role"`
		Handshake handshake `json:"handshake"`
	}{"pagnet.session-worker.authentication.v1", role, h})
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(b)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
func equalProof(a, b string) bool { return hmac.Equal([]byte(a), []byte(b)) }

// Serve authenticates owner-local controllers and allocates a fresh durable
// fence. No address is published to the network and no server credential is
// accepted. Unsupported kernel owner transports fail closed.
func Serve(ctx context.Context, j *Journal, key []byte, execute IntentExecutor) error {
	return serve(ctx, j, key, execute, nil, "")
}

const NativeOwnershipProtocol = "pagnet-whole-native-session-v2"

func ServeOwner(ctx context.Context, owner *SessionOwner, key []byte, build string) error {
	return serve(ctx, owner.journal, key, owner.Execute, owner, build)
}
func serve(ctx context.Context, j *Journal, key []byte, execute IntentExecutor, owner *SessionOwner, build string) error {
	if len(key) != 32 || execute == nil {
		return errors.New("worker requires a private control key and owned executor")
	}
	key = append([]byte(nil), key...)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	path := filepath.Join(j.dir, "controller.sock")
	if len(path) > 100 {
		return errors.New("worker socket path exceeds supported platform limit")
	}
	// Do not remove an arbitrary existing path. An interrupted worker's stale
	// socket is cleaned by its exclusive owner only after verifying its type.
	if err := removeStaleSocket(path); err != nil {
		return err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return err
	}
	defer listener.Close()
	if err := privateSocket(path); err != nil {
		return err
	}
	quit := make(chan struct{})
	defer close(quit)
	go func() {
		select {
		case <-ctx.Done():
			_ = listener.Close()
		case <-quit:
		}
	}()
	slots := make(chan struct{}, 4)
	controllers := &currentController{}
	var wg sync.WaitGroup
	defer func() { cancel(); wg.Wait() }()
	for {
		c, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		select {
		case slots <- struct{}{}:
		default:
			_ = c.Close()
			continue
		}
		wg.Go(func() {
			defer func() { <-slots }()
			defer c.Close()
			serveController(ctx, c, j, key, execute, owner, build, controllers)
		})
	}
}

func serveController(ctx context.Context, c *net.UnixConn, j *Journal, key []byte, execute IntentExecutor, owner *SessionOwner, build string, controllers *currentController) {
	if _, _, err := localpeer.Owner(c); err != nil {
		return
	}
	_ = c.SetDeadline(time.Now().Add(handshakeTimeout))
	serverNonce, err := freshNonce()
	if err != nil {
		return
	}
	hello := handshake{Protocol: Protocol, Scope: j.scope, ServerNonce: serverNonce}
	if owner != nil {
		hello.Ownership = NativeOwnershipProtocol
		hello.WorkerBuild = build
	}
	if writeFrame(c, hello) != nil {
		return
	}
	var auth handshake
	if readFrame(c, &auth) != nil || auth.Protocol != Protocol || auth.Ownership != hello.Ownership || auth.WorkerBuild != hello.WorkerBuild || auth.Scope != j.scope || auth.ServerNonce != serverNonce || !validNonce(auth.ClientNonce) || auth.ControllerID == "" || len(auth.ControllerID) > 256 || !equalProof(auth.Proof, authenticationProof(key, "controller", auth)) {
		return
	}
	if auth.Mode == "terminal" {
		if owner == nil || auth.Lease <= 0 {
			return
		}
		if !owner.hasLiveTerminal(auth.NativeGeneration) {
			auth.Error = "This native session does not expose a live interactive terminal."
			auth.Proof = authenticationProof(key, "worker", auth)
			_ = writeFrame(c, auth)
			return
		}
		if !controllers.installStream(auth.Lease, auth.ControllerID, c) {
			return
		}
		defer controllers.releaseStream(c)
		auth.Proof = authenticationProof(key, "worker", auth)
		if writeFrame(c, auth) != nil {
			return
		}
		_ = c.SetDeadline(time.Time{})
		serveTerminalStream(ctx, c, owner, controllers, auth.Lease)
		return
	}
	if auth.Mode != "" || auth.Lease != 0 || auth.NativeGeneration != "" || auth.Error != "" {
		return
	}
	auth.Lease, err = controllers.advanceAndInstall(ctx, j, auth.ControllerID, c)
	if err != nil {
		return
	}
	defer controllers.release(auth.Lease, c)
	if owner != nil {
		owner.relay.bindLease(auth.Lease)
		defer owner.relay.disconnect(auth.Lease)
	}
	auth.Proof = authenticationProof(key, "worker", auth)
	if writeFrame(c, auth) != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = c.Close()
		case <-done:
		}
	}()
	for {
		var req Request
		if readFrame(c, &req) != nil {
			return
		}
		response := Response{}
		switch req.Type {
		case "intent":
			var authorize func() error
			if owner != nil {
				authorize = func() error { return owner.relay.authorizeNativeEffect(auth.Lease) }
			}
			out, run, err := j.admit(ctx, auth.Lease, req.Sequence, req.CommandID, req.Kind, req.Payload, authorize)
			if err != nil {
				response.Error = err.Error()
			} else {
				response.Outcome = &out
				if run {
					execute(out, append(json.RawMessage(nil), req.Payload...))
				}
			}
		case "outcome":
			if err := j.CurrentLease(ctx, auth.Lease); err != nil {
				response.Error = err.Error()
			} else if out, err := j.Outcome(ctx, req.Sequence); err != nil {
				response.Error = "worker outcome is unavailable"
			} else {
				response.Outcome = &out
			}
		case "ack":
			if err := j.Acknowledge(ctx, auth.Lease, req.Sequence); err != nil {
				response.Error = err.Error()
			}
		default:
			if owner == nil {
				response.Error = "unsupported worker request"
			} else if err := j.CurrentLease(ctx, auth.Lease); err != nil {
				response.Error = err.Error()
			} else {
				response = owner.controllerRequest(ctx, auth.Lease, req)
			}
		}
		if writeFrame(c, response) != nil {
			return
		}
	}
}

// Controller is an owner-local connection with a durably allocated fence. A
// newer authenticated controller replaces its authority without ending work.
type Controller struct {
	mu                     sync.Mutex
	conn                   net.Conn
	Lease                  int64
	Ownership, WorkerBuild string
	identity               string
}

func DialController(ctx context.Context, dir string, scope Scope, key []byte, id string) (*Controller, error) {
	if len(key) != 32 || id == "" || len(id) > 256 {
		return nil, errors.New("invalid private controller identity")
	}
	c, err := (&net.Dialer{}).DialContext(ctx, "unix", filepath.Join(dir, "controller.sock"))
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*Controller, error) { _ = c.Close(); return nil, err }
	if _, _, err := localpeer.Owner(c); err != nil {
		return fail(err)
	}
	_ = c.SetDeadline(time.Now().Add(handshakeTimeout))
	var h handshake
	if err = readFrame(c, &h); err != nil {
		return fail(err)
	}
	if h.NativeGeneration != "" || h.Error != "" || h.Mode != "" || h.Protocol != Protocol || h.Scope != scope || !validNonce(h.ServerNonce) || h.ClientNonce != "" || h.ControllerID != "" || h.Lease != 0 || h.Proof != "" {
		return fail(errors.New("worker handshake scope or protocol mismatch"))
	}
	h.ControllerID = id
	h.ClientNonce, err = freshNonce()
	if err != nil {
		return fail(err)
	}
	h.Proof = authenticationProof(key, "controller", h)
	if err = writeFrame(c, h); err != nil {
		return fail(err)
	}
	var reply handshake
	if err = readFrame(c, &reply); err != nil {
		return fail(err)
	}
	if reply.NativeGeneration != "" || reply.Error != "" || reply.Mode != h.Mode || reply.Protocol != h.Protocol || reply.Ownership != h.Ownership || reply.WorkerBuild != h.WorkerBuild || reply.Scope != h.Scope || reply.ControllerID != h.ControllerID || reply.ServerNonce != h.ServerNonce || reply.ClientNonce != h.ClientNonce || reply.Lease <= 0 || !equalProof(reply.Proof, authenticationProof(key, "worker", reply)) {
		return fail(errors.New("worker mutual authentication failed"))
	}
	_ = c.SetDeadline(time.Time{})
	return &Controller{conn: c, Lease: reply.Lease, Ownership: reply.Ownership, WorkerBuild: reply.WorkerBuild, identity: id}, nil
}
func (c *Controller) Close() error { return c.conn.Close() }
func (c *Controller) Call(ctx context.Context, req Request) (Response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	deadline := time.Now().Add(handshakeTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = c.conn.SetDeadline(deadline)
	if err := writeFrame(c.conn, req); err != nil {
		_ = c.conn.Close()
		return Response{}, err
	}
	var response Response
	err := readFrame(c.conn, &response)
	if err != nil {
		_ = c.conn.Close()
	}
	_ = c.conn.SetDeadline(time.Time{})
	return response, err
}

func DialOwnerController(ctx context.Context, dir string, scope Scope, key []byte, id string) (*Controller, error) {
	c, err := DialController(ctx, dir, scope, key, id)
	if err != nil {
		return nil, err
	}
	if c.Ownership != NativeOwnershipProtocol {
		_ = c.Close()
		return nil, errors.New("worker lacks whole native session ownership protocol")
	}
	return c, nil
}
func (o *SessionOwner) controllerRequest(ctx context.Context, lease int64, req Request) (response Response) {
	var err error
	switch req.Type {
	case "activation_poll":
		response.Activation, err = o.relay.pollActivation(lease)
	case "activation_origin":
		if req.ActivationOrigin == nil {
			err = errors.New("activation origin missing")
		} else {
			err = o.relay.completeActivation(lease, *req.ActivationOrigin)
		}
	case "snapshot":
		snap := o.Snapshot()
		response.Snapshot = &snap
	case "output":
		var page OutputPage
		page, err = o.outputReplay().Replay(req.ReplayGeneration, req.Cursor, req.Limit)
		if err == nil {
			response.Output = &page
		}
	case "observations":
		response.Observations, err = o.journal.PendingObservationsForLease(ctx, lease, req.Limit)
	case "source_capture":
		response.Capture, err = o.journal.ReadCaptureChunk(ctx, lease, req.ObservationID, req.SourceDigest, req.CaptureOffset)
	case "observation_ack":
		err = o.journal.AcknowledgeObservation(ctx, lease, req.ObservationID, req.SourceDigest)
	case "admission_revoke":
		o.relay.disconnect(lease)
	case "admission":
		if req.Admission == nil {
			err = errors.New("fresh control-plane admission required")
		} else {
			err = o.relay.admit(lease, *req.Admission)
		}
	case "bridge_poll":
		response.Bridge, err = o.relay.poll(lease)
	case "bridge_result":
		if req.Relay == nil {
			err = errors.New("native relay result missing")
		} else {
			err = o.relay.complete(lease, *req.Relay)
		}
	default:
		err = errors.New("unsupported native owner request")
	}
	if err != nil {
		response.Error = err.Error()
	}
	return response
}

// Installation follows mutual authentication and durable lease acquisition.
// Unauthenticated peers can never evict the current controller. Superseded
// sockets close promptly so stale readers cannot exhaust bounded IPC slots.
type currentController struct {
	mu       sync.Mutex
	lease    int64
	identity string
	stream   *net.UnixConn
	conn     *net.UnixConn
}

// The same mutex fences ephemeral native effects and lease installation.
// There is no SQLite transaction or durable intent for a terminal keystroke.
func (c *currentController) advanceAndInstall(ctx context.Context, j *Journal, id string, conn *net.UnixConn) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	lease, err := j.AdvanceLease(ctx)
	if err != nil {
		return 0, err
	}
	if c.conn != nil {
		_ = c.conn.Close()
	}
	if c.stream != nil {
		_ = c.stream.Close()
		c.stream = nil
	}
	c.lease = lease
	c.identity = id
	c.conn = conn
	return lease, nil
}
func (c *currentController) installStream(lease int64, id string, conn *net.UnixConn) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lease != lease || c.identity != id || c.conn == nil {
		return false
	}
	if c.stream != nil {
		_ = c.stream.Close()
	}
	c.stream = conn
	return true
}
func (c *currentController) releaseStream(conn *net.UnixConn) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stream == conn {
		c.stream = nil
	}
}
func (c *currentController) terminalEffect(lease int64, conn *net.UnixConn, do func() error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lease != lease || c.conn == nil || c.stream != conn {
		return ErrFenced
	}
	return do()
}
func (c *currentController) release(lease int64, conn *net.UnixConn) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lease == lease && c.conn == conn {
		c.conn = nil
		if c.stream != nil {
			_ = c.stream.Close()
			c.stream = nil
		}
	}
}
