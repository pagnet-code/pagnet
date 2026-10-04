package sessionworker

import (
	"context"
	"net"
	"time"

	"github.com/pagnet-code/pagnet/internal/localpeer"
)

type readinessWait struct {
	Token ReadinessToken `json:"token"`
}
type readinessReply struct {
	Token ReadinessToken `json:"token"`
	Error string         `json:"error,omitempty"`
}

// Auxiliary readiness sockets share current primary authority but never install
// a controller, advance a lease, acknowledge evidence, or carry source payloads.
func serveLocalReadiness(parent context.Context, c *net.UnixConn, owner *SessionOwner, key []byte, build string, hello, auth localHandshake, controllers *currentController) {
	if auth.Protocol != hello.Protocol || auth.Authority != hello.Authority || auth.WorkerBuild != build || auth.ServerNonce != hello.ServerNonce || !validNonce(auth.ClientNonce) || auth.ControllerID == "" || len(auth.ControllerID) > 256 || auth.Lease <= 0 || !equalProof(auth.Proof, localAuthenticationProof(key, "controller.readiness", auth)) {
		return
	}
	if !controllers.installStream(auth.Lease, auth.ControllerID, c) {
		return
	}
	defer controllers.releaseStream(c)
	auth.Proof = localAuthenticationProof(key, "worker.readiness", auth)
	if writeFrame(c, auth) != nil {
		return
	}
	var request readinessWait
	if readBoundedFrame(c, &request, 4096) != nil || !request.Token.valid() {
		return
	}
	// The handshake deadline must not turn a quiet native wait into 5s polling.
	// The notification itself is bounded at 30s and abandonment cancels it.
	_ = c.SetDeadline(time.Now().Add(localReadinessTimeout + time.Second))
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	// Detect client abandonment without holding the primary IPC or registry lock.
	joined := make(chan struct{})
	go func() { defer close(joined); var extra [1]byte; _, _ = c.Read(extra[:]); cancel() }()
	defer func() { _ = c.Close(); <-joined }()
	token, e := owner.journal.localReadiness.wait(ctx, request.Token)
	reply := readinessReply{Token: token}
	if e != nil {
		reply.Error = "Readiness wait is no longer current"
	}
	_ = writeFrame(c, reply)
}

// WaitReady waits only on an independently authenticated readiness channel.
// It never changes the primary lease or blocks the primary cancellation socket.
// controlKey is actual memory-only private bootstrap material, not wire input.
func (c *LocalClient) WaitReady(ctx context.Context, controlKey []byte, last ReadinessToken) (ready ReadinessToken, waitErr error) {
	if c == nil || ctx == nil || len(controlKey) != 32 || !last.valid() {
		return ReadinessToken{}, ErrFenced
	}
	if e := ctx.Err(); e != nil {
		return ReadinessToken{}, e
	}
	defer func() {
		if waitErr != nil && ctx.Err() != nil {
			waitErr = ctx.Err()
		}
	}()
	primary, e := c.OwnerProcess()
	if e != nil {
		return ReadinessToken{}, e
	}
	path, e := SocketPath(c.directory)
	if e != nil {
		return ReadinessToken{}, e
	}
	conn, e := (&net.Dialer{}).DialContext(ctx, "unix", path)
	if e != nil {
		return ReadinessToken{}, e
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	deadline := time.Now().Add(handshakeTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	pid, uid, e := localpeer.Owner(conn)
	if e != nil {
		return ReadinessToken{}, e
	}
	process, e := localpeer.ReadProcess(pid)
	if e != nil || process.PID != primary.PID || process.UID != uid || process.UID != primary.UID || process.Start != primary.Start {
		return ReadinessToken{}, ErrFenced
	}
	var hello localHandshake
	if e = readFrame(conn, &hello); e != nil {
		return ReadinessToken{}, e
	}
	if hello.Mode != "" || hello.Protocol != LocalProtocol || hello.Authority != c.authority || hello.WorkerBuild != c.WorkerBuild || !validNonce(hello.ServerNonce) || hello.ClientNonce != "" || hello.ControllerID != "" || hello.Lease != 0 || hello.Proof != "" {
		return ReadinessToken{}, ErrFenced
	}
	hello.Mode = "readiness"
	hello.ControllerID = c.controllerID
	hello.Lease = c.Lease
	hello.ClientNonce, e = freshNonce()
	if e != nil {
		return ReadinessToken{}, e
	}
	hello.Proof = localAuthenticationProof(controlKey, "controller.readiness", hello)
	if e = writeFrame(conn, hello); e != nil {
		return ReadinessToken{}, e
	}
	var reply localHandshake
	if e = readFrame(conn, &reply); e != nil {
		return ReadinessToken{}, e
	}
	if reply.Mode != hello.Mode || reply.Protocol != hello.Protocol || reply.Authority != hello.Authority || reply.WorkerBuild != hello.WorkerBuild || reply.ControllerID != hello.ControllerID || reply.Lease != hello.Lease || reply.ServerNonce != hello.ServerNonce || reply.ClientNonce != hello.ClientNonce || !equalProof(reply.Proof, localAuthenticationProof(controlKey, "worker.readiness", reply)) {
		return ReadinessToken{}, ErrFenced
	}
	if _, e = c.OwnerProcess(); e != nil {
		return ReadinessToken{}, e
	}
	deadline = time.Now().Add(localReadinessTimeout + time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	if e = writeFrame(conn, readinessWait{last}); e != nil {
		return ReadinessToken{}, e
	}
	var result readinessReply
	if e = readBoundedFrame(conn, &result, 4096); e != nil {
		return ReadinessToken{}, e
	}
	if result.Error != "" || !result.Token.valid() {
		return ReadinessToken{}, ErrFenced
	}
	return result.Token, nil
}
