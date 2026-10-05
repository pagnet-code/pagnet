package sessionworker

import (
	"context"
	"net"
	"time"

	"github.com/pagnet-code/pagnet/internal/localpeer"
)

// This channel shares the current CLOUD controller's fence. It does not adopt
// a local actor, advance a lease, cancel work, acknowledge output or reveal data.
func serveCloudReadiness(parent context.Context, c *net.UnixConn, j *Journal, key []byte, auth handshake, controllers *currentController) {
	if j.isLocal() || auth.Lease <= 0 || auth.NativeGeneration != "" || auth.Error != "" || !controllers.installStream(auth.Lease, auth.ControllerID, c) {
		return
	}
	defer controllers.releaseStream(c)
	auth.Proof = authenticationProof(key, "worker", auth)
	if writeFrame(c, auth) != nil {
		return
	}
	var request readinessWait
	if readBoundedFrame(c, &request, 4096) != nil || !request.Token.valid() {
		return
	}
	_ = c.SetDeadline(time.Now().Add(localReadinessTimeout + time.Second))
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	joined := make(chan struct{})
	go func() { defer close(joined); var extra [1]byte; _, _ = c.Read(extra[:]); cancel() }()
	defer func() { _ = c.Close(); <-joined }()
	token, e := j.cloudReadiness.wait(ctx, request.Token)
	reply := readinessReply{Token: token}
	if e != nil {
		reply.Error = "Cloud source notification is no longer current"
	}
	_ = writeFrame(c, reply)
}

// WaitCloudReady authenticates an auxiliary socket to the exact original OS
// process and current controller lease, leaving the main cancellation RPC free.
func (c *Controller) WaitCloudReady(ctx context.Context, dir string, scope Scope, key []byte, last ReadinessToken) (ready ReadinessToken, waitErr error) {
	if c == nil || ctx == nil || len(key) != 32 || !last.valid() {
		return ready, ErrFenced
	}
	if e := ctx.Err(); e != nil {
		return ready, e
	}
	defer func() {
		if waitErr != nil && ctx.Err() != nil {
			waitErr = ctx.Err()
		}
	}()
	c.mu.Lock()
	primaryPID, primaryUID, e := localpeer.Owner(c.conn)
	primary, pe := localpeer.ReadProcess(primaryPID)
	lease, id, ownership, build := c.Lease, c.identity, c.Ownership, c.WorkerBuild
	c.mu.Unlock()
	if e != nil || pe != nil || primary.UID != primaryUID {
		return ready, ErrFenced
	}
	path, e := SocketPath(dir)
	if e != nil {
		return ready, e
	}
	conn, e := (&net.Dialer{}).DialContext(ctx, "unix", path)
	if e != nil {
		return ready, e
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
	process, pe := localpeer.ReadProcess(pid)
	if e != nil || pe != nil || pid != primary.PID || uid != primary.UID || process.Start != primary.Start {
		return ready, ErrFenced
	}
	var hello handshake
	if e = readFrame(conn, &hello); e != nil {
		return ready, e
	}
	if hello.Protocol != Protocol || hello.Scope != scope || hello.Ownership != ownership || hello.WorkerBuild != build || hello.Mode != "" || hello.NativeGeneration != "" || hello.Error != "" || hello.Lease != 0 || hello.ControllerID != "" || hello.ClientNonce != "" || hello.Proof != "" || !validNonce(hello.ServerNonce) {
		return ready, ErrFenced
	}
	hello.Mode = "cloud-readiness"
	hello.Lease = lease
	hello.ControllerID = id
	hello.ClientNonce, e = freshNonce()
	if e != nil {
		return ready, e
	}
	hello.Proof = authenticationProof(key, "controller", hello)
	if e = writeFrame(conn, hello); e != nil {
		return ready, e
	}
	var reply handshake
	if e = readFrame(conn, &reply); e != nil {
		return ready, e
	}
	if reply.Mode != hello.Mode || reply.Protocol != hello.Protocol || reply.Scope != hello.Scope || reply.Ownership != hello.Ownership || reply.WorkerBuild != hello.WorkerBuild || reply.ServerNonce != hello.ServerNonce || reply.ClientNonce != hello.ClientNonce || reply.ControllerID != id || reply.Lease != lease || reply.Error != "" || reply.NativeGeneration != "" || !equalProof(reply.Proof, authenticationProof(key, "worker", reply)) {
		return ready, ErrFenced
	}
	deadline = time.Now().Add(localReadinessTimeout + time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	if e = writeFrame(conn, readinessWait{last}); e != nil {
		return ready, e
	}
	var result readinessReply
	if e = readBoundedFrame(conn, &result, 4096); e != nil {
		return ready, e
	}
	if result.Error != "" || !result.Token.valid() {
		return ready, ErrFenced
	}
	return result.Token, nil
}
