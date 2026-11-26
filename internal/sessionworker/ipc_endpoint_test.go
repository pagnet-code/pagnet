package sessionworker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

type endpointTestConn struct {
	net.Conn
	writes, reads int
	closed        bool
	deadlines     []time.Time
	setDeadline   func(time.Time) error
}

func (c *endpointTestConn) Write(b []byte) (int, error) {
	c.writes++
	return c.Conn.Write(b)
}

func (c *endpointTestConn) Read(b []byte) (int, error) {
	c.reads++
	return c.Conn.Read(b)
}

func (c *endpointTestConn) Close() error {
	c.closed = true
	return c.Conn.Close()
}

func (c *endpointTestConn) SetDeadline(d time.Time) error {
	c.deadlines = append(c.deadlines, d)
	if c.setDeadline != nil {
		if err := c.setDeadline(d); err != nil {
			return err
		}
	}
	return c.Conn.SetDeadline(d)
}

func endpointTestExchange(t *testing.T, controller *Controller, server net.Conn) {
	t.Helper()
	req := Request{Type: "snapshot", Sequence: 42, Payload: json.RawMessage(`{"value":1}`)}
	var expected bytes.Buffer
	if err := writeFrame(&expected, req); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		frame := make([]byte, expected.Len())
		if _, err := io.ReadFull(server, frame); err != nil {
			result <- err
			return
		}
		if !bytes.Equal(frame, expected.Bytes()) {
			result <- errors.New("endpoint changed request wire bytes")
			return
		}
		result <- writeFrame(server, Response{Error: "response"})
	}()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	response, err := controller.CallEndpoint(ctx, req)
	if err != nil {
		t.Fatal("valid endpoint call failed", err)
	}
	if response.Error != "response" {
		t.Fatalf("unexpected response: %+v", response)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestControllerEndpointPreflightPreservesConnection(t *testing.T) {
	for _, mode := range []string{"busy", "canceled", "expired", "invalid_json", "oversized", "deadline_error", "canceled_after_deadline"} {
		t.Run(mode, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			conn := &endpointTestConn{Conn: client}
			controller := &Controller{conn: conn}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			req := Request{Type: "unsent"}
			var want error
			switch mode {
			case "busy":
				controller.mu.Lock()
				want = ErrControllerCallBusy
			case "canceled":
				cancel()
				want = context.Canceled
			case "expired":
				expired, stop := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
				defer stop()
				ctx = expired
				want = context.DeadlineExceeded
			case "invalid_json":
				req.Payload = json.RawMessage(`{`)
			case "oversized":
				req.Type = strings.Repeat("x", maxFrame)
			case "deadline_error":
				want = errors.New("deadline failed")
				conn.setDeadline = func(time.Time) error { return want }
			case "canceled_after_deadline":
				want = context.Canceled
				conn.setDeadline = func(time.Time) error { cancel(); return nil }
			}
			_, err := controller.CallEndpoint(ctx, req)
			if mode == "busy" {
				controller.mu.Unlock()
			}
			if !errors.Is(err, ErrControllerCallNotStarted) || (want != nil && !errors.Is(err, want)) {
				t.Fatalf("unexpected preflight result: %v", err)
			}
			if conn.writes != 0 || conn.reads != 0 || conn.closed {
				t.Fatalf("preflight used connection: writes=%d reads=%d closed=%v", conn.writes, conn.reads, conn.closed)
			}
			if mode == "canceled_after_deadline" && (len(conn.deadlines) != 2 || !conn.deadlines[1].IsZero()) {
				t.Fatalf("canceled preflight retained deadline: %v", conn.deadlines)
			}
			conn.setDeadline = nil
			endpointTestExchange(t, controller, server)
		})
	}
}

func TestControllerEndpointSuccess(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	conn := &endpointTestConn{Conn: client}
	endpointTestExchange(t, &Controller{conn: conn}, server)
	if len(conn.deadlines) != 2 || conn.deadlines[0].IsZero() || !conn.deadlines[1].IsZero() || conn.closed {
		t.Fatalf("unexpected successful connection state: deadlines=%v closed=%v", conn.deadlines, conn.closed)
	}
}

func TestControllerEndpointDispatchFailureClosesConnection(t *testing.T) {
	for _, mode := range []string{"write_timeout", "read_timeout", "eof"} {
		t.Run(mode, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			conn := &endpointTestConn{Conn: client}
			controller := &Controller{conn: conn}
			read := make(chan error, 1)
			if mode != "write_timeout" {
				go func() {
					var req Request
					err := readFrame(server, &req)
					if mode == "eof" {
						_ = server.Close()
					}
					read <- err
				}()
			}
			ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
			defer cancel()
			_, err := controller.CallEndpoint(ctx, Request{Type: "snapshot"})
			if err == nil || errors.Is(err, ErrControllerCallNotStarted) {
				t.Fatalf("dispatched request returned unsent result: %v", err)
			}
			if !conn.closed || conn.writes == 0 {
				t.Fatalf("dispatch failure state: writes=%d closed=%v", conn.writes, conn.closed)
			}
			if mode != "write_timeout" {
				if err := <-read; err != nil {
					t.Fatal("request was not sent", err)
				}
			}
			if mode == "eof" && !errors.Is(err, io.EOF) {
				t.Fatalf("expected EOF: %v", err)
			}
			deadline, _ := ctx.Deadline()
			if len(conn.deadlines) == 0 || !conn.deadlines[0].Equal(deadline) {
				t.Fatal("call did not use context deadline")
			}
		})
	}
}

func TestControllerEndpointExplicitCancellation(t *testing.T) {
	for _, mode := range []string{"write", "read"} {
		t.Run(mode, func(t *testing.T) {
			client, server := net.Pipe()
			defer server.Close()
			started := make(chan struct{})
			conn := &endpointCancelConn{Conn: client, started: started, signalWrite: mode == "write"}
			controller := &Controller{conn: conn}
			if mode == "read" {
				go func() {
					var req Request
					_ = readFrame(server, &req)
				}()
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			finished := make(chan error, 1)
			go func() { _, err := controller.CallEndpoint(ctx, Request{Type: "snapshot"}); finished <- err }()
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("call did not start I/O")
			}
			cancel()
			select {
			case err := <-finished:
				if !errors.Is(err, context.Canceled) || errors.Is(err, ErrControllerCallNotStarted) {
					t.Fatalf("dispatched cancellation = %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("explicit cancellation waited for the 5s socket deadline")
			}
			if _, err := server.Write([]byte{0}); err == nil {
				t.Fatal("canceled RPC left transport open")
			}
		})
	}
}

type endpointCancelConn struct {
	net.Conn
	started     chan struct{}
	signalWrite bool
	once        sync.Once
}

func (c *endpointCancelConn) Write(b []byte) (int, error) {
	if c.signalWrite {
		c.once.Do(func() { close(c.started) })
	}
	return c.Conn.Write(b)
}

func (c *endpointCancelConn) Read(b []byte) (int, error) {
	if !c.signalWrite {
		c.once.Do(func() { close(c.started) })
	}
	return c.Conn.Read(b)
}

func TestControllerEndpointCancellationJoinsBeforeUnlock(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	started, callbackEntered, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	base := &endpointCancelConn{Conn: client, started: started}
	conn := &endpointTestConn{Conn: base}
	conn.setDeadline = func(deadline time.Time) error {
		if !deadline.IsZero() && time.Until(deadline) <= 0 {
			close(callbackEntered)
			<-release
		}
		return nil
	}
	controller := &Controller{conn: conn}
	written := make(chan error, 1)
	writeReply := make(chan struct{})
	var replyOnce sync.Once
	defer replyOnce.Do(func() { close(writeReply) })
	go func() {
		var req Request
		if err := readFrame(server, &req); err != nil {
			written <- err
			return
		}
		<-writeReply
		written <- writeFrame(server, Response{})
	}()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	finished := make(chan error, 1)
	go func() { _, err := controller.CallEndpoint(ctx, Request{Type: "snapshot"}); finished <- err }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("call did not reach its read")
	}
	cancel()
	select {
	case <-callbackEntered:
	case <-time.After(time.Second):
		t.Fatal("cancellation callback did not start")
	}
	replyOnce.Do(func() { close(writeReply) })
	if err := <-written; err != nil {
		t.Fatal("late reply failed before cancellation deadline advanced", err)
	}
	// The reply is complete, but cleanup must retain mu until the callback joins.
	if _, err := controller.CallEndpoint(t.Context(), Request{Type: "next"}); !errors.Is(err, ErrControllerCallBusy) {
		t.Fatalf("later call entered before cancellation callback joined: %v", err)
	}
	select {
	case err := <-finished:
		t.Fatalf("call returned before cancellation callback joined: %v", err)
	default:
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case err := <-finished:
		if !errors.Is(err, context.Canceled) || errors.Is(err, ErrControllerCallNotStarted) {
			t.Fatalf("late reply accepted after cancellation: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("call did not finish after cancellation callback")
	}
	if !conn.closed || !conn.deadlines[len(conn.deadlines)-1].IsZero() {
		t.Fatal("canceled call did not close transport and reset deadline")
	}
	// A fresh serialized connection cannot be touched by the old callback.
	nextClient, nextServer := net.Pipe()
	defer nextClient.Close()
	defer nextServer.Close()
	controller.mu.Lock()
	controller.conn = nextClient
	controller.mu.Unlock()
	endpointTestExchange(t, controller, nextServer)
}
