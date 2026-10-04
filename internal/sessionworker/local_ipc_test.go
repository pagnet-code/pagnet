package sessionworker

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestLocalCallAlreadyCancelledWritesNoRequest(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	c := &LocalClient{conn: client}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := c.Call(ctx, LocalRequest{Type: "snapshot"}); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	server.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	var request LocalRequest
	if e := readFrame(server, &request); e == nil {
		t.Fatal("cancelled caller wrote a request")
	}
}
func TestLocalCallCancellationJoinsDeadlineCallback(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	c := &LocalClient{conn: client}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, e := c.Call(ctx, LocalRequest{Type: "snapshot"}); done <- e }()
	var req LocalRequest
	if e := readFrame(server, &req); e != nil {
		t.Fatal(e)
	}
	cancel()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("cancelled blocked read returned success")
		}
	case <-time.After(time.Second):
		t.Fatal("call waited for generic five-second deadline")
	}
	// The callback has joined before Call releases its mutex; no pending callback
	// can alter the deadline of a later owner call. Failed framed transport is
	// closed rather than reused with a potentially ambiguous request/response.
	if _, e := c.Call(context.Background(), LocalRequest{Type: "snapshot"}); e == nil {
		t.Fatal("ambiguous closed transport reused")
	}
}
