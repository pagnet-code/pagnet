//go:build linux || darwin

package sessionworker

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func ipcFixture(t *testing.T) (*Journal, string, []byte, *atomic.Int32) {
	t.Helper()
	dir, err := os.MkdirTemp("", "pgn-worker-")
	if err != nil {
		t.Fatal(err)
	}
	j, err := OpenJournal(dir, testScope())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var effects atomic.Int32
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, j, key, func(out Outcome, _ json.RawMessage) {
			effects.Add(1)
			if err := j.Settle(context.Background(), out.Sequence, "completed", json.RawMessage(`{"native":"effect"}`)); err != nil {
				t.Error(err)
			}
		})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Error(err)
			}
		case <-time.After(6 * time.Second):
			t.Error("worker IPC shutdown hung")
		}
		_ = j.Close()
		_ = os.RemoveAll(dir)
	})
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Lstat(filepath.Join(dir, "controller.sock")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("private worker socket not ready")
		}
		time.Sleep(time.Millisecond)
	}
	return j, dir, key, &effects
}

func TestPrivateIPCHandoffAndAuthentication(t *testing.T) {
	j, dir, key, effects := ipcFixture(t)
	ctx := context.Background()
	a, err := DialController(ctx, dir, testScope(), key, "controller-a")
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	request := Request{Type: "intent", Sequence: 1, CommandID: "native-command", Kind: "input", Payload: json.RawMessage(`{"input":"one"}`)}
	response, err := a.Call(ctx, request)
	if err != nil || response.Error != "" || response.Outcome == nil {
		t.Fatalf("first admission: %+v %v", response, err)
	}
	wrongKey := append([]byte(nil), key...)
	wrongKey[0] ^= 1
	if wrong, err := DialController(ctx, dir, testScope(), wrongKey, "bad"); err == nil {
		_ = wrong.Close()
		t.Fatal("wrong credential authenticated")
	}
	wrongScope := testScope()
	wrongScope.AccountID = "other-account"
	if wrong, err := DialController(ctx, dir, wrongScope, key, "bad-scope"); err == nil {
		_ = wrong.Close()
		t.Fatal("different account authenticated")
	}
	if err := j.CurrentLease(ctx, a.Lease); err != nil {
		t.Fatalf("failed authentication fenced valid owner: %v", err)
	}
	b, err := DialController(ctx, dir, testScope(), key, "controller-b")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if b.Lease <= a.Lease {
		t.Fatal("replacement controller has no new durable fence")
	}
	response, err = a.Call(ctx, Request{Type: "intent", Sequence: 2, CommandID: "old", Kind: "input", Payload: json.RawMessage(`{}`)})
	if err != nil || response.Error != ErrFenced.Error() {
		t.Fatalf("old connection retained authority: %+v %v", response, err)
	}
	response, err = b.Call(ctx, request)
	if err != nil || response.Error != "" || response.Outcome == nil || response.Outcome.State != "completed" {
		t.Fatalf("replacement replay: %+v %v", response, err)
	}
	if effects.Load() != 1 {
		t.Fatalf("native effect duplicated: %d", effects.Load())
	}
}

func TestPrivateIPCFreshNonceAndVersionFailClosed(t *testing.T) {
	j, dir, key, _ := ipcFixture(t)
	raw := func() (net.Conn, handshake) {
		t.Helper()
		c, err := net.Dial("unix", filepath.Join(dir, "controller.sock"))
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(time.Second))
		var h handshake
		if err = readFrame(c, &h); err != nil {
			t.Fatal(err)
		}
		return c, h
	}
	first, auth := raw()
	auth.ControllerID = "captured"
	auth.ClientNonce, _ = freshNonce()
	auth.Proof = authenticationProof(key, "controller", auth)
	if err := writeFrame(first, auth); err != nil {
		t.Fatal(err)
	}
	var reply handshake
	if err := readFrame(first, &reply); err != nil {
		t.Fatal(err)
	}
	_ = first.Close()
	replay, newHello := raw()
	defer replay.Close()
	if newHello.ServerNonce == auth.ServerNonce {
		t.Fatal("worker challenge reused nonce")
	}
	if err := writeFrame(replay, auth); err != nil {
		t.Fatal(err)
	}
	if err := readFrame(replay, &reply); err == nil {
		t.Fatal("captured authentication replay succeeded")
	}
	old, h := raw()
	defer old.Close()
	h.Protocol = "pagnet-session-worker-v0"
	h.ControllerID = "old"
	h.ClientNonce, _ = freshNonce()
	h.Proof = authenticationProof(key, "controller", h)
	if err := writeFrame(old, h); err != nil {
		t.Fatal(err)
	}
	if err := readFrame(old, &reply); err == nil {
		t.Fatal("incompatible protocol silently accepted")
	}
	if err := j.CurrentLease(context.Background(), 1); err != nil {
		t.Fatalf("rejected replay changed durable lease: %v", err)
	}
	oversized, _ := raw()
	defer oversized.Close()
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], maxFrame+1)
	_, _ = oversized.Write(header[:])
	if err := readFrame(oversized, &reply); err == nil {
		t.Fatal("oversized unauthenticated frame accepted")
	}
}
