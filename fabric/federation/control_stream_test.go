package federation_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/federation"
	"io"
	"net"
	"testing"
	"time"
)

func actualPullChannels(t *testing.T, credit uint8) (*federation.PullPage, *federation.PullPage, federation.ControlRequest) {
	s, r, q, _ := actualPullRig(t, credit)
	return s, r, q
}
func actualPullRig(t *testing.T, credit uint8) (*federation.PullPage, *federation.PullPage, federation.ControlRequest, *federation.Duplex) {
	t.Helper()
	f, l, _, _ := newControlFixture(t)
	ctx := context.Background()
	a, _, e := f.ledger.Admit(ctx, f.cfg, f.bundle, f.caller)
	if e != nil {
		t.Fatal(e)
	}
	attempt, _, e := f.ledger.MarkAttempt(ctx, f.cfg, a, f.caller)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.ledger.Associate(ctx, f.cfg, a, f.caller, attempt, federation.Association{Protocol: "native.local", BindingDigest: sha256.Sum256([]byte("source-binding-fixture")), PrivateReference: json.RawMessage(`{"retainedOriginal":"source-frame-fixture"}`)}); e != nil {
		t.Fatal(e)
	}
	floor := federation.ConsumerCursor{Ordinal: -1}
	request := signedControl(t, &f, "pull", "actual-pull-page", attempt.ID(), federation.ControlPayload{Cursor: &floor, Credit: credit})
	if _, _, fresh, e := l.Begin(ctx, f.cfg, request); e != nil || !fresh {
		t.Fatal(e)
	}
	sourceCfg := f.cfg
	sourceCfg.Local = f.cfg.Remote
	sourceCfg.Remote = f.cfg.Local
	sourceCfg.Keys = f.sourceKey
	sourceCfg.Trust = f.sourceGate
	sourceCfg.SourceRole = true
	left, right := net.Pipe()
	sourceStream, _ := federation.NewConnStream(left, 3*time.Second)
	destStream, _ := federation.NewConnStream(right, 3*time.Second)
	source, e := federation.NewDuplex(ctx, sourceCfg, sourceStream, 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	dest, e := federation.NewDuplex(ctx, f.cfg, destStream, 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	// Original output travels destination -> original source caller.
	sourceChannel, _ := federation.NewForwardChannel(source)
	destChannel, _ := federation.NewForwardChannel(dest)
	sender, e := federation.NewPullPage(destChannel, request)
	if e != nil {
		t.Fatal(e)
	}
	receiver, e := federation.NewPullPage(sourceChannel, request)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { sender.Close(); receiver.Close() })
	return sender, receiver, request, dest
}
func TestActualEncryptedPullPageBackpressureExactBytesAndPageEOF(t *testing.T) {
	sender, receiver, r := actualPullChannels(t, 2)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	start := fabric.InvocationFrame{InvocationID: r.Proof.Frame.InvocationID, Sequence: 0, Kind: fabric.FrameStart}
	go func() { done <- sender.Send(ctx, start) }()
	select {
	case e := <-done:
		t.Fatal("unpulled original frame did not backpressure", e)
	case <-time.After(30 * time.Millisecond):
	}
	got, e := receiver.Receive(ctx)
	if e != nil || got.Kind != fabric.FrameStart {
		t.Fatal(e)
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	data := []byte(`{"originalNumber":9007199254740993123456789,"utf8":"🙂"}`)
	go func() {
		done <- sender.Send(ctx, fabric.InvocationFrame{InvocationID: r.Proof.Frame.InvocationID, Sequence: 1, Kind: fabric.FrameChunk, Data: data})
	}()
	got, e = receiver.Receive(ctx)
	if e != nil || !bytes.Equal(got.Data, data) {
		t.Fatal("original output bytes changed", e)
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	if got, e = receiver.Receive(ctx); !errors.Is(e, io.EOF) || got.Kind == fabric.FrameComplete {
		t.Fatal("credit exhaustion fabricated completion", e)
	}
	if e = sender.Send(ctx, fabric.InvocationFrame{InvocationID: r.Proof.Frame.InvocationID, Sequence: 2, Kind: fabric.FrameComplete}); e == nil {
		t.Fatal("excess credit accepted")
	}
}
func TestActualEncryptedPullPageCancellationUnblocksWithoutTerminalFabrication(t *testing.T) {
	sender, receiver, r := actualPullChannels(t, 4)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- sender.Send(ctx, fabric.InvocationFrame{InvocationID: r.Proof.Frame.InvocationID, Sequence: 0, Kind: fabric.FrameStart})
	}()
	time.Sleep(20 * time.Millisecond)
	receiver.Close()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("transport close confirmed original source output")
		}
	case <-time.After(time.Second):
		t.Fatal("owned blocked producer did not join")
	}
	if got, e := receiver.Receive(ctx); e == nil || got.Kind == fabric.FrameComplete {
		t.Fatal("transport cancellation fabricated completion")
	}
}
func TestActualEncryptedPullPageRejectsWrongSourceAndImpossibleTerminal(t *testing.T) {
	for _, kind := range []string{"wrong-id", "wrong-sequence", "complete-before-start", "duplicate-start", "terminal-error-without-error", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			sender, receiver, r := actualPullChannels(t, 4)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if kind == "duplicate-start" || kind == "terminal-error-without-error" || kind == "oversized" {
				done := make(chan error, 1)
				go func() {
					done <- sender.Send(ctx, fabric.InvocationFrame{InvocationID: r.Proof.Frame.InvocationID, Sequence: 0, Kind: fabric.FrameStart})
				}()
				if _, e := receiver.Receive(ctx); e != nil {
					t.Fatal(e)
				}
				if e := <-done; e != nil {
					t.Fatal(e)
				}
			}
			f := fabric.InvocationFrame{InvocationID: r.Proof.Frame.InvocationID, Sequence: 0, Kind: fabric.FrameStart}
			switch kind {
			case "wrong-id":
				f.InvocationID = "unrelated-original"
			case "wrong-sequence":
				f.Sequence = 2
			case "complete-before-start":
				f.Kind = fabric.FrameComplete
			case "duplicate-start":
				f.Sequence = 1
			case "terminal-error-without-error":
				f.Sequence = 1
				f.Kind = fabric.FrameError
			case "oversized":
				f.Sequence = 1
				f.Kind = fabric.FrameChunk
				f.Data = bytes.Repeat([]byte("x"), fabric.MaxFrameBytes)
			}
			if e := sender.Send(ctx, f); e == nil {
				t.Fatal("invalid original frame accepted")
			}
		})
	}
}

func TestActualEncryptedPullReceiverRejectsMaliciousAuthenticatedFrame(t *testing.T) {
	for _, kind := range []string{"wrong-id", "skip", "wrong-page-digest", "premature-complete", "unknown-kind"} {
		t.Run(kind, func(t *testing.T) {
			_, receiver, request, rawPeer := actualPullRig(t, 2)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			raw, _ := json.Marshal(request)
			digest := sha256.Sum256(raw)
			f := fabric.InvocationFrame{InvocationID: request.Proof.Frame.InvocationID, Sequence: 0, Kind: fabric.FrameStart}
			switch kind {
			case "wrong-id":
				f.InvocationID = "unrelated-original"
			case "skip":
				f.Sequence = 5
			case "wrong-page-digest":
				digest[0] ^= 1
			case "premature-complete":
				f.Kind = fabric.FrameComplete
			case "unknown-kind":
				f.Kind = "fabricated.done"
			}
			payload, _ := json.Marshal(struct {
				RequestDigest [32]byte               `json:"requestDigest"`
				Frame         fabric.InvocationFrame `json:"frame"`
			}{digest, f})
			sent := make(chan error, 1)
			go func() { sent <- rawPeer.Send(ctx, append([]byte{6}, payload...)) }()
			if got, e := receiver.Receive(ctx); e == nil || got.InvocationID != "" {
				t.Fatal("untrusted original frame became visible", e)
			}
			select {
			case <-sent:
			case <-time.After(time.Second):
				t.Fatal("rejected frame did not join peer writer")
			}
		})
	}
}

func TestActualEncryptedPullTerminalEvidenceStaysDistinctFromCompletion(t *testing.T) {
	for _, kind := range []fabric.FrameKind{fabric.FrameComplete, fabric.FrameError} {
		t.Run(string(kind), func(t *testing.T) {
			sender, receiver, r := actualPullChannels(t, 4)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				done <- sender.Send(ctx, fabric.InvocationFrame{InvocationID: r.Proof.Frame.InvocationID, Sequence: 0, Kind: fabric.FrameStart})
			}()
			if _, e := receiver.Receive(ctx); e != nil {
				t.Fatal(e)
			}
			if e := <-done; e != nil {
				t.Fatal(e)
			}
			terminal := fabric.InvocationFrame{InvocationID: r.Proof.Frame.InvocationID, Sequence: 1, Kind: kind}
			if kind == fabric.FrameError {
				terminal.Error = fabric.NewError(fabric.CodeCancelled, "actual source stop evidence fixture")
			}
			go func() { done <- sender.Send(ctx, terminal) }()
			got, e := receiver.Receive(ctx)
			if e != nil || got.Kind != kind || kind == fabric.FrameError && got.Error == nil {
				t.Fatal("terminal evidence changed", e)
			}
			if e = <-done; e != nil {
				t.Fatal(e)
			}
			if got, e = receiver.Receive(ctx); !errors.Is(e, io.EOF) || got.Kind == fabric.FrameComplete {
				t.Fatal("page EOF inferred a new completion", e)
			}
			if e = sender.Send(ctx, fabric.InvocationFrame{InvocationID: r.Proof.Frame.InvocationID, Sequence: 2, Kind: fabric.FrameChunk, Data: []byte("after-terminal")}); e == nil {
				t.Fatal("content after terminal accepted")
			}
		})
	}
}
