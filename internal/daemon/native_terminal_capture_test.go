package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/internal/sessionworker"
)

type captureReplayWorker struct {
	replay    *sessionworker.OutputReplay
	snapshots atomic.Int64
	outputs   atomic.Int64
}

func (w *captureReplayWorker) Snapshot(context.Context) (sessionworker.NativeSnapshot, error) {
	w.snapshots.Add(1)
	return sessionworker.NativeSnapshot{}, nil
}
func (w *captureReplayWorker) NativeTerminalOutput(_ context.Context, replay string, cursor int64) (sessionworker.OutputPage, error) {
	w.outputs.Add(1)
	return w.replay.Replay(replay, cursor, 64)
}
func (w *captureReplayWorker) append(t *testing.T, data []byte) {
	t.Helper()
	raw, _ := json.Marshal(data)
	if _, err := w.replay.Append("generation", nil, "terminal", raw); err != nil {
		t.Fatal(err)
	}
}
func captureForTest() (*nativeTerminalCapture, *captureReplayWorker) {
	w := &captureReplayWorker{replay: sessionworker.NewOutputReplay()}
	return &nativeTerminalCapture{worker: w, changed: make(chan struct{}, 1), windows: map[string]*nativeTerminalWindow{}, source: sessionworker.NativeSnapshot{NativeGeneration: "generation"}}, w
}
func waitNativeCapture(t *testing.T, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !ready() {
		if time.Now().After(deadline) {
			t.Fatal("capture did not reach expected state")
		}
		time.Sleep(time.Millisecond)
	}
}
func TestNativeTerminalCaptureDormancyAndViewers(t *testing.T) {
	c, w := captureForTest()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		c.watch(ctx, nil, func() error {
			if _, err := w.Snapshot(ctx); err != nil {
				return err
			}
			return c.readOutput(nil, ctx, true)
		})
	}()
	viewers := func(names ...string) {
		c.mu.Lock()
		c.windows = map[string]*nativeTerminalWindow{}
		for _, name := range names {
			c.windows[name] = nil
		}
		c.wake()
		c.mu.Unlock()
	}
	time.Sleep(230 * time.Millisecond)
	if w.snapshots.Load() != 0 || w.outputs.Load() != 0 {
		t.Fatal("dormant capture polled worker")
	}
	viewers("one", "two")
	waitNativeCapture(t, func() bool { return w.outputs.Load() > 0 })
	viewers("two")
	before := w.outputs.Load()
	waitNativeCapture(t, func() bool { return w.outputs.Load() > before })
	viewers()
	// Wait for any poll already holding the pump to complete.
	c.pump.Lock()
	c.pump.Unlock()
	snapshots, outputs := w.snapshots.Load(), w.outputs.Load()
	time.Sleep(230 * time.Millisecond)
	if w.snapshots.Load() != snapshots || w.outputs.Load() != outputs {
		t.Fatal("last detach left worker polling active")
	}
	viewers("resumed")
	waitNativeCapture(t, func() bool { return w.outputs.Load() > outputs })
	viewers()
	c.close(nil, "")
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("explicit close did not wake dormant capture")
	}
}
func TestNativeTerminalCaptureReplayResume(t *testing.T) {
	c, w := captureForTest()
	ctx := context.Background()
	first := []byte("before\x1b[")
	w.append(t, first)
	if err := c.readOutput(nil, ctx, true); err != nil {
		t.Fatal(err)
	}
	replay, cursor := c.replay, c.cursor
	// More than four pages must be drained before bootstrap, preserving split ANSI bytes.
	tail := []byte("31m\xe2\x98\x83")
	expected := append(append([]byte(nil), first...), tail...)
	w.append(t, tail)
	for i := 0; i < 300; i++ {
		w.append(t, []byte("x"))
		expected = append(expected, 'x')
	}
	if err := c.readOutput(nil, ctx, true); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(c.ring, expected) || c.sequence != uint64(len(expected)) || c.replay != replay || c.cursor <= cursor {
		t.Fatal("resume lost continuous replay or split bytes")
	}
	// Overflow worker retention while dormant. Only retained output belongs in bootstrap.
	oldSequence := c.sequence
	for i := 0; i < 8300; i++ {
		w.append(t, []byte("y"))
	}
	if err := c.readOutput(nil, ctx, true); err != nil {
		t.Fatal(err)
	}
	if len(c.ring) != 8192 || !bytes.Equal(c.ring, bytes.Repeat([]byte("y"), 8192)) {
		t.Fatal("gap concatenated stale and retained output")
	}
	if c.sequence != oldSequence+8192 {
		t.Fatal("gap reset output sequence")
	}
}
func TestNativeTerminalCaptureLiveGapRejected(t *testing.T) {
	c, w := captureForTest()
	w.append(t, []byte("old"))
	if err := c.readOutput(nil, context.Background(), true); err != nil {
		t.Fatal(err)
	}
	w.replay = sessionworker.NewOutputReplay()
	w.append(t, []byte("replacement"))
	c.windows["live"] = nil
	if err := c.readOutput(nil, context.Background(), false); err == nil {
		t.Fatal("live replay replacement silently accepted")
	}
}
func TestNativeTerminalCaptureShutdownWhileDormant(t *testing.T) {
	for _, reason := range []string{"proxy", "daemon"} {
		t.Run(reason, func(t *testing.T) {
			c, _ := captureForTest()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan struct{})
			finished := make(chan struct{})
			go func() {
				defer close(finished)
				c.watch(ctx, done, func() error { t.Error("dormant poll"); return nil })
			}()
			if reason == "proxy" {
				close(done)
			} else {
				cancel()
			}
			select {
			case <-finished:
			case <-time.After(time.Second):
				t.Fatal("shutdown did not wake dormant capture")
			}
		})
	}
}

func TestNativeTerminalCaptureBootstrapPrecedesLivePoll(t *testing.T) {
	c, w := captureForTest()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.append(t, []byte("snapshot\x1b["))
	c.pump.Lock()
	if err := c.readOutput(nil, ctx, true); err != nil {
		c.pump.Unlock()
		t.Fatal(err)
	}
	snapshot := append([]byte(nil), c.ring...)
	c.mu.Lock()
	c.windows["new"] = nil
	c.wake()
	c.mu.Unlock()
	polled := make(chan []byte, 1)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		c.watch(ctx, nil, func() error {
			page, err := w.NativeTerminalOutput(ctx, c.replay, c.cursor)
			if err != nil {
				return err
			}
			for _, record := range page.Records {
				c.cursor = record.Sequence
				var data []byte
				if err := json.Unmarshal(record.Data, &data); err != nil {
					return err
				}
				polled <- data
			}
			return nil
		})
	}()
	w.append(t, []byte("31m live"))
	select {
	case <-polled:
		c.pump.Unlock()
		t.Fatal("live output overtook bootstrap")
	case <-time.After(230 * time.Millisecond):
	}
	if string(snapshot) != "snapshot\x1b[" {
		c.pump.Unlock()
		t.Fatal("bootstrap missed replay catch-up")
	}
	c.pump.Unlock()
	select {
	case live := <-polled:
		if string(live) != "31m live" {
			t.Fatal("live replay lost bytes")
		}
	case <-time.After(time.Second):
		t.Fatal("live polling did not resume after bootstrap")
	}
	cancel()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("watch did not stop")
	}
}

// Append a full page after every fetch, so the reader can never reach the
// producer's current tail. Bootstrap must use its original high-water mark.
type producingCaptureWorker struct {
	*captureReplayWorker
	t *testing.T
}

func (w *producingCaptureWorker) NativeTerminalOutput(ctx context.Context, replay string, cursor int64) (sessionworker.OutputPage, error) {
	page, err := w.captureReplayWorker.NativeTerminalOutput(ctx, replay, cursor)
	for i := 0; i < 64; i++ {
		w.append(w.t, []byte("live"))
	}
	return page, err
}
func TestNativeTerminalCaptureBusyReplayBootstrap(t *testing.T) {
	c, w := captureForTest()
	for i := 0; i < 300; i++ {
		w.append(t, []byte("snapshot"))
	}
	c.worker = &producingCaptureWorker{captureReplayWorker: w, t: t}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c.pump.Lock()
	if err := c.readOutput(nil, ctx, true); err != nil {
		c.pump.Unlock()
		t.Fatal(err)
	}
	// The initial 300 records fit in five pages. The last complete page may
	// include new records; those bytes must be represented in the snapshot.
	if w.outputs.Load() != 5 || c.cursor != 320 {
		c.pump.Unlock()
		t.Fatalf("bootstrap chased producer: calls=%d cursor=%d", w.outputs.Load(), c.cursor)
	}
	snapshot := append([]byte(nil), c.ring...)
	sequence := c.sequence
	c.pump.Unlock()
	expected := append(bytes.Repeat([]byte("snapshot"), 300), bytes.Repeat([]byte("live"), 20)...)
	if !bytes.Equal(snapshot, expected) || sequence != uint64(len(expected)) {
		t.Fatal("bootstrap lost output at high-water mark")
	}
	// Bytes emitted during catch-up remain at the cursor for live polling.
	page, err := w.NativeTerminalOutput(ctx, c.replay, c.cursor)
	if err != nil || page.Gap || len(page.Records) != 64 || page.Records[0].Sequence != 321 {
		t.Fatal("bootstrap left a gap before live output", err)
	}
}

type replacingCaptureWorker struct {
	*captureReplayWorker
	t        *testing.T
	replaced bool
}

func (w *replacingCaptureWorker) NativeTerminalOutput(ctx context.Context, replay string, cursor int64) (sessionworker.OutputPage, error) {
	page, err := w.captureReplayWorker.NativeTerminalOutput(ctx, replay, cursor)
	if !w.replaced {
		w.replaced = true
		w.replay = sessionworker.NewOutputReplay()
		w.append(w.t, []byte("replacement"))
	}
	return page, err
}
func TestNativeTerminalCaptureReplayReplacementDuringBootstrap(t *testing.T) {
	c, w := captureForTest()
	for i := 0; i < 100; i++ {
		w.append(t, []byte("old"))
	}
	c.worker = &replacingCaptureWorker{captureReplayWorker: w, t: t}
	if err := c.readOutput(nil, context.Background(), true); err == nil {
		t.Fatal("bootstrap crossed replay generations using stale high-water mark")
	}
	if c.cursor != 64 || !bytes.Equal(c.ring, bytes.Repeat([]byte("old"), 64)) {
		t.Fatal("failed bootstrap mixed replay generations")
	}
	// A later attach can start a fresh catch-up and rebuild from the replacement.
	if err := c.readOutput(nil, context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if string(c.ring) != "replacement" {
		t.Fatal("retry retained stale bootstrap bytes")
	}
}
