package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

type nativeTerminalManager struct {
	mu       sync.Mutex
	captures map[string]*nativeTerminalCapture
}
type nativeTerminalCapture struct {
	mu       sync.Mutex
	proxy    *NativeWorkerProxy
	source   sessionworker.NativeSnapshot
	windows  map[string]*nativeTerminalWindow
	ring     []byte
	sequence uint64
	replay   string
	cursor   int64
	closed   bool
}

func (tm *terminalManager) nativeManager() *nativeTerminalManager {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	if tm.native == nil {
		tm.native = &nativeTerminalManager{captures: map[string]*nativeTerminalCapture{}}
	}
	return tm.native
}
func (d *Daemon) nativeTerminalCaptureFor(p *NativeWorkerProxy, snapshot sessionworker.NativeSnapshot) (*nativeTerminalCapture, error) {
	manager := d.terminal.nativeManager()
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if old := manager.captures[p.scope.InstanceID]; old != nil {
		if old.proxy == p && old.source.NativeGeneration == snapshot.NativeGeneration {
			return old, nil
		}
		old.close(d, "process_exited")
		delete(manager.captures, p.scope.InstanceID)
	}
	if len(manager.captures) >= 128 {
		return nil, errors.New("native terminal view capacity reached")
	}
	capture := &nativeTerminalCapture{proxy: p, source: snapshot, windows: map[string]*nativeTerminalWindow{}}
	manager.captures[p.scope.InstanceID] = capture
	go capture.run(d, manager)
	return capture, nil
}
func (c *nativeTerminalCapture) close(d *Daemon, reason string) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	windows := make([]*nativeTerminalWindow, 0, len(c.windows))
	for _, window := range c.windows {
		windows = append(windows, window)
	}
	c.windows = nil
	clear(c.ring)
	c.ring = nil
	c.mu.Unlock()
	for _, window := range windows {
		window.close()
		d.removeAttach(window.meta.InstanceID, window.meta.SessionID)
		if reason != "" {
			_ = d.nativeSendTerminal(window.conn, window.proxy, transport.MsgTerminalOutput, transport.TerminalOutputPayload{InstanceID: window.meta.InstanceID, SessionID: window.meta.SessionID, NativeGeneration: window.meta.NativeGeneration, SessionKeyID: window.meta.SessionKeyID, ClosedReason: reason})
		}
	}
}
func (c *nativeTerminalCapture) run(d *Daemon, manager *nativeTerminalManager) {
	defer func() {
		c.close(d, "process_exited")
		manager.mu.Lock()
		if manager.captures[c.proxy.scope.InstanceID] == c {
			delete(manager.captures, c.proxy.scope.InstanceID)
		}
		manager.mu.Unlock()
	}()
	timer := time.NewTicker(100 * time.Millisecond)
	defer timer.Stop()
	for {
		select {
		case <-c.proxy.done:
			return
		case <-d.turnCtx.Done():
			return
		case <-timer.C:
		}
		c.mu.Lock()
		closed := c.closed
		c.mu.Unlock()
		if closed {
			return
		}
		ctx, cancel := context.WithTimeout(d.turnCtx, 2*time.Second)
		snapshot, err := c.proxy.Snapshot(ctx)
		if err != nil || !snapshot.HasTerminal || snapshot.NativeGeneration != c.source.NativeGeneration || snapshot.NativeSessionID != c.source.NativeSessionID || snapshot.NativeStartIdentity != c.source.NativeStartIdentity || !bytes.Equal(snapshot.Origin, c.source.Origin) {
			cancel()
			return
		}
		// An idle native terminal must release keys on authority/epoch revoke
		// even when there are no new PTY bytes to trigger an output check.
		c.mu.Lock()
		views := make([]*nativeTerminalWindow, 0, len(c.windows))
		for _, window := range c.windows {
			views = append(views, window)
		}
		c.mu.Unlock()
		for _, window := range views {
			current, err := d.nativeWorkerFor(window.conn, window.meta.InstanceID)
			if err == nil && current != window.proxy {
				err = ErrNativeOriginAdmissionDeferred
			}
			if err == nil {
				window.mu.Lock()
				if !window.closed {
					err = window.currentEpoch(d)
				}
				window.mu.Unlock()
			}
			if err != nil {
				c.detach(d, window.meta.SessionID, "input_unavailable")
			}
		}
		for batch := 0; batch < 4; batch++ {
			page, err := c.proxy.NativeTerminalOutput(ctx, c.replay, c.cursor)
			if err != nil {
				cancel()
				return
			}
			if page.Gap && c.replay != "" {
				cancel()
				return
			}
			c.replay = page.ReplayGeneration
			for _, record := range page.Records {
				c.cursor = record.Sequence
				if record.Kind != "terminal" {
					continue
				}
				if record.NativeGeneration != c.source.NativeGeneration || !bytes.Equal(record.Origin, c.source.Origin) {
					continue
				}
				var data []byte
				if json.Unmarshal(record.Data, &data) != nil || len(data) == 0 || len(data) > terminalChunk {
					cancel()
					return
				}
				c.mu.Lock()
				if c.closed || c.sequence+uint64(len(data)) > e2ee.TerminalMaxSafeSequence {
					c.mu.Unlock()
					clear(data)
					cancel()
					return
				}
				c.sequence += uint64(len(data))
				sequence := c.sequence
				c.ring = append(c.ring, data...)
				if len(c.ring) > terminalRingCap {
					extra := len(c.ring) - terminalRingCap
					copy(c.ring, c.ring[extra:])
					clear(c.ring[terminalRingCap:])
					c.ring = c.ring[:terminalRingCap]
				}
				windows := make([]*nativeTerminalWindow, 0, len(c.windows))
				for _, window := range c.windows {
					windows = append(windows, window)
				}
				c.mu.Unlock()
				for _, window := range windows {
					frame, err := window.output(d, data, sequence, false)
					if errors.Is(err, ErrNativeOriginAdmissionDeferred) {
						continue
					}
					if err == nil {
						err = d.nativeSendTerminal(window.conn, c.proxy, transport.MsgTerminalOutput, frame)
					}
					if err != nil {
						c.detach(d, window.meta.SessionID, "input_unavailable")
					}
				}
				clear(data)
			}
			if len(page.Records) == 0 || c.cursor >= page.NextSequence-1 {
				break
			}
		}
		cancel()
	}
}
func (c *nativeTerminalCapture) detach(d *Daemon, session, reason string) {
	c.mu.Lock()
	window := c.windows[session]
	delete(c.windows, session)
	c.mu.Unlock()
	if window == nil {
		return
	}
	window.close()
	d.removeAttach(window.meta.InstanceID, session)
	if reason != "" {
		_ = d.nativeSendTerminal(window.conn, c.proxy, transport.MsgTerminalOutput, transport.TerminalOutputPayload{InstanceID: window.meta.InstanceID, SessionID: session, NativeGeneration: window.meta.NativeGeneration, SessionKeyID: window.meta.SessionKeyID, ClosedReason: reason})
	}
	// Restore the most recently requested remaining viewer geometry.
	c.mu.Lock()
	var latest *nativeTerminalWindow
	var size lastSize
	for _, other := range c.windows {
		other.mu.Lock()
		candidate := other.size
		other.mu.Unlock()
		if candidate.at.After(size.at) {
			latest = other
			size = candidate
		}
	}
	c.mu.Unlock()
	if latest != nil && size.rows > 0 {
		_ = latest.stream.Resize(size.rows, size.cols)
	}
}
func (d *Daemon) nativeTerminalWindowFor(conn *websocket.Conn, instance, session string) (*nativeTerminalCapture, *nativeTerminalWindow, error) {
	proxy, err := d.nativeWorkerFor(conn, instance)
	if err != nil {
		return nil, nil, err
	}
	manager := d.terminal.nativeManager()
	manager.mu.Lock()
	capture := manager.captures[instance]
	manager.mu.Unlock()
	if capture == nil || capture.proxy != proxy {
		return nil, nil, ErrNativeOriginAdmissionDeferred
	}
	capture.mu.Lock()
	window := capture.windows[session]
	capture.mu.Unlock()
	if window == nil || window.conn != conn {
		return nil, nil, ErrNativeOriginAdmissionDeferred
	}
	return capture, window, nil
}
func (d *Daemon) doNativeAttachTerminal(conn *websocket.Conn, p transport.TerminalAttachPayload) error {
	detached, err := d.state.TerminalDetached(p.InstanceID, p.SessionID)
	if err != nil {
		return err
	}
	if detached {
		return errors.New("terminal view was detached")
	}
	if err = d.nativeAcceptActivate(conn, p.InstanceID, p.NativeDispatch); err != nil {
		return err
	}
	proxy, err := d.nativeWorkerFor(conn, p.InstanceID)
	if err != nil {
		return errors.Join(ErrDeferred, err)
	}
	ctx, cancel := context.WithTimeout(d.turnCtx, 2*time.Second)
	defer cancel()
	snapshot, err := proxy.Snapshot(ctx)
	if err != nil {
		return errors.Join(ErrDeferred, err)
	}
	if !snapshot.HasTerminal {
		dispatches, dispatchErr := proxy.call(ctx, sessionworker.Request{Type: "dispatches"})
		if dispatchErr != nil {
			return ErrDeferred
		}
		operation, mappingErr := nativeDispatchOperationSequence(*p.NativeDispatch, dispatches.Dispatches)
		if mappingErr != nil {
			return ErrDeferred
		}
		response, callErr := proxy.call(ctx, sessionworker.Request{Type: "outcome", Sequence: operation})
		if callErr != nil || response.Outcome == nil || response.Outcome.State == "admitted" {
			return ErrDeferred
		}
		return errors.New("This runtime does not expose an original interactive terminal")
	}
	capture, err := d.nativeTerminalCaptureFor(proxy, snapshot)
	if err != nil {
		return err
	}
	capture.mu.Lock()
	existing := capture.windows[p.SessionID]
	capture.mu.Unlock()
	if existing != nil {
		return d.nativeTerminalSnapshot(conn, transport.TerminalSnapshotPayload{InstanceID: p.InstanceID, SessionID: p.SessionID})
	}
	record, err := d.nativeRegistry.Lookup(p.InstanceID)
	if err != nil {
		return err
	}
	stream, err := proxy.OpenNativeTerminalStream(ctx, record.Dir, snapshot.NativeGeneration)
	if err != nil {
		return errors.Join(ErrDeferred, err)
	}
	window, err := d.newNativeTerminalWindow(conn, proxy, p.SessionID, snapshot, stream)
	if err != nil {
		stream.Close()
		return err
	}
	capture.mu.Lock()
	if capture.closed || len(capture.windows) >= 32 {
		capture.mu.Unlock()
		window.close()
		return errors.New("native terminal viewer capacity reached")
	}
	if previous := capture.windows[p.SessionID]; previous != nil {
		capture.mu.Unlock()
		window.close()
		return ErrDeferred
	}
	capture.windows[p.SessionID] = window
	capture.mu.Unlock()
	detached, err = d.state.TerminalDetached(p.InstanceID, p.SessionID)
	if err != nil || detached {
		capture.detach(d, p.SessionID, "")
		return errors.New("terminal view was detached during activation")
	}
	if err = d.nativeSendTerminal(conn, proxy, transport.MsgTerminalSessionKey, window.meta); err != nil {
		capture.detach(d, p.SessionID, "")
		return err
	}
	// Hold the view lock through its first snapshot write: no live frame can
	// reach this socket before the receiver has its byte cursor.
	capture.mu.Lock()
	data := append([]byte(nil), capture.ring...)
	sequence := capture.sequence
	window.mu.Lock()
	frame, err := window.outputLocked(d, data, sequence, true)
	if err == nil {
		err = d.nativeSendTerminal(conn, proxy, transport.MsgTerminalOutput, frame)
	}
	clear(data)
	if err == nil && !window.closed {
		window.active = true
	}
	window.mu.Unlock()
	capture.mu.Unlock()
	if err != nil {
		capture.detach(d, p.SessionID, "")
		return err
	}
	d.addAttach(p.InstanceID, p.SessionID)
	return nil
}
func (d *Daemon) nativeTerminalSnapshot(conn *websocket.Conn, p transport.TerminalSnapshotPayload) error {
	capture, window, err := d.nativeTerminalWindowFor(conn, p.InstanceID, p.SessionID)
	if err != nil {
		return err
	}
	capture.mu.Lock()
	data := append([]byte(nil), capture.ring...)
	sequence := capture.sequence
	capture.mu.Unlock()
	defer clear(data)
	frame, err := window.output(d, data, sequence, true)
	if err != nil {
		return err
	}
	return d.nativeSendTerminal(conn, window.proxy, transport.MsgTerminalOutput, frame)
}
func (d *Daemon) nativeTerminalInput(conn *websocket.Conn, p transport.TerminalInputPayload) error {
	capture, window, err := d.nativeTerminalWindowFor(conn, p.InstanceID, p.SessionID)
	if err != nil {
		return err
	}
	if err = window.input(d, p); err != nil {
		capture.detach(d, p.SessionID, "input_unavailable")
	}
	return err
}
func (d *Daemon) nativeTerminalResize(conn *websocket.Conn, p transport.TerminalResizePayload) error {
	_, window, err := d.nativeTerminalWindowFor(conn, p.InstanceID, p.SessionID)
	if err != nil {
		return err
	}
	window.mu.Lock()
	defer window.mu.Unlock()
	if window.closed || !window.active {
		return ErrNativeOriginAdmissionDeferred
	}
	if err = window.currentEpoch(d); err != nil {
		return err
	}
	if err = window.stream.Resize(p.Rows, p.Cols); err == nil {
		window.size = lastSize{rows: p.Rows, cols: p.Cols, at: time.Now()}
	}
	return err
}
func (d *Daemon) nativeTerminalDetach(conn *websocket.Conn, p transport.DetachTerminalPayload) error {
	if _, err := d.nativeWorkerFor(conn, p.InstanceID); err != nil {
		return err
	}
	if err := d.state.MarkTerminalDetached(p.InstanceID, p.SessionID); err != nil {
		return err
	}
	capture, _, err := d.nativeTerminalWindowFor(conn, p.InstanceID, p.SessionID)
	if err == nil {
		capture.detach(d, p.SessionID, "")
	}
	return nil
}
func (d *Daemon) nativeTerminalStop(conn *websocket.Conn, p transport.TerminalStopPayload) error {
	if err := d.nativeAcceptOperation(conn, p.InstanceID, p.NativeDispatch, "hibernate", sessionworker.Operation{}); err != nil {
		return err
	}
	proxy, err := d.nativeWorkerFor(conn, p.InstanceID)
	if err != nil {
		return ErrDeferred
	}
	ctx, cancel := context.WithTimeout(d.turnCtx, time.Second)
	defer cancel()
	response, err := proxy.call(ctx, sessionworker.Request{Type: "outcome", Sequence: p.NativeDispatch.DispatchSequence})
	if err != nil || response.Outcome == nil || response.Outcome.State == "admitted" {
		return ErrDeferred
	}
	if response.Outcome.State != "completed" {
		return errors.New("Runtime is busy or could not safely hibernate")
	}
	manager := d.terminal.nativeManager()
	manager.mu.Lock()
	capture := manager.captures[p.InstanceID]
	manager.mu.Unlock()
	if capture != nil && capture.proxy == proxy {
		capture.close(d, "stopped")
	}
	return nil
}
func (tm *terminalManager) closeNative() {
	tm.mu.Lock()
	manager := tm.native
	tm.mu.Unlock()
	if manager == nil {
		return
	}
	manager.mu.Lock()
	captures := make([]*nativeTerminalCapture, 0, len(manager.captures))
	for _, capture := range manager.captures {
		captures = append(captures, capture)
	}
	manager.mu.Unlock()
	for _, capture := range captures {
		capture.close(tm.d, "")
	}
}
