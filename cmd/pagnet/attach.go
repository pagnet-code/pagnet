package main

// `pagnet attach <agent>` — interactive attach to a managed agent on
// (possibly another) host, through the control-plane terminal proxy
// (addendum §6–§15). The worker attach is a real PTY: the CLI puts its
// own terminal in raw mode and mirrors bytes both ways
// (stdin → base64 "input" frames → daemon PTY; PTY output frames → stdout),
// forwards SIGWINCH as "resize" frames, and detaches on Ctrl-] (the PTY
// keeps running on the host — §10).
//
// Without a TTY (piped stdin) it degrades to line mode: each line is sent
// as input plus a newline — a scripting/smoke-testing path.

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// detachKey is the escape that leaves a raw-mode attach (tmux-style):
// it is consumed by the CLI, never forwarded to the PTY.
const detachKey = 0x1d // Ctrl-]

func attachCmd() *cobra.Command {
	var network, instanceID string
	cmd := &cobra.Command{
		Use:   "attach <agent>",
		Short: "Attach an interactive PTY terminal to a running agent",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newCLI("")
			if err != nil {
				return err
			}
			netID, _, err := c.resolveNetwork(network)
			if err != nil {
				return err
			}
			defID, inst, err := c.findInstance(netID, args[0], instanceID)
			if err != nil {
				return err
			}

			var att struct {
				AttachSessionID string `json:"attachSessionId"`
				WSTicket        string `json:"wsTicket"`
			}
			if err := c.post("/api/v1/networks/"+netID+"/agents/"+defID+"/instances/"+inst.ID+"/attach",
				map[string]any{}, &att); err != nil {
				return fmt.Errorf("attach: %w", err)
			}
			session := att.AttachSessionID

			u, err := url.Parse(c.base)
			if err != nil {
				return err
			}
			// wss only for an https control plane — never downgrade TLS
			// (the scheme must be read BEFORE it is rewritten).
			switch u.Scheme {
			case "https":
				u.Scheme = "wss"
			default:
				u.Scheme = "ws"
			}
			u.Path = "/api/v1/attach/" + session + "/ws"
			// The WS handshake carries the one-shot ticket issued with the
			// attach — never the long-lived token (SEC-004).
			u.RawQuery = "ticket=" + url.QueryEscape(att.WSTicket)
			ws, resp, err := websocket.DefaultDialer.Dial(u.String(), nil)
			if err != nil {
				return fmt.Errorf("attach WS: %v (status %v)", err, resp)
			}
			defer func() { _ = ws.Close() }()

			fd := int(os.Stdin.Fd())
			if term.IsTerminal(fd) {
				return runRawAttach(ws, fd)
			}
			return runLineAttach(ws)
		},
	}
	cmd.Flags().StringVarP(&network, "network", "n", "", "network of the agent (default: the saved/only network)")
	cmd.Flags().StringVar(&instanceID, "instance", "", "instance id (when the agent has several)")
	return cmd
}

// ptyFrame is one attach-WS frame (terminal bytes or control).
type ptyFrame struct {
	Type     string `json:"type"`
	Data     string `json:"data,omitempty"`
	Seq      uint64 `json:"seq,omitempty"`
	Snapshot bool   `json:"snapshot,omitempty"`
	LastSeq  uint64 `json:"lastSeq,omitempty"`
	Reason   string `json:"reason,omitempty"`
	Error    string `json:"error,omitempty"`
}

// outputPump drains the WS until it closes, writing PTY bytes to stdout.
// Returns the reason a "closed" frame carried, if any.
func outputPump(ws *websocket.Conn) (<-chan struct{}, func() string) {
	return outputPumpTo(ws, os.Stdout)
}

func outputPumpTo(ws *websocket.Conn, output io.Writer) (<-chan struct{}, func() string) {
	done, _, reason := outputPumpToReady(ws, output)
	return done, reason
}

func outputPumpToReady(ws *websocket.Conn, output io.Writer) (<-chan struct{}, <-chan struct{}, func() string) {
	done := make(chan struct{})
	snapshotReady := make(chan struct{})
	reason := ""
	var reasonMu sync.Mutex
	go func() {
		defer close(done)
		defer ws.Close()
		var lastSeq uint64
		var ready bool
		for {
			_, raw, err := ws.ReadMessage()
			if err != nil {
				return
			}
			var f ptyFrame
			if json.Unmarshal(raw, &f) != nil {
				continue
			}
			switch f.Type {
			case "terminal":
				// Sequence numbers count bytes, not frames. Validate before
				// advancing the cursor so corrupt data cannot hide lost output.
				const maxTerminalBytes = 256 * 1024 // daemon's bounded replay ring
				end := f.Seq
				if f.Snapshot {
					end = f.LastSeq
				}
				var invalid string
				var b []byte
				if len(f.Data) > base64.StdEncoding.EncodedLen(maxTerminalBytes) {
					invalid = "terminal output exceeds replay limit"
				} else {
					b, err = base64.StdEncoding.DecodeString(f.Data)
					if err != nil || len(b) > maxTerminalBytes || end < uint64(len(b)) {
						invalid = "invalid terminal output encoding or sequence"
					}
				}
				if invalid == "" {
					if !f.Snapshot && !ready {
						invalid = "terminal output arrived before its snapshot"
					} else if ready {
						if end <= lastSeq {
							continue
						}
						start := end - uint64(len(b))
						if start > lastSeq {
							invalid = "terminal output sequence gap; reconnect to restore the screen"
						} else {
							b = b[lastSeq-start:]
						}
					}
				}
				if invalid == "" {
					if n, writeErr := output.Write(b); writeErr != nil || n != len(b) {
						invalid = "terminal output write failed"
					}
				}
				if invalid != "" {
					reasonMu.Lock()
					reason = invalid
					reasonMu.Unlock()
					_ = ws.Close()
					return
				}
				if !ready {
					close(snapshotReady)
				}
				ready = true
				lastSeq = end
			case "closed":
				reasonMu.Lock()
				reason = f.Reason
				reasonMu.Unlock()
				return
			case "error":
				fmt.Fprintf(os.Stderr, "\nattach: %s\n", f.Error)
			}
		}
	}()
	return done, snapshotReady, func() string { reasonMu.Lock(); defer reasonMu.Unlock(); return reason }
}

// waitAttachReady prevents keystrokes and resizes from preceding PTY creation.
func waitAttachReady(ws *websocket.Conn, done, ready <-chan struct{}, reason func() string) error {
	select {
	case <-ready:
		return nil
	case <-done:
		if r := reason(); r != "" {
			return fmt.Errorf("attach: %s", r)
		}
		return fmt.Errorf("attach: terminal closed before its initial snapshot")
	case <-time.After(75 * time.Second):
		_ = ws.Close()
		return fmt.Errorf("attach: timed out waiting for the initial terminal snapshot")
	}
}

// newAttachWriter serializes input and resize frames: Gorilla permits only
// one concurrent writer, including write-deadline updates.
func newAttachWriter(ws *websocket.Conn) func(map[string]any) {
	var mu sync.Mutex
	return func(m map[string]any) {
		mu.Lock()
		defer mu.Unlock()
		if err := ws.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
			_ = ws.Close()
			return
		}
		if err := ws.WriteJSON(m); err != nil {
			_ = ws.Close()
		}
	}
}

// runRawAttach is the TTY path: raw stdin mirroring, SIGWINCH resizes,
// Ctrl-] to detach.
func runRawAttach(ws *websocket.Conn, fd int) (err error) {
	sendFrame := newAttachWriter(ws)
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return fmt.Errorf("raw terminal: %w", err)
	}
	defer func() { _ = term.Restore(fd, oldState) }()

	fmt.Fprintln(os.Stderr, "\nattached (Ctrl-] to detach; the PTY keeps running on the host)")

	done, ready, closedReason := outputPumpToReady(ws, os.Stdout)
	if err := waitAttachReady(ws, done, ready, closedReason); err != nil {
		return err
	}

	// Initial size, sent only after the PTY snapshot confirms readiness.
	if cols, rows, err := term.GetSize(fd); err == nil {
		sendFrame(map[string]any{
			"type": "resize", "cols": cols, "rows": rows,
		})
	}

	stopResize := watchTerminalResize(fd, func(cols, rows int) {
		sendFrame(map[string]any{"type": "resize", "cols": cols, "rows": rows})
	})
	defer stopResize()

	buf := make([]byte, 4096)
	for {
		n, rerr := os.Stdin.Read(buf)
		if n > 0 {
			b := buf[:n]
			// Detach key: consumed locally, not forwarded (a read may
			// carry it mid-chunk — forward only the prefix).
			if i := indexByte(b, detachKey); i >= 0 {
				if i > 0 {
					sendFrame(map[string]any{
						"type": "input", "data": base64.StdEncoding.EncodeToString(b[:i]),
					})
				}
				break
			}
			sendFrame(map[string]any{
				"type": "input", "data": base64.StdEncoding.EncodeToString(b),
			})
			continue
		}
		if rerr != nil {
			break // stdin gone (EOF / terminal closed)
		}
	}

	_ = ws.Close()
	// Drain briefly so trailing output lands before the screen is restored.
	deadline := time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) && !isDone(done) {
		time.Sleep(50 * time.Millisecond)
	}
	term.Restore(fd, oldState)
	if r := closedReason(); r != "" {
		fmt.Fprintf(os.Stderr, "terminal closed: %s\n", r)
	}
	fmt.Fprintln(os.Stderr, "detached")
	return nil
}

func isDone(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

// runLineAttach is the non-TTY path (piped stdin): each line is sent as
// input + newline; EOF detaches. No resize frames are sent (the PTY
// keeps its default size).
func runLineAttach(ws *websocket.Conn) (err error) {
	sendFrame := newAttachWriter(ws)
	fmt.Fprintln(os.Stderr, "attached (line mode; the PTY keeps running on the host)")
	done, ready, closedReason := outputPumpToReady(ws, os.Stdout)
	if err := waitAttachReady(ws, done, ready, closedReason); err != nil {
		return err
	}

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()
		sendFrame(map[string]any{
			"type": "input",
			"data": base64.StdEncoding.EncodeToString([]byte(line + "\n")),
		})
	}
	_ = ws.Close()
	deadline := time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) && !isDone(done) {
		time.Sleep(50 * time.Millisecond)
	}
	if r := closedReason(); r != "" {
		fmt.Fprintf(os.Stderr, "terminal closed: %s\n", r)
	}
	fmt.Fprintln(os.Stderr, "detached")
	return nil
}

func indexByte(b []byte, c byte) int {
	for i, x := range b {
		if x == c {
			return i
		}
	}
	return -1
}

// findInstance resolves an agent by name and picks its instance (the only
// one, or --instance).
func (c *cliCtx) findInstance(netID, agentName, instanceID string) (defID string, inst *struct {
	ID     string `json:"ID"`
	Status string `json:"Status"`
}, err error) {
	var agents []struct {
		ID   string `json:"ID"`
		Name string `json:"Name"`
	}
	if err := c.get("/api/v1/networks/"+netID+"/agents", &agents); err != nil {
		return "", nil, err
	}
	def := ""
	for _, a := range agents {
		if a.Name == agentName {
			def = a.ID
		}
	}
	if def == "" {
		return "", nil, fmt.Errorf("agent %q not found in this network", agentName)
	}
	var insts []struct {
		ID     string `json:"ID"`
		Status string `json:"Status"`
	}
	if err := c.get("/api/v1/networks/"+netID+"/agents/"+def+"/instances", &insts); err != nil {
		return "", nil, err
	}
	switch len(insts) {
	case 0:
		return "", nil, fmt.Errorf("agent %s has no instance (launch one first)", agentName)
	case 1:
		return def, &insts[0], nil
	}
	if instanceID == "" {
		fmt.Println("instances:")
		for _, i := range insts {
			fmt.Printf("  %s  %s\n", i.ID, i.Status)
		}
		return "", nil, fmt.Errorf("pick one with --instance")
	}
	for i := range insts {
		if insts[i].ID == instanceID {
			return def, &insts[i], nil
		}
	}
	return "", nil, fmt.Errorf("instance %s not found for %s", agentName, instanceID)
}
