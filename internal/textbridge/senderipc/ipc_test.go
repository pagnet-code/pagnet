//go:build linux || darwin

package senderipc

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/internal/localipc"
	"github.com/pagnet-code/pagnet/internal/localpeer"
	"github.com/pagnet-code/pagnet/internal/textbridge/sender"
	"github.com/pagnet-code/pagnet/sdk"
)

type ipcEndpoint struct {
	mu               sync.Mutex
	service, project string
	wires            map[string]sdk.PreparedSharingProjectMessage
	receipts         map[string]sdk.SharingProjectMessageReceipt
	prepares, sends  int
	ready            func(string)
	message          func(context.Context, sdk.SharingProjectMessage) error
	sent             chan string
}

func (e *ipcEndpoint) WhoAmI(context.Context) (*sdk.Identity, error) {
	return &sdk.Identity{Kind: "service", PrincipalID: e.service}, nil
}
func (e *ipcEndpoint) SharingProjectStatus(context.Context, string) (sdk.SharingProjectStatus, error) {
	return sdk.SharingProjectStatus{ProjectID: e.project, State: "active", EndpointProved: true}, nil
}
func (e *ipcEndpoint) PrepareSharingProjectMessageWithID(_, _, _, id string, _, _ []byte) (sdk.PreparedSharingProjectMessage, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.prepares++
	p := sdk.PreparedSharingProjectMessage{ID: id, Wire: []byte("wire:" + id)}
	e.wires[id] = p
	return p, nil
}
func (e *ipcEndpoint) LoadPreparedSharingProjectMessage(_, id string) (sdk.PreparedSharingProjectMessage, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if p, ok := e.wires[id]; ok {
		return p, nil
	}
	return sdk.PreparedSharingProjectMessage{}, os.ErrNotExist
}
func (e *ipcEndpoint) SharingProjectMessageReceipt(_ context.Context, _, id string) (sdk.SharingProjectMessageReceipt, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if r, ok := e.receipts[id]; ok {
		return r, nil
	}
	return sdk.SharingProjectMessageReceipt{}, os.ErrNotExist
}
func (e *ipcEndpoint) SendPreparedSharingProjectMessage(_ context.Context, _, id string) (sdk.SharingProjectMessageReceipt, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.sends++
	sum := sha256.Sum256(e.wires[id].Wire)
	r := sdk.SharingProjectMessageReceipt{MessageID: id, RequestDigest: sum[:], AdmissionSeq: 1, CreatedAt: time.Now().UTC(), Status: "pending"}
	e.receipts[id] = r
	e.sent <- id
	return r, nil
}
func (e *ipcEndpoint) OnSharingProjectMessage(h func(context.Context, sdk.SharingProjectMessage) error) {
	e.message = h
}
func (e *ipcEndpoint) OnSharingProjectReady(h func(string)) { e.ready = h }
func (e *ipcEndpoint) EnableSharingProjects()               { e.ready(e.project) }
func (e *ipcEndpoint) Done() <-chan struct{}                { return nil }
func (e *ipcEndpoint) reply(t *testing.T, req Request) {
	t.Helper()
	id, _ := uuid.NewV7()
	if err := e.message(context.Background(), sdk.SharingProjectMessage{Header: sdk.SharingProjectMessageHeader{Kind: "REPLY", ProjectID: req.ProjectID, ID: id.String(), ThreadID: req.AskID, CorrelationID: &req.AskID, SenderPrincipalID: req.RecipientID, RecipientPrincipalID: e.service}, Plaintext: []byte("answer"), Wire: []byte("authenticated reply")}); err != nil {
		t.Fatal(err)
	}
}

type ipcFixture struct {
	state      string
	server     *Server
	controller *sender.Controller
	endpoint   *ipcEndpoint
	request    Request
	cancel     context.CancelFunc
	done       chan error
}

func newIPCFixture(t *testing.T) *ipcFixture {
	t.Helper()
	state, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(state, 0700); err != nil {
		t.Fatal(err)
	}
	server, err := Listen(state)
	if err != nil {
		t.Fatal(err)
	}
	binding := Binding{Server: "https://example.com", TenantID: uuid.NewString(), OwnerUserID: uuid.NewString(), HostID: uuid.NewString(), InstallationID: uuid.NewString(), ServiceID: uuid.NewString()}
	store, err := sender.Open(filepath.Join(state, "operations"), sender.Binding{ServiceOrigin: binding.Server, PrincipalID: binding.ServiceID})
	if err != nil {
		t.Fatal(err)
	}
	project := uuid.NewString()
	ask, _ := uuid.NewV7()
	req := Request{Version: Version, Binding: binding, Action: "ask", ProjectID: project, AskID: ask.String(), RecipientID: uuid.NewString(), Prompt: "question", WaitMillis: 1000}
	endpoint := &ipcEndpoint{service: binding.ServiceID, project: project, wires: map[string]sdk.PreparedSharingProjectMessage{}, receipts: map[string]sdk.SharingProjectMessageReceipt{}, sent: make(chan string, 16)}
	ready := make(chan struct{})
	controller := sender.NewController(store, endpoint, binding.ServiceID, sender.ControllerConfig{Enabled: func(string) bool { return true }, OnReady: func(c *sender.Controller) func() {
		cleanup, err := server.Publish(binding, c)
		if err != nil {
			t.Error(err)
		}
		close(ready)
		return cleanup
	}})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- controller.Run(ctx) }()
	<-ready
	f := &ipcFixture{state: state, server: server, controller: controller, endpoint: endpoint, request: req, cancel: cancel, done: done}
	t.Cleanup(func() { cancel(); <-done; server.Close(); store.Close() })
	return f
}
func awaitIPC(t *testing.T, ch <-chan string) string {
	t.Helper()
	select {
	case id := <-ch:
		return id
	case <-time.After(time.Second):
		t.Fatal("IPC did not reserve and send")
		return ""
	}
}
func TestIPCOnlineAskResumeResultAndLostAcceptedResponse(t *testing.T) {
	f := newIPCFixture(t)
	path, _ := localipc.TextSenderSocketPath(f.state)
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := localpeer.Owner(conn); err != nil {
		t.Fatal("same-owner server peer rejected", err)
	}
	if err := writeFrame(conn, f.request); err != nil {
		t.Fatal(err)
	}
	if id := awaitIPC(t, f.endpoint.sent); id != f.request.AskID {
		t.Fatal("changed ASK")
	}
	conn.Close() // Accepted operation survives loss of its response.
	f.endpoint.reply(t, f.request)
	op, err := Call(context.Background(), f.state, f.request)
	if err != nil || op.AskID != f.request.AskID || op.Reply == nil {
		t.Fatalf("lost response retry: %+v %v", op, err)
	}
	for _, action := range []string{"resume", "result"} {
		req := f.request
		req.Action = action
		req.Prompt = ""
		req.RecipientID = ""
		if action == "result" {
			req.WaitMillis = 0
		}
		got, err := Call(context.Background(), f.state, req)
		if err != nil || got.Reply == nil || got.Reply.Text != "answer" {
			t.Fatalf("%s: %+v %v", action, got, err)
		}
	}
	f.endpoint.mu.Lock()
	defer f.endpoint.mu.Unlock()
	if f.endpoint.prepares != 1 || f.endpoint.sends != 1 {
		t.Fatal("retry generated duplicate ciphertext/admission")
	}
}
func TestIPCBindingAndConflictGates(t *testing.T) {
	f := newIPCFixture(t)
	for _, field := range []string{"server", "tenant", "owner", "host", "installation", "service"} {
		t.Run(field, func(t *testing.T) {
			req := f.request
			switch field {
			case "server":
				req.Binding.Server = "https://elsewhere.example"
			case "tenant":
				req.Binding.TenantID = uuid.NewString()
			case "owner":
				req.Binding.OwnerUserID = uuid.NewString()
			case "host":
				req.Binding.HostID = uuid.NewString()
			case "installation":
				req.Binding.InstallationID = uuid.NewString()
			case "service":
				req.Binding.ServiceID = uuid.NewString()
			}
			if _, err := Call(context.Background(), f.state, req); !errors.Is(err, ErrUnavailable) {
				t.Fatal("wrong binding accepted", err)
			}
		})
	}
	if _, err := f.controller.ReserveWithID(context.Background(), f.request.ProjectID, f.request.RecipientID, f.request.AskID, f.request.Prompt); err != nil {
		t.Fatal(err)
	}
	awaitIPC(t, f.endpoint.sent)
	for _, field := range []string{"project", "recipient", "prompt"} {
		req := f.request
		switch field {
		case "project":
			req.ProjectID = uuid.NewString()
		case "recipient":
			req.RecipientID = uuid.NewString()
		case "prompt":
			req.Prompt = "different"
		}
		if _, err := Call(context.Background(), f.state, req); !errors.Is(err, sender.ErrConflict) {
			t.Fatal("same ASK substitution accepted", field, err)
		}
	}
}
func TestIPCStrictBoundedFrames(t *testing.T) {
	f := newIPCFixture(t)
	raw, _ := json.Marshal(f.request)
	for _, frame := range []string{`{"version":1,"version":1}` + "\n", strings.Replace(string(raw), `"version":1`, `"version":1,"unknown":true`, 1) + "\n", strings.Replace(string(raw), `"version":1`, `"version":2`, 1) + "\n", strings.Repeat("x", MaxFrame+1) + "\n", string(raw) + " trailing\n", `{"version":1` + "\n"} {
		path, _ := localipc.TextSenderSocketPath(f.state)
		conn, err := net.Dial("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		conn.SetDeadline(time.Now().Add(time.Second))
		_, _ = conn.Write([]byte(frame))
		var one [1]byte
		if n, err := conn.Read(one[:]); err == nil || n != 0 {
			t.Fatal("invalid frame received response")
		}
		conn.Close()
	}
	if _, err := f.controller.Get(context.Background(), f.request.ProjectID, f.request.AskID); !errors.Is(err, sender.ErrNotFound) {
		t.Fatal("invalid frame reserved work", err)
	}
	// Unsupported peers cannot reach JSON handling, even if they send a valid frame.
	left, right := net.Pipe()
	exited := make(chan struct{})
	go func() { f.server.serve(left); left.Close(); close(exited) }()
	right.SetDeadline(time.Now().Add(time.Second))
	_, _ = right.Write(raw)
	right.Close()
	select {
	case <-exited:
	case <-time.After(time.Second):
		t.Fatal("non-Unix peer was not rejected")
	}
}
func TestIPCUnpublishJoinsWaitersAndRefusesDuplicateListener(t *testing.T) {
	f := newIPCFixture(t)
	if duplicate, err := Listen(f.state); err == nil {
		duplicate.Close()
		t.Fatal("duplicate listener replaced active socket")
	}
	req := f.request
	req.WaitMillis = MaxWait.Milliseconds()
	result := make(chan error, 1)
	go func() { _, err := Call(context.Background(), f.state, req); result <- err }()
	awaitIPC(t, f.endpoint.sent)
	f.cancel()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("revoked publication returned operation")
		}
	case <-time.After(time.Second):
		t.Fatal("unpublish did not join request")
	}
	if _, err := Call(context.Background(), f.state, f.request); !errors.Is(err, ErrUnavailable) {
		t.Fatal("revoked controller stayed published", err)
	}
}
func TestIPCSocketPathGuards(t *testing.T) {
	for _, kind := range []string{"public directory", "symlink directory", "regular file", "symlink socket", "public socket"} {
		t.Run(kind, func(t *testing.T) {
			state, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(state, 0700); err != nil {
				t.Fatal(err)
			}
			if kind == "public directory" {
				if err := os.Chmod(state, 0755); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "symlink directory" {
				link := filepath.Join(filepath.Dir(state), "sender-link")
				if err := os.Symlink(state, link); err != nil {
					t.Fatal(err)
				}
				defer os.Remove(link)
				state = link
			}
			path := filepath.Join(state, localipc.TextSenderSocketName)
			switch kind {
			case "regular file":
				if err := os.WriteFile(path, []byte("keep"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink socket":
				target := filepath.Join(state, "target")
				if err := os.WriteFile(target, []byte("keep"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			case "public socket":
				listener, err := net.Listen("unix", path)
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				if err := os.Chmod(path, 0666); err != nil {
					t.Fatal(err)
				}
			}
			if server, err := Listen(state); err == nil {
				server.Close()
				t.Fatal("unsafe socket path accepted")
			}
			if kind == "regular file" {
				raw, err := os.ReadFile(path)
				if err != nil || string(raw) != "keep" {
					t.Fatal("regular path was clobbered", err)
				}
			}
		})
	}
}

func TestIPCBoundedConnectionsAndAbandonedWait(t *testing.T) {
	f := newIPCFixture(t)
	path, _ := localipc.TextSenderSocketPath(f.state)
	var pending []net.Conn
	defer func() {
		for _, conn := range pending {
			conn.Close()
		}
	}()
	for range cap(f.server.slots) {
		conn, err := net.Dial("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		pending = append(pending, conn)
	}
	deadline := time.Now().Add(time.Second)
	for len(f.server.slots) < cap(f.server.slots) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(f.server.slots) != cap(f.server.slots) {
		t.Fatal("connections not bounded at configured cap")
	}
	extra, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	extra.SetReadDeadline(time.Now().Add(time.Second))
	var one [1]byte
	if _, err := extra.Read(one[:]); err == nil {
		t.Fatal("over-cap connection retained")
	}
	extra.Close()
	for _, conn := range pending {
		conn.Close()
	}
	pending = nil
	deadline = time.Now().Add(time.Second)
	for len(f.server.slots) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(f.server.slots) != 0 {
		t.Fatal("abandoned frame readers kept slots")
	}
	req := f.request
	req.WaitMillis = MaxWait.Milliseconds()
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeFrame(conn, req); err != nil {
		t.Fatal(err)
	}
	awaitIPC(t, f.endpoint.sent)
	conn.Close()
	deadline = time.Now().Add(time.Second)
	for len(f.server.slots) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(f.server.slots) != 0 {
		t.Fatal("abandoned operation wait kept handler slot")
	}
}

func TestIPCFrameReadDeadline(t *testing.T) {
	f := newIPCFixture(t)
	path, _ := localipc.TextSenderSocketPath(f.state)
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(frameTimeout + time.Second))
	var one [1]byte
	n, readErr := conn.Read(one[:])
	if n != 0 || readErr == nil {
		t.Fatal("unframed idle connection survived read deadline")
	}
	if timeout, ok := readErr.(net.Error); ok && timeout.Timeout() {
		t.Fatal("client deadline fired before server bounded frame read")
	}
}

func TestIPCReplacesOnlyStaleOwnedSocket(t *testing.T) {
	state, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(state, 0700); err != nil {
		t.Fatal(err)
	}
	path, err := localipc.TextSenderSocketPath(state)
	if err != nil {
		t.Fatal(err)
	}
	stale, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	stale.SetUnlinkOnClose(false)
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	stale.Close()
	server, err := Listen(state)
	if err != nil {
		t.Fatal("safe stale socket not recovered", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != "replacement" {
		t.Fatal("shutdown removed replacement path", err)
	}
}
