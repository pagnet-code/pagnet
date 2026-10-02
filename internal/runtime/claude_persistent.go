package runtime

// The protocol follows Anthropic's official claude-agent-sdk-python transport
// and Query implementation: persistent stream-json stdin, initialize control
// request, user messages, can_use_tool requests and control_response. The
// endpoint is a machine plane; it does not advertise a second native TUI.
import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/proc"
	"github.com/pagnet-code/pagnet/internal/session"
)

type ClaudePersistent struct {
	Binary                                 string
	PrefixArgs, NativeDirs, Env            []string
	StateDir                               string
	StartupTimeout                         time.Duration
	NativeEventObserverRegistrationFactory session.NativeEventObserverRegistrationFactory
	life                                   lifecycleState
	mu                                     sync.Mutex
	endpoints                              map[string]*claudeEndpoint
}
type claudePermission struct {
	raw, input json.RawMessage
	turn       string
	resolving  bool
}
type claudeEndpoint struct {
	background     map[string]bool
	scheduler      bool
	resolutionGate sync.RWMutex
	retired        bool
	announced      bool
	h              *proc.Handle
	in             io.WriteCloser
	out            io.ReadCloser
	done           chan struct{}
	once           sync.Once
	writes         chan acpWrite
	events         chan session.SessionEvent
	controls       map[string]chan error
	permissions    map[string]claudePermission
	mu             sync.Mutex
	nativeID, turn string
	started        time.Time
	acknowledged   bool
	materialised   bool
	observer       session.NativeEventObserver
	retire         func()
	err            error
}

func NewClaudePersistent(binary string) *ClaudePersistent {
	return &ClaudePersistent{Binary: binary, endpoints: map[string]*claudeEndpoint{}}
}
func (d *ClaudePersistent) Name() domain.RuntimeName      { return domain.RuntimeClaudeCode }
func (d *ClaudePersistent) SetLifecycle(l proc.Lifecycle) { d.life.SetLifecycle(l) }
func (d *ClaudePersistent) Capabilities() session.Capabilities {
	return session.Capabilities{PersistentEndpoint: true, StructuredEvents: true, NativeSubmit: true, Interrupt: true, NativeInteractionObserve: true, RemoteInteractionResolve: true, ResumeExternalSession: true}
}
func (d *ClaudePersistent) SupportsRemoteResolve(kind string) bool { return kind == "permission" }
func (d *ClaudePersistent) Available() bool                        { return NewClaude(d.Binary).Available() }
func (d *ClaudePersistent) BinaryPath() (string, bool)             { return NewClaude(d.Binary).BinaryPath() }
func (d *ClaudePersistent) get(id string) *claudeEndpoint {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.endpoints[id]
}
func (e *claudeEndpoint) live() bool {
	select {
	case <-e.done:
		return false
	default:
		return true
	}
}
func (d *ClaudePersistent) Live(id string) bool { e := d.get(id); return e != nil && e.live() }
func (d *ClaudePersistent) PID(id string) *int {
	e := d.get(id)
	if e == nil || !e.live() {
		return nil
	}
	pid := e.h.PID()
	return &pid
}
func (d *ClaudePersistent) ActiveWork(id string) bool {
	e := d.get(id)
	if e == nil {
		return false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.turn != "" || len(e.permissions) > 0 || len(e.background) > 0 || e.scheduler
}
func (d *ClaudePersistent) Materialised(id string) bool {
	e := d.get(id)
	if e == nil {
		return false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.materialised
}
func (d *ClaudePersistent) Hibernate(ctx context.Context, s *session.RuntimeSession) error {
	if d.ActiveWork(s.InstanceID) {
		return session.ErrBusy
	}
	return d.Stop(s.InstanceID)
}
func (d *ClaudePersistent) Stop(id string) error {
	e := d.get(id)
	if e == nil {
		return nil
	}
	e.shutdown(io.EOF)
	lif := d.life.get().(proc.EndpointLifecycle)
	if err := lif.StopEndpoint(id); err != nil {
		return err
	}
	select {
	case <-e.done:
	case <-time.After(3 * time.Second):
		return errors.New("Claude native observer retirement is still pending")
	}
	if _, err := e.h.WaitDeadline(2 * time.Second); err != nil {
		return err
	}
	d.mu.Lock()
	if d.endpoints[id] == e {
		delete(d.endpoints, id)
	}
	d.mu.Unlock()
	return nil
}
func (e *claudeEndpoint) shutdown(err error) {
	e.once.Do(func() { e.mu.Lock(); e.err = err; e.mu.Unlock(); _ = e.in.Close(); _ = e.out.Close() })
}
func (e *claudeEndpoint) info(s *session.RuntimeSession) *session.RuntimeEndpoint {
	return &session.RuntimeEndpoint{ID: e.nativeID, Runtime: s.Runtime, Ownership: session.OwnershipPagnet, Lease: session.LeaseClaimed, Healthy: e.live(), Transport: "stdio:claude-stream-json", PID: e.h.PID(), PGID: e.h.PGID(), StartedAt: e.started, Sessions: []string{e.nativeID}}
}
func (d *ClaudePersistent) Activate(ctx context.Context, s *session.RuntimeSession, ch chan<- session.SessionEvent) (*session.RuntimeEndpoint, error) {
	if e := d.get(s.InstanceID); e != nil {
		if e.live() {
			return e.info(s), nil
		}
		if err := d.Stop(s.InstanceID); err != nil {
			return nil, err
		}
	}
	if s.NativeID != "" && !s.Materialised {
		return nil, session.ErrNotMaterialised
	}
	if _, err := uuid.Parse(s.InstanceID); err != nil {
		return nil, errors.New("invalid Claude instance identity")
	}
	bin, err := NewClaude(d.Binary).binary()
	if err != nil {
		return nil, err
	}
	root := d.StateDir
	if root == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		root = filepath.Join(home, ".pagnet")
	}
	state := filepath.Join(root, "runtimes", string(d.Name()), s.InstanceID)
	if err = os.MkdirAll(state, 0700); err != nil {
		return nil, err
	}
	scratch, err := ensureScratch(state)
	if err != nil {
		return nil, err
	}
	native := profileNativeDirs(d.NativeDirs, homeNativeDirs(".claude"))
	if err = ensureNativeDirs(native...); err != nil {
		return nil, err
	}
	env := ChildEnv(d.Env, s.Env)
	env = ChildEnv(env, []string{"TMPDIR=" + scratch, "PAGNET_INSTANCE_ID=" + s.InstanceID})
	id := s.NativeID
	resuming := id != ""
	if !resuming {
		id = uuid.NewString()
	}
	if _, err = uuid.Parse(id); err != nil {
		return nil, session.ErrSessionLost
	}
	args := append([]string{}, d.PrefixArgs...)
	args = append(args, "-p", "--verbose", "--input-format", "stream-json", "--output-format", "stream-json", "--permission-mode", "default", "--permission-prompt-tool", "stdio")
	if resuming {
		args = append(args, "--resume="+id)
	} else {
		args = append(args, "--session-id="+id)
	}
	if s.Model != "" {
		args = append(args, "--model", s.Model)
	}
	if s.StandingInstructions != "" {
		path := filepath.Join(state, "standing.md")
		if err = AtomicWriteFile(path, []byte(s.StandingInstructions), 0600); err != nil {
			return nil, err
		}
		args = append(args, "--append-system-prompt-file", path)
	}
	if mcp := pagnetMCPConfig(env); mcp != "" {
		if _, err = acpMCPServers(env); err != nil {
			return nil, err
		}
		args = append(args, "--mcp-config", mcp)
	}
	cmd := exec.Command(bin, args...)
	cmd.Dir = s.Workspace
	cmd.Env = env
	cmd.Stderr = io.Discard
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		in.Close()
		return nil, err
	}
	lif, ok := d.life.get().(proc.EndpointLifecycle)
	if !ok {
		in.Close()
		out.Close()
		return nil, errors.New("Claude lifecycle does not support owned endpoints")
	}
	h, err := lif.Launch(context.Background(), proc.LaunchRequest{InstanceID: s.InstanceID, TurnID: "endpoint", Runtime: string(d.Name()), Class: proc.ClassEndpoint, Cmd: cmd, Marker: "PAGNET_INSTANCE_ID=" + s.InstanceID, Sandbox: driverSandbox(driverSandboxOpts{workspace: s.Workspace, stateDir: state, nativeDirs: native, binary: bin, env: env, denied: s.SandboxDenied})})
	if err != nil {
		in.Close()
		out.Close()
		return nil, err
	}
	e := &claudeEndpoint{h: h, in: in, out: out, done: make(chan struct{}), writes: make(chan acpWrite, 16), events: make(chan session.SessionEvent, 128), controls: map[string]chan error{}, permissions: map[string]claudePermission{}, background: map[string]bool{}, nativeID: id, started: time.Now()}
	if d.NativeEventObserverRegistrationFactory != nil {
		r := d.NativeEventObserverRegistrationFactory(s.InstanceID)
		e.observer = r.Observe
		e.retire = r.Retire
	}
	go e.writeLoop()
	go e.readLoop()
	success := false
	defer func() {
		if !success {
			e.shutdown(errors.New("Claude initialize failed"))
			_ = lif.StopEndpoint(s.InstanceID)
			_, _ = h.WaitDeadline(2 * time.Second)
		}
	}()
	startup, cancel := context.WithTimeout(ctx, effectiveStartupTimeout(d.StartupTimeout))
	defer cancel()
	if err = e.control(startup, map[string]any{"subtype": "initialize", "hooks": nil}); err != nil {
		if resuming {
			return nil, fmt.Errorf("%w: Claude resume initialization failed", session.ErrSessionLost)
		}
		return nil, fmt.Errorf("Claude control initialize: %w", err)
	}
	s.NativeID = id
	d.mu.Lock()
	d.endpoints[s.InstanceID] = e
	d.mu.Unlock()
	success = true
	kind := session.EventSessionStarted
	if resuming {
		kind = session.EventSessionResumed
	}
	e.resolutionGate.RLock()
	activation := session.SessionEvent{Type: kind, SessionID: id}
	if err = e.publish(activation); err == nil {
		e.mu.Lock()
		e.announced = true
		e.mu.Unlock()
	}
	e.resolutionGate.RUnlock()
	if err != nil {
		return nil, err
	}
	if !acpEmit(ctx, ch, activation) {
		return nil, ctx.Err()
	}
	return e.info(s), nil
}
func (e *claudeEndpoint) send(ctx context.Context, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(raw) >= acpMaxFrame {
		return errors.New("Claude native frame exceeds protocol bound")
	}
	w := acpWrite{data: append(raw, '\n'), result: make(chan error, 1)}
	select {
	case e.writes <- w:
	case <-e.done:
		return io.EOF
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case err := <-w.result:
		return err
	case <-e.done:
		return io.EOF
	case <-ctx.Done():
		e.shutdown(ctx.Err())
		return session.ErrTurnInterrupted
	}
}
func (e *claudeEndpoint) writeLoop() {
	for {
		select {
		case <-e.done:
			return
		case w := <-e.writes:
			n, err := e.in.Write(w.data)
			if err == nil && n != len(w.data) {
				err = io.ErrShortWrite
			}
			w.result <- err
			if err != nil {
				e.shutdown(err)
				return
			}
		}
	}
}
func (e *claudeEndpoint) control(ctx context.Context, request any) error {
	id := uuid.NewString()
	response := make(chan error, 1)
	e.mu.Lock()
	e.controls[id] = response
	e.mu.Unlock()
	defer func() { e.mu.Lock(); delete(e.controls, id); e.mu.Unlock() }()
	if err := e.send(ctx, map[string]any{"type": "control_request", "request_id": id, "request": request}); err != nil {
		return err
	}
	select {
	case err := <-response:
		return err
	case <-e.done:
		return io.EOF
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (e *claudeEndpoint) publish(event session.SessionEvent) error {
	if e.observer != nil {
		if err := e.observer(event); err != nil {
			return err
		}
	}
	// Unsolicited native events are retained by the observer, never misattributed
	// to a later managed submit. Idle events do not fill the managed queue.
	if event.TurnID == "" {
		return nil
	}
	select {
	case e.events <- event:
		return nil
	default:
		return errors.New("Claude native event buffer overflow")
	}
}
func (e *claudeEndpoint) readLoop() {
	defer close(e.done)
	defer func() {
		e.resolutionGate.Lock()
		defer e.resolutionGate.Unlock()
		e.h.Abort("Claude native reader closed")
		if _, waitErr := e.h.WaitDeadline(2 * time.Second); waitErr == nil {
			e.mu.Lock()
			announced, native := e.announced, e.nativeID
			e.mu.Unlock()
			if announced && e.observer != nil {
				_ = e.observer(session.SessionEvent{Type: session.EventSessionStopped, SessionID: native})
			}
		}
		e.retired = true
		if e.retire != nil {
			e.retire()
		}
	}()
	defer e.shutdown(io.EOF)
	scanner := bufio.NewScanner(e.out)
	scanner.Buffer(make([]byte, 4096), acpMaxFrame)
	var plans claudePlanTracker
	for scanner.Scan() {
		raw := append(json.RawMessage(nil), scanner.Bytes()...)
		// request_id is snake case; decode the SDK's explicit wire field names.
		var wire struct {
			Type      string          `json:"type"`
			RequestID string          `json:"request_id"`
			Request   json.RawMessage `json:"request"`
			Response  struct {
				Subtype   string `json:"subtype"`
				RequestID string `json:"request_id"`
			} `json:"response"`
		}
		if json.Unmarshal(raw, &wire) != nil {
			e.shutdown(errors.New("Claude malformed protocol frame"))
			return
		}
		if wire.Type == "control_response" {
			e.mu.Lock()
			waiter := e.controls[wire.Response.RequestID]
			e.mu.Unlock()
			if waiter != nil {
				var err error
				if wire.Response.Subtype != "success" {
					err = errors.New("Claude control request rejected")
				}
				select {
				case waiter <- err:
				default:
					e.shutdown(errors.New("Claude duplicate control response"))
					return
				}
			}
			continue
		}
		e.mu.Lock()
		turn := e.turn
		e.mu.Unlock()
		if wire.Type == "control_request" {
			var request struct {
				Subtype, ToolName string
				Input             json.RawMessage
			}
			var fields struct {
				Subtype  string          `json:"subtype"`
				ToolName string          `json:"tool_name"`
				Input    json.RawMessage `json:"input"`
			}
			if json.Unmarshal(wire.Request, &fields) != nil || wire.RequestID == "" {
				e.shutdown(errors.New("Claude invalid control request"))
				return
			}
			request.Subtype = fields.Subtype
			request.ToolName = fields.ToolName
			request.Input = fields.Input
			if request.Subtype != "can_use_tool" {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				_ = e.send(ctx, map[string]any{"type": "control_response", "response": map[string]any{"subtype": "error", "request_id": wire.RequestID, "error": "Unsupported native control request"}})
				cancel()
				continue
			}
			if request.ToolName == "" || len(request.Input) == 0 {
				e.shutdown(errors.New("Claude invalid tool permission request"))
				return
			}
			if err := e.acknowledge(turn); err != nil {
				e.shutdown(err)
				return
			}
			e.mu.Lock()
			if len(e.permissions) >= 64 {
				e.mu.Unlock()
				e.shutdown(errors.New("Claude pending permission limit exceeded"))
				return
			}
			_, duplicate := e.permissions[wire.RequestID]
			if !duplicate {
				e.permissions[wire.RequestID] = claudePermission{raw: raw, input: append(json.RawMessage(nil), request.Input...), turn: turn}
			}
			e.mu.Unlock()
			if duplicate {
				e.shutdown(errors.New("Claude reused pending permission identity"))
				return
			}
			ev := session.SessionEvent{Type: session.EventInteractionStarted, SessionID: e.nativeID, TurnID: turn, Interaction: &session.InteractionEvent{NativeInteractionID: wire.RequestID, Kind: "permission", Summary: request.ToolName, NativePayload: raw, Options: []domain.RuntimeInteractionOption{{ID: "allow-once", Kind: "allow_once"}, {ID: "deny", Kind: "reject_once"}}}}
			if err := e.publish(ev); err != nil {
				e.shutdown(err)
				return
			}
			continue
		}
		if wire.Type == "control_cancel_request" {
			e.mu.Lock()
			p, ok := e.permissions[wire.RequestID]
			delete(e.permissions, wire.RequestID)
			e.mu.Unlock()
			if ok {
				if err := e.publish(session.SessionEvent{Type: session.EventInteractionResolved, SessionID: e.nativeID, TurnID: p.turn, Interaction: &session.InteractionEvent{NativeInteractionID: wire.RequestID, Kind: "permission", NativePayload: p.raw, Resolved: true, Decision: "cancelled"}}); err != nil {
					e.shutdown(err)
					return
				}
			}
			continue
		}
		var event claudeEvent
		if json.Unmarshal(raw, &event) != nil {
			e.shutdown(errors.New("Claude malformed native event"))
			return
		}
		if event.SessionID != "" && event.SessionID != e.nativeID {
			e.shutdown(session.ErrSessionLost)
			return
		}
		if event.Type == "system" {
			if err := e.observeBackground(raw, event); err != nil {
				e.shutdown(err)
				return
			}
		}
		if event.ParentID != "" {
			continue
		}
		if event.Type != "assistant" && event.Type != "result" && event.Type != "user" && event.Type != "system" {
			continue
		}
		if event.Type == "user" || event.Type == "assistant" || event.Type == "result" {
			if err := e.acknowledge(turn); err != nil {
				e.shutdown(err)
				return
			}
		}
		if event.SessionID == e.nativeID {
			if plan := plans.consume(event); plan != nil {
				if err := e.publish(session.SessionEvent{Type: session.EventPlanUpdated, SessionID: e.nativeID, TurnID: turn, Plan: plan}); err != nil {
					e.shutdown(err)
					return
				}
			}
		}
		switch event.Type {
		case "assistant":
			for _, part := range event.Message.Content {
				if part.Type == "tool_use" && (part.Name == "CronCreate" || part.Name == "ScheduleWakeup") {
					e.mu.Lock()
					e.scheduler = true
					e.mu.Unlock()
				}
				if part.Type == "text" && part.Text != "" {
					if err := e.publish(session.SessionEvent{Type: session.EventTurnOutput, SessionID: e.nativeID, TurnID: turn, Output: part.Text, Model: event.Message.Model}); err != nil {
						e.shutdown(err)
						return
					}
				}
			}
		case "result":
			if event.SessionID == "" {
				e.shutdown(errors.New("Claude result lacks session identity"))
				return
			}
			kind := session.EventTurnCompleted
			if event.IsError {
				kind = session.EventTurnFailed
			}
			ev := session.SessionEvent{Type: kind, SessionID: e.nativeID, TurnID: turn, Output: event.Result, Model: event.Model, InputTokens: &event.Usage.InputTokens, OutputTokens: &event.Usage.OutputTokens, CachedTokens: &event.Usage.CacheRead}
			if event.IsError {
				ev.FailureKind = "runtime_error"
				ev.Error = "Claude reported a failed native turn"
			}
			e.mu.Lock()
			if !event.IsError {
				e.materialised = true
			}
			e.mu.Unlock()
			if err := e.publish(ev); err != nil {
				e.shutdown(err)
				return
			}
			e.mu.Lock()
			if e.turn == turn {
				e.turn = ""
			}
			e.mu.Unlock()
		}
	}
}
func (d *ClaudePersistent) Submit(ctx context.Context, s *session.RuntimeSession, req session.SubmitRequest, ch chan<- session.SessionEvent) error {
	if err := session.ValidateSubmitRequest(req); err != nil {
		return err
	}
	e := d.get(s.InstanceID)
	if e == nil || !e.live() {
		return session.ErrEndpointGone
	}
	if req.Kind == session.SubmitInteraction {
		return e.resolve(ctx, req)
	}
	e.mu.Lock()
	if e.turn != "" {
		e.mu.Unlock()
		return session.ErrBusy
	}
	e.turn = req.TurnID
	e.acknowledged = false
	e.mu.Unlock()
	defer func() { e.mu.Lock(); e.turn = ""; e.mu.Unlock() }()
	if err := e.send(ctx, map[string]any{"type": "user", "message": map[string]string{"role": "user", "content": req.Input}, "parent_tool_use_id": nil, "session_id": e.nativeID}); err != nil {
		e.shutdown(err)
		e.h.Abort("Claude prompt delivery uncertain")
		return session.ErrTurnInterrupted
	}
	for {
		select {
		case event := <-e.events:
			if event.TurnID != req.TurnID {
				continue
			}
			if !acpEmit(ctx, ch, event) {
				e.cancel()
				return session.ErrTurnInterrupted
			}
			if event.Type == session.EventTurnCompleted || event.Type == session.EventTurnFailed {
				return nil
			}
		case <-e.done:
			for len(e.events) > 0 {
				event := <-e.events
				if event.TurnID == req.TurnID {
					if !acpEmit(ctx, ch, event) {
						return session.ErrTurnInterrupted
					}
					if event.Type == session.EventTurnCompleted || event.Type == session.EventTurnFailed {
						return nil
					}
				}
			}
			return session.ErrTurnInterrupted
		case <-ctx.Done():
			e.cancel()
			return session.ErrTurnInterrupted
		}
	}
}
func (e *claudeEndpoint) cancel() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = e.control(ctx, map[string]string{"subtype": "interrupt"})
	e.shutdown(context.Canceled)
	e.h.Abort("Claude managed turn cancelled")
}
func (e *claudeEndpoint) resolve(ctx context.Context, req session.SubmitRequest) error {
	e.resolutionGate.RLock()
	defer e.resolutionGate.RUnlock()
	if e.retired {
		return session.ErrEndpointGone
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	p, ok := e.permissions[req.InteractionID]
	if !ok || p.resolving {
		return errors.New("Claude permission is no longer pending")
	}
	behavior := "deny"
	if req.Decision != "cancel" && req.Decision != "deny" {
		if req.Answer != "allow-once" && req.Decision != "allow-once" && req.Decision != "proceed_once" {
			return errors.New("select an explicit Claude permission option")
		}
		behavior = "allow"
	}
	response := map[string]any{"behavior": behavior}
	if behavior == "allow" {
		response["updatedInput"] = p.input
	} else {
		response["message"] = "Permission denied by operator"
	}
	p.resolving = true
	e.permissions[req.InteractionID] = p
	// Do not hold the endpoint state lock during a potentially blocked write.
	e.mu.Unlock()
	err := e.send(ctx, map[string]any{"type": "control_response", "response": map[string]any{"subtype": "success", "request_id": req.InteractionID, "response": response}})
	e.mu.Lock()
	if err != nil {
		e.mu.Unlock()
		e.shutdown(err)
		e.mu.Lock()
		return err
	}
	delete(e.permissions, req.InteractionID)
	ev := session.SessionEvent{Type: session.EventInteractionResolved, SessionID: e.nativeID, TurnID: p.turn, Interaction: &session.InteractionEvent{NativeInteractionID: req.InteractionID, Kind: "permission", NativePayload: p.raw, Resolved: true, Decision: behavior, Answer: req.Answer}}
	e.mu.Unlock()
	err = e.publish(ev)
	e.mu.Lock()
	return err
}

func (e *claudeEndpoint) acknowledge(turn string) error {
	if turn == "" {
		return nil
	}
	e.mu.Lock()
	start := !e.acknowledged
	e.acknowledged = true
	e.mu.Unlock()
	if start {
		return e.publish(session.SessionEvent{Type: session.EventTurnStarted, SessionID: e.nativeID, TurnID: turn})
	}
	return nil
}

// Official SDK task lifecycle messages are positive evidence of background
// work. Missing/unrecognized patches never prove idle. Automatic suspension
// remains unadvertised because the wire does not enumerate all future jobs.
func (e *claudeEndpoint) observeBackground(raw json.RawMessage, event claudeEvent) error {
	switch event.Subtype {
	case "task_started", "task_progress", "task_notification", "task_updated":
	default:
		return nil
	}
	var task struct {
		ID     string `json:"task_id"`
		Status string `json:"status"`
		Patch  struct {
			Status string `json:"status"`
		} `json:"patch"`
	}
	if json.Unmarshal(raw, &task) != nil || task.ID == "" || len(task.ID) > 512 {
		return errors.New("Claude invalid native background task identity")
	}
	e.mu.Lock()
	known := e.background[task.ID]
	if event.SessionID == "" && !known {
		e.mu.Unlock()
		return nil
	}
	status := task.Status
	if event.Subtype == "task_updated" {
		status = task.Patch.Status
	}
	terminal := status == "completed" || status == "failed" || status == "stopped"
	if terminal {
		delete(e.background, task.ID)
	} else {
		if len(e.background) >= 64 && !known {
			e.mu.Unlock()
			return errors.New("Claude background task bound exceeded")
		}
		e.background[task.ID] = true
	}
	busy := len(e.background) > 0 || e.turn != "" || len(e.permissions) > 0 || e.scheduler
	e.mu.Unlock()
	kind := session.EventBusy
	if !busy {
		kind = session.EventIdle
	}
	return e.publish(session.SessionEvent{Type: kind, SessionID: e.nativeID})
}
