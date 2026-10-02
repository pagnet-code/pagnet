package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/proc"
	"github.com/pagnet-code/pagnet/internal/session"
)

// ACPDriver owns one native ACP endpoint per managed conversation. Configuration
// is immutable after registration, allowing independent executable/auth profiles.
// Client filesystem and terminal RPCs are deliberately not advertised.
type ACPDriver struct {
	PlanSource                             string
	NativeEventObserverRegistrationFactory session.NativeEventObserverRegistrationFactory
	Binary, BinaryName                     string
	Runtime                                domain.RuntimeName
	Env, PrefixArgs, NativeDirs            []string
	StateDir, NativeHomeEnv                string
	StartupTimeout                         time.Duration
	Arguments                              func(*session.RuntimeSession) []string
	PrepareLaunch                          func(*session.RuntimeSession, []string, string) ([]string, error)
	Authenticate                           func([]string, []string) (string, error)
	life                                   lifecycleState
	mu                                     sync.Mutex
	endpoints                              map[string]*acpEndpoint
}
type acpEndpoint struct {
	tools          map[string]bool
	planSource     string
	resolutionGate sync.RWMutex
	retired        bool
	announced      bool
	observer       session.NativeEventObserver
	observedStart  bool
	conn           *acpConnection
	handle         *proc.Handle
	id, nativeID   string
	started        time.Time
	load           bool
	mu             sync.Mutex
	busy           bool
	turn           string
	permissions    map[string]acpPermission
	resolutions    chan *session.InteractionEvent
}
type acpPermission struct {
	raw     json.RawMessage
	turn    string
	id      json.RawMessage
	options map[string]string
}

func (d *ACPDriver) Name() domain.RuntimeName      { return d.Runtime }
func (d *ACPDriver) SetLifecycle(l proc.Lifecycle) { d.life.SetLifecycle(l) }
func (d *ACPDriver) Capabilities() session.Capabilities {
	return session.Capabilities{PersistentEndpoint: true, StructuredEvents: true, NativeSubmit: true, Interrupt: true, NativeInteractionObserve: true, RemoteInteractionResolve: true}
}
func (d *ACPDriver) SupportsRemoteResolve(kind string) bool { return kind == "permission" }
func (d *ACPDriver) binary() (string, error) {
	if d.Binary != "" {
		return exec.LookPath(d.Binary)
	}
	if p, err := exec.LookPath(d.BinaryName); err == nil {
		return p, nil
	}
	if self, err := os.Executable(); err == nil {
		if p, err := exec.LookPath(filepath.Join(filepath.Dir(self), d.BinaryName)); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("%s CLI not found on PATH", d.BinaryName)
}
func (d *ACPDriver) Available() bool            { _, ok := d.BinaryPath(); return ok }
func (d *ACPDriver) BinaryPath() (string, bool) { p, err := d.binary(); return p, err == nil }
func (d *ACPDriver) get(id string) *acpEndpoint {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.endpoints[id]
}
func (e *acpEndpoint) live() bool {
	select {
	case <-e.conn.done:
		return false
	default:
		return true
	}
}
func (d *ACPDriver) Live(id string) bool { e := d.get(id); return e != nil && e.live() }
func (d *ACPDriver) PID(id string) *int {
	e := d.get(id)
	if e == nil || !e.live() {
		return nil
	}
	p := e.handle.PID()
	return &p
}
func (d *ACPDriver) ActiveWork(id string) bool {
	e := d.get(id)
	if e == nil {
		return false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.busy || len(e.permissions) > 0 || len(e.tools) > 0
}
func (d *ACPDriver) Stop(id string) error {
	d.mu.Lock()
	e := d.endpoints[id]
	d.mu.Unlock()
	if e == nil {
		return nil
	}
	e.conn.close(io.EOF)
	if err := d.life.get().(proc.EndpointLifecycle).StopEndpoint(id); err != nil {
		return err
	}
	select {
	case <-e.conn.readerDone:
	case <-time.After(3 * time.Second):
		return errors.New("ACP native observer retirement is still pending")
	}
	_, err := e.handle.WaitDeadline(2 * time.Second)
	if err == nil {
		d.mu.Lock()
		if d.endpoints[id] == e {
			delete(d.endpoints, id)
		}
		d.mu.Unlock()
	}
	return err
}
func (d *ACPDriver) Hibernate(ctx context.Context, s *session.RuntimeSession) error {
	e := d.get(s.InstanceID)
	if e == nil {
		return nil
	}
	if d.ActiveWork(s.InstanceID) {
		return session.ErrBusy
	}
	if s.Materialised && !e.load {
		return errors.New("native ACP runtime does not advertise session loading; endpoint retained")
	}
	return d.Stop(s.InstanceID)
}
func (e *acpEndpoint) info(s *session.RuntimeSession) *session.RuntimeEndpoint {
	return &session.RuntimeEndpoint{ID: e.id, Runtime: s.Runtime, Ownership: session.OwnershipPagnet, Lease: session.LeaseClaimed, Healthy: e.live(), Transport: "stdio:acp", PID: e.handle.PID(), PGID: e.handle.PGID(), Sessions: []string{e.nativeID}, StartedAt: e.started}
}
func acpEmit(ctx context.Context, ch chan<- session.SessionEvent, event session.SessionEvent) bool {
	if ch == nil {
		return true
	}
	select {
	case ch <- event:
		return true
	case <-ctx.Done():
		return false
	}
}
func (d *ACPDriver) Activate(ctx context.Context, s *session.RuntimeSession, ch chan<- session.SessionEvent) (*session.RuntimeEndpoint, error) {
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
	bin, err := d.binary()
	if err != nil {
		return nil, err
	}
	env, state, native, err := d.launchState(s)
	if err != nil {
		return nil, err
	}
	if d.PrepareLaunch != nil {
		env, err = d.PrepareLaunch(s, env, state)
		if err != nil {
			return nil, err
		}
	}
	mcp, err := acpMCPServers(env)
	if err != nil {
		return nil, err
	}
	args := append([]string{}, d.PrefixArgs...)
	if d.Arguments != nil {
		args = append(args, d.Arguments(s)...)
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
		return nil, errors.New("ACP lifecycle does not support endpoints")
	}
	h, err := lif.Launch(context.Background(), proc.LaunchRequest{InstanceID: s.InstanceID, TurnID: "endpoint", Runtime: string(d.Name()), Class: proc.ClassEndpoint, Cmd: cmd, Marker: "PAGNET_INSTANCE_ID=" + s.InstanceID, Sandbox: driverSandbox(driverSandboxOpts{workspace: s.Workspace, stateDir: state, nativeDirs: native, binary: bin, env: env, denied: s.SandboxDenied})})
	if err != nil {
		in.Close()
		out.Close()
		return nil, err
	}
	registration := session.NativeEventObserverRegistration{}
	if d.NativeEventObserverRegistrationFactory != nil {
		registration = d.NativeEventObserverRegistrationFactory(s.InstanceID)
	}
	planSource := d.PlanSource
	if planSource == "" {
		planSource = "acp"
	}
	e := &acpEndpoint{planSource: planSource, observer: registration.Observe, handle: h, id: string(domain.NewID()), started: time.Now(), permissions: map[string]acpPermission{}, tools: map[string]bool{}, resolutions: make(chan *session.InteractionEvent, 32)}
	e.conn = newOwnedACPConnection(in, out, func() {
		e.resolutionGate.Lock()
		defer e.resolutionGate.Unlock()
		h.Abort("ACP native reader closed")
		if _, waitErr := h.WaitDeadline(2 * time.Second); waitErr == nil {
			e.mu.Lock()
			announced, native := e.announced, e.nativeID
			e.mu.Unlock()
			if announced && e.observer != nil {
				_ = e.observer(session.SessionEvent{Type: session.EventSessionStopped, SessionID: native})
			}
		}
		e.retired = true
		if registration.Retire != nil {
			registration.Retire()
		}
	}, e.captureNativeMessage)
	success := false
	defer func() {
		if !success {
			e.conn.close(io.EOF)
			_ = lif.StopEndpoint(s.InstanceID)
			_, _ = h.WaitDeadline(2 * time.Second)
		}
	}()
	startup, cancel := context.WithTimeout(ctx, effectiveStartupTimeout(d.StartupTimeout))
	defer cancel()
	var init struct {
		ProtocolVersion   int `json:"protocolVersion"`
		AgentCapabilities struct {
			LoadSession bool `json:"loadSession"`
		} `json:"agentCapabilities"`
		AuthMethods []struct {
			ID string `json:"id"`
		} `json:"authMethods"`
	}
	if err = e.conn.request(startup, "initialize", map[string]any{"protocolVersion": 1, "clientCapabilities": map[string]any{}, "clientInfo": map[string]string{"name": "pagnet", "version": "1.0.0"}}, &init); err != nil {
		return nil, fmt.Errorf("ACP initialize: %w", err)
	}
	if init.ProtocolVersion != 1 {
		return nil, errors.New("native ACP protocol version unsupported")
	}
	e.load = init.AgentCapabilities.LoadSession
	if d.Authenticate != nil {
		methods := []string{}
		for _, m := range init.AuthMethods {
			methods = append(methods, m.ID)
		}
		method, err := d.Authenticate(methods, env)
		if err != nil {
			return nil, err
		}
		if method != "" {
			if err = e.conn.request(startup, "authenticate", map[string]any{"methodId": method, "_meta": map[string]bool{"headless": true}}, nil); err != nil {
				return nil, fmt.Errorf("ACP authentication: %w", err)
			}
		}
	}
	cwd, err := filepath.Abs(s.Workspace)
	if err != nil {
		return nil, err
	}
	params := map[string]any{"cwd": cwd, "mcpServers": mcp}
	event := session.EventSessionStarted
	if s.NativeID != "" {
		if !e.load {
			return nil, session.ErrSessionLost
		}
		params["sessionId"] = s.NativeID
		if err = e.conn.request(startup, "session/load", params, nil); err != nil {
			return nil, fmt.Errorf("%w: %v", session.ErrSessionLost, err)
		}
		e.mu.Lock()
		e.nativeID = s.NativeID
		e.mu.Unlock()
		event = session.EventSessionResumed
	} else {
		var result struct {
			SessionID string `json:"sessionId"`
		}
		if err = e.conn.request(startup, "session/new", params, &result); err != nil {
			return nil, fmt.Errorf("ACP session/new: %w", err)
		}
		if result.SessionID == "" || len(result.SessionID) > 4096 {
			return nil, errors.New("native ACP session ID invalid")
		}
		e.mu.Lock()
		e.nativeID = result.SessionID
		e.mu.Unlock()
	}
	s.NativeID = e.nativeID
	d.mu.Lock()
	if d.endpoints == nil {
		d.endpoints = map[string]*acpEndpoint{}
	}
	d.endpoints[s.InstanceID] = e
	d.mu.Unlock()
	success = true
	go func() {
		<-e.conn.done
		d.mu.Lock()
		current := d.endpoints[s.InstanceID] == e
		d.mu.Unlock()
		if current {
			e.handle.Abort("ACP transport closed")
		}
	}()
	activationEvent := session.SessionEvent{Type: event, SessionID: e.nativeID}
	e.resolutionGate.RLock()
	if e.observer != nil {
		err = e.observer(activationEvent)
	}
	if err == nil {
		e.mu.Lock()
		e.announced = true
		e.mu.Unlock()
	}
	e.resolutionGate.RUnlock()
	if err != nil {
		return nil, err
	}
	acpEmit(ctx, ch, activationEvent)
	return e.info(s), nil
}

// Native homes are confined to a dedicated runtime subtree, never the daemon
// credential root or a user's existing global Grok account directory.
func (d *ACPDriver) launchState(s *session.RuntimeSession) ([]string, string, []string, error) {
	if _, err := uuid.Parse(s.InstanceID); err != nil {
		return nil, "", nil, errors.New("invalid ACP instance ID")
	}
	root := d.StateDir
	if root == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, "", nil, err
		}
		root = filepath.Join(home, ".pagnet")
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, "", nil, err
	}
	base := filepath.Join(root, "runtimes", string(d.Runtime))
	state := filepath.Join(base, s.InstanceID)
	nativeHome := filepath.Join(state, "home")
	env := ChildEnv(d.Env, s.Env)
	for _, entry := range env {
		if value, ok := strings.CutPrefix(entry, d.NativeHomeEnv+"="); ok {
			nativeHome = value
		}
	}
	native := append([]string{}, d.NativeDirs...)
	native = append(native, nativeHome)
	for _, path := range append(native, state) {
		abs, err := filepath.Abs(path)
		if err != nil {
			return nil, "", nil, err
		}
		rel, err := filepath.Rel(base, abs)
		if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return nil, "", nil, errors.New("ACP native state must stay inside its dedicated runtime subtree")
		}
		if err = os.MkdirAll(abs, 0700); err != nil {
			return nil, "", nil, err
		}
		real, err := filepath.EvalSymlinks(abs)
		if err != nil || real != abs {
			return nil, "", nil, errors.New("ACP native state symlink refused")
		}
	}
	scratch, err := ensureScratch(state)
	if err != nil {
		return nil, "", nil, err
	}
	env = ChildEnv(env, []string{d.NativeHomeEnv + "=" + nativeHome, "TMPDIR=" + scratch, "PAGNET_INSTANCE_ID=" + s.InstanceID})
	return env, state, native, nil
}

type acpMCPServer struct {
	Name    string   `json:"name"`
	Command string   `json:"command"`
	Args    []string `json:"args"`
	Env     []acpEnv `json:"env"`
}
type acpEnv struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func acpMCPServers(env []string) ([]acpMCPServer, error) {
	raw := pagnetMCPConfig(env)
	servers := []acpMCPServer{}
	if raw == "" {
		return servers, nil
	}
	var config struct {
		Servers map[string]struct {
			Command string            `json:"command"`
			Args    []string          `json:"args"`
			Env     map[string]string `json:"env"`
		} `json:"mcpServers"`
	}
	if json.Unmarshal([]byte(raw), &config) != nil || config.Servers == nil {
		return nil, errors.New("invalid native ACP MCP configuration")
	}
	names := []string{}
	for name := range config.Servers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		server := config.Servers[name]
		if name == "" || !filepath.IsAbs(server.Command) {
			return nil, errors.New("ACP MCP requires named absolute stdio commands")
		}
		entry := acpMCPServer{Name: name, Command: server.Command, Args: server.Args, Env: []acpEnv{}}
		if entry.Args == nil {
			entry.Args = []string{}
		}
		keys := []string{}
		for key := range server.Env {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			entry.Env = append(entry.Env, acpEnv{Name: key, Value: server.Env[key]})
		}
		servers = append(servers, entry)
	}
	return servers, nil
}
