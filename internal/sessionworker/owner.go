package sessionworker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/creack/pty"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/internal/proc"
	agentruntime "github.com/pagnet-code/pagnet/internal/runtime"
	"github.com/pagnet-code/pagnet/internal/session"
)

// NativeSpec contains immutable host-local configuration. Env is memory-only:
// it is never encoded into the intent/output journal or sent to controllers.
type NativeSpec struct {
	Runtime                                  domain.RuntimeName
	Binary                                   string
	PrefixArgs, NativeDirs                   []string
	Env                                      []string `json:"-"`
	Workspace, Model, StandingInstructions   string
	MCPExecutable, NetworkID, Kind, TenantID string
	NetworkTenantID                          string
	ProtectedContext                         *e2ee.ProtectedContext
	ContextStateDir                          string
}

type Operation struct {
	SourceCommandID  string `json:"sourceCommandId,omitempty"`
	Input            string `json:"input,omitempty"`
	InputKind        string `json:"inputKind,omitempty"`
	NativeGeneration string `json:"nativeGeneration,omitempty"`
	NativeSessionID  string `json:"nativeSessionId,omitempty"`
	InteractionID    string `json:"interactionId,omitempty"`
	OptionID         string `json:"optionId,omitempty"`
	InspectionProof  string `json:"inspectionProof,omitempty"`
	Data             []byte `json:"data,omitempty"`
	Rows             uint16 `json:"rows,omitempty"`
	Cols             uint16 `json:"cols,omitempty"`
}

type NativeSnapshot struct {
	ActualRuntime       domain.RuntimeName   `json:"actualRuntime"`
	ProfileFingerprint  string               `json:"profileFingerprint"`
	Scope               Scope                `json:"scope"`
	NativeGeneration    string               `json:"nativeGeneration"`
	NativeStartIdentity string               `json:"nativeStartIdentity,omitempty"`
	NativeSessionID     string               `json:"nativeSessionId"`
	Origin              json.RawMessage      `json:"origin,omitempty"`
	PID                 int                  `json:"pid"`
	State               session.SessionState `json:"state"`
	Pending             []Inspection         `json:"pending,omitempty"`
	HasTerminal         bool                 `json:"hasTerminal"`
	PublicError         string               `json:"publicError,omitempty"`
}

type SessionOwner struct {
	cancel             context.CancelFunc
	wg                 sync.WaitGroup
	closing            bool
	ctx                context.Context
	journal            *Journal
	captureKey         []byte
	output             *OutputReplay
	spec               NativeSpec
	manager            *session.Manager
	driver             session.Driver
	supervisor         *proc.Supervisor
	sess               *session.RuntimeSession
	prompt             sync.Mutex
	terminalWrite      sync.Mutex
	mu                 sync.Mutex
	generation, nonce  string
	origin             json.RawMessage
	candidateCommandID string
	terminal           *os.File
	pending            map[string]*nativeApproval
	fatal              error
	nativeSink         bool
	observationBlocked error
	observationWaiters map[string]bool
	relay              *relayBroker
}

func NewSessionOwner(ctx context.Context, j *Journal, spec NativeSpec, controlKey []byte) (*SessionOwner, error) {
	if len(controlKey) != 32 {
		return nil, errors.New("worker private capture key missing")
	}
	if !filepath.IsAbs(spec.Workspace) || !filepath.IsAbs(spec.Binary) || !filepath.IsAbs(spec.MCPExecutable) || (spec.Kind != "worker" && spec.Kind != "representative") || (spec.Kind == "worker" && (spec.NetworkID == "" || spec.NetworkTenantID == "")) {
		return nil, errors.New("incomplete worker native scope or execution profile")
	}
	if spec.TenantID != j.scope.TenantID {
		return nil, errors.New("native tenant does not match immutable worker authority")
	}
	if err := agentruntime.ValidateExtraEnv(spec.Env); err != nil {
		return nil, err
	}
	if spec.ProtectedContext != nil && (spec.ProtectedContext.Validate() != nil || spec.ProtectedContext.HostID != j.scope.HostID || spec.ProtectedContext.TenantID != spec.TenantID || !filepath.IsAbs(spec.ContextStateDir)) {
		return nil, errors.New("worker inspection context does not match its owner")
	}
	spec.Env = append([]string(nil), spec.Env...)
	spec.NativeDirs = append([]string(nil), spec.NativeDirs...)
	spec.PrefixArgs = append([]string(nil), spec.PrefixArgs...)
	if spec.ProtectedContext != nil {
		copy := *spec.ProtectedContext
		spec.ProtectedContext = &copy
	}
	ctx, cancel := context.WithCancel(ctx)
	cfg := proc.DefaultConfig()
	cfg.StateDir = j.dir
	sup := proc.NewSupervisor(cfg, slog.New(slog.DiscardHandler))
	owner := &SessionOwner{ctx: ctx, cancel: cancel, journal: j, captureKey: append([]byte(nil), controlKey...), spec: spec, manager: session.NewManager(), supervisor: sup, pending: map[string]*nativeApproval{}, relay: newRelayBroker(j.scope, spec)}
	var driver session.Driver
	switch spec.Runtime {
	case domain.RuntimeFakePersistent:
		d := agentruntime.NewPersistentFake(spec.Binary)
		d.StateDir = filepath.Join(j.dir, "native-state")
		d.PTYSize = &pty.Winsize{Rows: 24, Cols: 80}
		d.PTYAvailable = owner.captureTerminal
		d.NativeEventObserverFactory = owner.nativeEventObserver
		owner.nativeSink = true
		driver = d
	case domain.RuntimeQwenCode:
		d := agentruntime.NewQwenPersistent(spec.Binary)
		d.StateDir = filepath.Join(j.dir, "native-state")
		d.PrefixArgs = spec.PrefixArgs
		d.NativeDirs = spec.NativeDirs
		d.PTYAvailable = owner.captureTerminal
		d.NativeEventObserverFactory = owner.nativeEventObserver
		owner.nativeSink = true
		driver = d
	case domain.RuntimeCodex:
		d := agentruntime.NewCodexPersistent(spec.Binary)
		d.StateDir = filepath.Join(j.dir, "native-state")
		d.PrefixArgs = spec.PrefixArgs
		d.NativeDirs = spec.NativeDirs
		d.PTYAvailable = owner.captureTerminal
		d.NativeEventObserverFactory = owner.nativeEventObserver
		owner.nativeSink = true
		driver = d
	case domain.RuntimeGrok:
		d := agentruntime.NewGrok(spec.Binary)
		d.StateDir = filepath.Join(j.dir, "native-state")
		d.PrefixArgs = spec.PrefixArgs
		d.NativeDirs = spec.NativeDirs
		driver = d
	default:
		cancel()
		sup.StopAll(5 * time.Second)
		return nil, errors.New("runtime has not migrated to the independently owned session boundary")
	}
	setter, ok := driver.(interface{ SetLifecycle(proc.Lifecycle) })
	if !ok {
		cancel()
		sup.StopAll(5 * time.Second)
		return nil, errors.New("runtime cannot transfer native process ownership")
	}
	setter.SetLifecycle(sup)
	owner.driver = driver
	owner.manager.RegisterDriver(&ownedDriver{Driver: driver, owner: owner})
	owner.sess = owner.manager.Session(j.scope.InstanceID, spec.Runtime, spec.Workspace)
	owner.manager.SetModel(owner.sess, spec.Model)
	owner.manager.SetStandingInstructions(owner.sess, spec.StandingInstructions)
	denied := []string{j.dir}
	if spec.ContextStateDir != "" {
		denied = append(denied, spec.ContextStateDir)
	}
	owner.manager.SetSandboxDenied(owner.sess, denied)
	return owner, nil
}

// Execute is called exactly once for a durable admission. Its goroutine belongs
// to the worker, never the authenticated controller connection's lifetime.
func (o *SessionOwner) Execute(out Outcome, payload json.RawMessage) {
	o.mu.Lock()
	if o.closing {
		o.mu.Unlock()
		o.finish(out.Sequence, nil, errors.New("session worker is stopping"))
		return
	}
	o.wg.Go(func() {
		var op Operation
		decoder := json.NewDecoder(bytes.NewReader(payload))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&op); err != nil {
			o.finish(out.Sequence, nil, errors.New("invalid native operation"))
			return
		}
		var result any
		var err error
		switch out.Kind {
		case "activate", "prompt":
			if !o.prompt.TryLock() {
				err = session.ErrBusy
				break
			}
			defer o.prompt.Unlock()
			o.mu.Lock()
			o.candidateCommandID = op.SourceCommandID
			fatal := o.fatal
			if fatal == nil {
				fatal = o.observationBlocked
			}
			o.mu.Unlock()
			if fatal != nil {
				err = errors.New("worker output persistence unavailable")
				break
			}
			events := make(chan session.SessionEvent, 64)
			drained := make(chan struct{})
			go func() {
				defer close(drained)
				for event := range events {
					if !o.nativeSink {
						o.observe(event)
					}
				}
			}()
			if out.Kind == "activate" {
				_, err = o.manager.EnsureActive(o.ctx, o.sess, events)
				close(events)

			} else {
				if op.Input == "" || len(op.Input) > 128<<10 {
					close(events)
					err = errors.New("invalid or oversized prompt")
				} else {
					result, err = o.manager.Submit(o.ctx, o.sess, session.SubmitRequest{TurnID: out.CommandID, Input: op.Input, InputKind: op.InputKind, Kind: session.SubmitPrompt}, events)
				}
			}
			<-drained
			if out.Kind == "activate" {
				result = o.Snapshot()
			}
		case "input":
			err = o.writeInput(op)
		case "resize":
			err = o.resize(op)
		case "resolve":
			err = o.resolveApproval(op)
		case "hibernate":
			if !o.prompt.TryLock() {
				err = session.ErrBusy
				break
			}
			defer o.prompt.Unlock()
			err = o.manager.Hibernate(o.ctx, o.sess)
		case "stop":
			err = o.manager.Stop(o.journal.scope.InstanceID)
		default:
			err = errors.New("unsupported native operation")
		}
		o.finish(out.Sequence, result, err)
	})
	o.mu.Unlock()
}
func (o *SessionOwner) finish(sequence int64, result any, err error) {
	state := "completed"
	if err != nil {
		state = "failed"
		if errors.Is(err, session.ErrTurnInterrupted) {
			state = "uncertain"
		}
		result = struct {
			Error string `json:"error"`
		}{err.Error()}
	}
	raw, marshalErr := json.Marshal(result)
	if marshalErr != nil {
		state = "uncertain"
		raw = json.RawMessage(`{"error":"native outcome could not be encoded"}`)
	}
	if err := o.journal.Settle(context.Background(), sequence, state, raw); err != nil {
		o.failPersistence(err)
	}
}
func (o *SessionOwner) failPersistence(err error) {
	o.mu.Lock()
	if o.fatal == nil {
		o.fatal = err
	}
	o.mu.Unlock()
}
func (o *SessionOwner) record(kind string, data any, generation string, origin json.RawMessage) {
	raw, err := json.Marshal(data)
	if err == nil {
		_, err = o.outputReplay().Append(generation, origin, kind, raw)
	}
	if err != nil {
		o.failPersistence(err)
	}
}
func (o *SessionOwner) observe(event session.SessionEvent) {
	o.mu.Lock()
	generation := o.generation
	origin := append(json.RawMessage(nil), o.origin...)
	o.mu.Unlock()
	if event.Interaction != nil {
		if event.Interaction.Resolved {
			o.mu.Lock()
			delete(o.pending, event.Interaction.NativeInteractionID)
			o.mu.Unlock()
		} else {
			o.prepareInspection(event, generation)
		}
		// Native details/answers and the inspection secret remain worker-private.
		copy := *event.Interaction
		copy.NativePayload = nil
		copy.Summary = ""
		copy.Answer = ""
		event.Interaction = &copy
	}
	o.record("session", event, generation, origin)
}
func (o *SessionOwner) captureTerminal(_ string, master *os.File) {
	o.mu.Lock()
	generation := o.generation
	origin := append(json.RawMessage(nil), o.origin...)
	if o.closing {
		o.mu.Unlock()
		return
	}
	o.terminal = master
	o.wg.Go(func() {
		buffer := make([]byte, 4096)
		for {
			n, err := master.Read(buffer)
			if n > 0 {
				o.record("terminal", append([]byte(nil), buffer[:n]...), generation, origin)
			}
			if err != nil {
				return
			}
		}
	})
	o.mu.Unlock()
}
func (o *SessionOwner) writeInput(op Operation) error {
	if len(op.Data) == 0 || len(op.Data) > 4096 {
		return errors.New("invalid terminal input batch")
	}
	o.terminalWrite.Lock()
	defer o.terminalWrite.Unlock()
	o.mu.Lock()
	master := o.terminal
	valid := op.NativeGeneration != "" && op.NativeGeneration == o.generation && o.fatal == nil
	o.mu.Unlock()
	if !valid || master == nil || !o.driver.Live(o.journal.scope.InstanceID) {
		return errors.New("terminal generation is no longer live")
	}
	n, err := master.Write(op.Data)
	if err != nil || n != len(op.Data) {
		return fmt.Errorf("%w: terminal input may be partially applied", session.ErrTurnInterrupted)
	}
	return nil
}
func (o *SessionOwner) resize(op Operation) error {
	if op.Rows == 0 || op.Cols == 0 || op.Rows > 1000 || op.Cols > 1000 {
		return errors.New("invalid terminal dimensions")
	}
	o.mu.Lock()
	master := o.terminal
	valid := op.NativeGeneration != "" && op.NativeGeneration == o.generation
	o.mu.Unlock()
	if !valid || master == nil || !o.driver.Live(o.journal.scope.InstanceID) {
		return errors.New("terminal generation is no longer live")
	}
	return pty.Setsize(master, &pty.Winsize{Rows: op.Rows, Cols: op.Cols})
}
func (o *SessionOwner) Snapshot() NativeSnapshot {
	o.mu.Lock()
	observedGeneration := o.generation
	o.mu.Unlock()
	native, _ := o.manager.TryNativeID(o.journal.scope.InstanceID)
	state, _ := o.manager.State(o.journal.scope.InstanceID)
	profileRaw, _ := json.Marshal(o.spec) // Env is memory-only and deliberately excluded.
	profileHash := sha256.Sum256(profileRaw)
	snap := NativeSnapshot{Scope: o.journal.scope, NativeSessionID: native, State: state, ActualRuntime: o.spec.Runtime, ProfileFingerprint: hex.EncodeToString(profileHash[:])}
	if pid := o.supervisor.EndpointPID(o.journal.scope.InstanceID); pid != nil && native != "" && o.driver.Live(o.journal.scope.InstanceID) {
		ctx, cancel := context.WithTimeout(o.ctx, 50*time.Millisecond)
		captured, ownedErr := o.supervisor.OwnedStartIdentity(ctx, *pid)
		cancel()
		actual, actualErr := proc.StartIdentity(*pid)
		driverPID := o.manager.PID(o.journal.scope.InstanceID)
		if ownedErr == nil && actualErr == nil && captured != "" && actual == captured && driverPID != nil && *driverPID == *pid {
			snap.PID = *pid
			snap.NativeStartIdentity = captured
		}
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if observedGeneration != o.generation {
		snap.PID = 0
		snap.NativeStartIdentity = ""
		snap.NativeSessionID = ""
	}
	snap.NativeGeneration = o.generation
	snap.Origin = append(json.RawMessage(nil), o.origin...)
	snap.HasTerminal = o.terminal != nil && snap.PID > 0
	if o.observationBlocked != nil {
		snap.PublicError = "Native event publication is paused until durable journal capacity is available."
	}
	if o.fatal != nil {
		snap.PublicError = "Worker output persistence requires attention; new native work is paused."
	}
	for _, pending := range o.pending {
		if pending.inspection != nil && !pending.consumed {
			copy := *pending.inspection
			snap.Pending = append(snap.Pending, copy)
		}
	}
	return snap
}
func (o *SessionOwner) Close() {
	o.mu.Lock()
	o.closing = true
	o.mu.Unlock()
	o.cancel()
	o.relay.close()
	o.supervisor.StopAll(5 * time.Second)
	o.wg.Wait()
	clear(o.captureKey)
}

// ownedDriver intercepts every actual activation, including the Manager's
// proven-unaccepted endpoint retry. It preserves optional driver capabilities.
type ownedDriver struct {
	session.Driver
	owner *SessionOwner
}

func (d *ownedDriver) Activate(ctx context.Context, sess *session.RuntimeSession, events chan<- session.SessionEvent) (*session.RuntimeEndpoint, error) {
	if !d.Driver.Live(sess.InstanceID) {
		generation, err := freshNonce()
		if err != nil {
			return nil, err
		}
		nonce, err := freshNonce()
		if err != nil {
			return nil, err
		}
		o := d.owner
		o.mu.Lock()
		commandID := o.candidateCommandID
		o.mu.Unlock()
		origin, err := o.awaitActivationOrigin(ctx, commandID, generation)
		if err != nil {
			return nil, err
		}
		o.mu.Lock()
		o.generation = generation
		o.nonce = nonce
		o.origin = append(json.RawMessage(nil), origin...)
		o.pending = map[string]*nativeApproval{}
		o.terminal = nil
		o.mu.Unlock()
		o.manager.ResetNativeActivity(sess.InstanceID)
		o.relay.bindNative(generation)
		// Manager holds its activation lock across this write and Activate. No
		// controller can mutate launch environment/model on a live worker endpoint.
		sess.Env = o.launchEnvironment(nonce)
	}
	return d.Driver.Activate(ctx, sess, events)
}
func (d *ownedDriver) PTYMaster(id string) *os.File {
	if p, ok := d.Driver.(session.PTYOwner); ok {
		return p.PTYMaster(id)
	}
	return nil
}
func (d *ownedDriver) ActiveWork(id string) bool {
	if p, ok := d.Driver.(session.ActivityReporter); ok {
		return p.ActiveWork(id)
	}
	if p, ok := d.Driver.(session.SuspendSafetyReporter); ok {
		return !p.AutoSuspendSafe(id)
	}
	return true
}
func (d *ownedDriver) Materialised(id string) bool {
	if p, ok := d.Driver.(session.MaterialisationReporter); ok {
		return p.Materialised(id)
	}
	return false
}
func (d *ownedDriver) AutoSuspendSafe(id string) bool {
	if p, ok := d.Driver.(session.SuspendSafetyReporter); ok {
		return p.AutoSuspendSafe(id)
	}
	return false
}
func (o *SessionOwner) launchEnvironment(nonce string) []string {
	name, surface := "pagnet", "worker"
	if o.spec.Kind == "representative" {
		name, surface = "pagnet-control", "control"
	}
	cfg := map[string]any{"mcpServers": map[string]any{name: map[string]any{"command": o.spec.MCPExecutable, "args": []string{"mcp", surface, "--socket", filepath.Join(o.journal.dir, "native.sock")}, "env": map[string]string{"PAGNET_INSTANCE_ID": o.journal.scope.InstanceID, "PAGNET_NETWORK_ID": o.spec.NetworkID, "PAGNET_BRIDGE_NONCE": nonce}}}}
	raw, _ := json.Marshal(cfg)
	env := append([]string(nil), o.spec.Env...)
	return append(env, "PAGNET_INSTANCE_ID="+o.journal.scope.InstanceID, "PAGNET_NETWORK_ID="+o.spec.NetworkID, "PAGNET_STATE_DIR="+filepath.Join(o.journal.dir, "native-state"), "PAGNET_MCP_CONFIG="+string(raw))
}
