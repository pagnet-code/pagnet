package runtime

// Codex persistent runtime driver (runtime-lifecycle rework, Wave 4).
//
// CodexPersistent is the persistent (one long-lived process per
// AgentInstance) Codex integration. It runs ONE `codex app-server
// --stdio` process per instance and drives it over JSON-RPC 2.0 on stdio
// (one JSON object per line):
//
//   - initialize: the handshake — sent on process start, awaited before
//     the endpoint accepts turns (a failed/timeout handshake is a clean
//     launch error, not a hang).
//   - thread/start (cold) / thread/resume (resume): the native session.
//     The response's thread.id is the driver's native session id
//     (NativeID). The standing document rides the thread's
//     developerInstructions (Codex's native standing/developer
//     instructions — standing context, NEVER a user chat message).
//   - turn/start {threadId, input[{type:"text", text:...}]}: one managed
//     turn. The input is EXACTLY what the daemon hands over (the
//     turnSpecFor invariant) — never appended or rewritten.
//   - notifications: the turn's streaming events (turn/started,
//     item/agentMessage/delta, item/started/completed,
//     thread/tokenUsage/updated, turn/completed — the terminal event).
//   - server requests: the runtime's native interactions (approval and
//     input requests). They are surfaced as generic interaction events;
//     pagnet NEVER auto-approves — the resolution travels back as the
//     JSON-RPC response when the daemon resolves the interaction.
//
// It implements the generic session.Driver contract (like QwenPersistent
// and PersistentFake), so the daemon drives it through the session core
// exactly the way it drives the other persistent runtimes.
//
// Key invariants:
//   - ONE app-server per instance: the process is started at activation
//     and kept alive across turns (ClassEndpoint, one per instance —
//     never one per turn).
//   - JSON-RPC correlation: responses are correlated to their waiters by
//     id; server-initiated notifications and requests are dispatched by
//     method. The reader loop is the single dispatcher.
//   - Materialised-gated persistence: the native id is set on the
//     session as the thread exchange happens; the Manager/daemon persist
//     it only once the session is materialised (the first completed
//     exchange) — a wake/launch of a never-materialised session
//     cold-starts a fresh thread (no brick).
//   - Crash contract: if the app-server dies after accepting a turn
//     (the turn/start response or the turn/started notification) but
//     before a terminal result, the turn settles as INTERRUPTED
//     (ErrTurnInterrupted — the outcome may be partially applied; the
//     Manager must not re-submit). A death before acceptance is
//     ErrEndpointGone (the Manager re-activates and retries once). A
//     dead process never wedges the instance.
//   - No terminal attach: Codex's app-server has no attachable native
//     TUI (the machine plane IS the stdio transport). NativeTUI /
//     SecondClientTerminalAttach are FALSE — the console does not offer
//     a terminal for Codex instances.
//   - MCP is injected at process start with -c config overrides
//     (mcp_servers.<name> = {command, args, env}) — the same
//     PAGNET_MCP_CONFIG the other adapters use. A missing/invalid MCP
//     config is a VISIBLE launch failure (the endpoint never comes up
//     silently without its network tools).

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/proc"
	"github.com/pagnet-code/pagnet/internal/session"
)

// codexClientInfo is the client identity the initialize handshake
// reports (informational: the app-server logs it for diagnostics).
const (
	codexClientName    = "pagnet"
	codexClientVersion = "1.0.0"
)

// CodexPersistent is the Codex app-server persistent driver.
type CodexPersistent struct {
	// Binary is the path to the codex executable. When empty it is
	// resolved from PATH / next to the current executable.
	Binary string
	// Model overrides the model for managed endpoints (empty = the
	// session's launch model, then the PAGNET_CODEX_MODEL env, then the
	// user's default).
	Model string
	// Env is appended to the inherited environment for the endpoint
	// process.
	Env []string

	life lifecycleState

	mu        sync.Mutex
	endpoints map[string]*codexEndpoint
}

// NewCodexPersistent builds a Codex persistent driver.
func NewCodexPersistent(binary string) *CodexPersistent {
	return &CodexPersistent{Binary: binary, endpoints: map[string]*codexEndpoint{}}
}

// SetLifecycle implements LifecycleSetter (the daemon injects its central
// process supervisor; standalone use falls back to a private one).
func (c *CodexPersistent) SetLifecycle(l proc.Lifecycle) { c.life.SetLifecycle(l) }

// Name is the canonical runtime name.
func (c *CodexPersistent) Name() domain.RuntimeName { return domain.RuntimeCodex }

// Capabilities is the probed capability set (honest advertisement).
func (c *CodexPersistent) Capabilities() session.Capabilities {
	return session.Capabilities{
		PersistentEndpoint:          true,
		MultipleSessionsPerEndpoint: false, // one thread per endpoint
		StructuredEvents:            true,
		NativeSubmit:                true,
		// pagnet serializes prompt turns (one in flight per instance);
		// the app-server does not queue managed submits for us.
		NativeQueueWhileBusy: false,
		NativeSteer:          false,
		Interrupt:            false,
		// Native interactions (approval / input requests) are observed as
		// structured server requests.
		NativeInteractionObserve: true,
		// Interactions are remotely resolvable (the resolution travels
		// back as the JSON-RPC response).
		RemoteInteractionResolve: true,
		// No attachable native TUI: the app-server's stdio IS the machine
		// plane (there is no separate human terminal to attach to). The
		// console must not offer a terminal for Codex instances.
		NativeTUI:                       false,
		SecondClientTerminalAttach:      false,
		TerminalAttachmentFullAuthority: false,
		LiveExternalAdoption:            false,
		ResumeExternalSession:           false,
		NativeSessionDiscovery:          false,
		DynamicModelChange:              false, // the model is fixed at thread start
		DynamicMCPInjection:             false, // MCP is fixed at process start
	}
}

// SupportsRemoteResolve reports whether a pending interaction of kind can
// be resolved remotely (it implements the session.RemoteResolvable
// optional interface). Every Codex interaction kind is expressible as a
// JSON-RPC response (accept/decline/cancel, or an answer) — the daemon
// decides whether to route the resolution; the driver never auto-
// approves.
func (c *CodexPersistent) SupportsRemoteResolve(kind string) bool { return true }

// Available reports whether the codex binary is resolvable (the session-
// core analogue of the Adapter.Available method).
func (c *CodexPersistent) Available() bool {
	_, err := c.binary()
	return err == nil
}

// BinaryPath reports the resolved path of the codex binary (same
// resolution as Available).
func (c *CodexPersistent) BinaryPath() (string, bool) {
	p, err := c.binary()
	return p, err == nil
}

// --- session.Driver implementation -----------------------------------------

// Activate starts (cold) or resumes the endpoint for the session. It is
// idempotent: a live endpoint is returned unchanged. A resume of a
// non-materialised session is refused (ErrNotMaterialised); a resume that
// finds no usable thread (or re-bases onto a different one) is
// ErrSessionLost.
func (c *CodexPersistent) Activate(ctx context.Context, sess *session.RuntimeSession, events chan<- session.SessionEvent) (*session.RuntimeEndpoint, error) {
	c.mu.Lock()
	if e, ok := c.endpoints[sess.InstanceID]; ok && e.live() {
		c.mu.Unlock()
		return e.endpointInfo(sess), nil
	}
	c.mu.Unlock()

	// Resume gate (mirrors the Manager's gate; defense-in-depth for
	// standalone use).
	if sess.NativeID != "" && !sess.Materialised {
		return nil, session.ErrNotMaterialised
	}

	e, actEv, err := c.launchEndpoint(ctx, sess)
	if err != nil {
		return nil, err
	}
	if events != nil {
		events <- actEv
	}
	if actEv.Type == session.EventSessionLost {
		// The resume found no usable thread (or re-based onto a
		// different one). The endpoint that was just launched for the
		// attempt must be fully stopped AND reaped so a lost resume never
		// leaves a stale endpoint in the supervisor's registry.
		c.stopEndpoint(sess.InstanceID)
		return nil, session.ErrSessionLost
	}
	// The driver sets sess.NativeID as the native exchange happens (the
	// Driver contract). This write is serialized by the Manager's
	// per-instance activation lock (EnsureActive holds it across this
	// call), so the Manager's locked NativeID query — which takes the
	// same lock — is race-free against it.
	sess.NativeID = actEv.SessionID
	return e.endpointInfo(sess), nil
}

// Submit delivers one logical input (a prompt or an interaction
// resolution) into the session's live endpoint. For a prompt it blocks
// until the turn settles (the reader signals turnDone on the terminal
// event); for an interaction it sends the JSON-RPC response and returns
// (the in-flight turn's stream carries the interaction.resolved +
// terminal events).
func (c *CodexPersistent) Submit(ctx context.Context, sess *session.RuntimeSession, req session.SubmitRequest, events chan<- session.SessionEvent) error {
	c.mu.Lock()
	e := c.endpoints[sess.InstanceID]
	c.mu.Unlock()
	if e == nil || !e.live() {
		// The endpoint is gone (dropped by the reader's exit path on an
		// unexpected death, or never launched). This is NOT a runtime turn
		// failure: the Manager re-activates and retries the submit.
		return session.ErrEndpointGone
	}
	if req.Kind == session.SubmitInteraction {
		// Remote resolution: answer the pending server request with the
		// JSON-RPC response (the ONLY way the resolution reaches the
		// runtime — pagnet never auto-approves). The in-flight turn's
		// stream carries the interaction.resolved.
		res, evs, found := e.state.resolveInteraction(req.InteractionID, req.Decision, req.Answer)
		if !found {
			// The interaction is stale (already resolved, or the endpoint
			// was re-activated and the request is gone): nothing to
			// answer.
			return nil
		}
		// Route the resolution events onto the in-flight turn's stream
		// BEFORE sending the JSON-RPC response. At this moment the app-
		// server is still BLOCKED waiting for the resolution, so the turn
		// is provably in flight (currentTurnEvents is non-nil) and the
		// interaction.resolved event lands on the turn stream in the
		// correct order (the resolution, then the terminal events the app-
		// server emits after processing it). Routing AFTER respondRPC
		// would let a fast app-server complete the turn first, settle
		// currentTurnEvents to nil, and silently drop the resolved event.
		// When the process is already dead, cleanupOnExit has nilled
		// currentTurnEvents (that is what closes stdin and makes the write
		// below fail), so routeEvent drops the event — no resolved event is
		// ever routed for a dead runtime.
		for _, ev := range evs {
			e.routeEvent(ev)
		}
		id, err := strconv.ParseInt(req.InteractionID, 10, 64)
		var werr error
		if err == nil {
			if res != nil {
				werr = e.respondRPC(id, res)
			} else {
				// The decision cannot be expressed for this request kind:
				// answer with a JSON-RPC error (the runtime sees the
				// refusal) — never a guessed approval.
				werr = e.respondRPCError(id, -32000, "pagnet: the decision cannot be expressed for this request")
			}
		} else {
			werr = errors.New("codex interaction id is not a valid request id")
		}
		if werr != nil {
			// A write to the stdin pipe fails only when the reader end is
			// closed — the process is dead. Report it as endpoint-gone so
			// the Manager re-activates instead of failing the instance.
			return session.ErrEndpointGone
		}
		return nil
	}
	// Prompt: register the machine turn, send turn/start, wait for the
	// turn to settle.
	e.mu.Lock()
	if e.currentTurnEvents != nil {
		e.mu.Unlock()
		return session.ErrBusy
	}
	e.currentTurnID = req.TurnID
	e.currentTurnEvents = events
	e.turnEndpointGone = false
	e.turnDone = make(chan struct{})
	done := e.turnDone
	e.mu.Unlock()
	e.state.beginMachineTurn(req.TurnID)
	params := map[string]any{
		"threadId": e.state.nativeThreadID(),
		// The turn input is EXACTLY the daemon's input (the turnSpecFor
		// invariant): one text item, verbatim — never appended or
		// rewritten.
		"input": []map[string]any{{"type": "text", "text": req.Input}},
	}
	res, err := e.request(ctx, "turn/start", params)
	if err != nil {
		e.state.clearMachineTurn()
		e.clearTurn()
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return ctx.Err()
		}
		if e.live() {
			// The server answered with a JSON-RPC error: it rejected the
			// turn (a turn failure, not an endpoint death). The turn
			// settles via the event, not an error.
			events <- session.SessionEvent{
				Type:        session.EventTurnFailed,
				SessionID:   e.state.nativeThreadID(),
				TurnID:      req.TurnID,
				FailureKind: string(domain.RuntimeFailureProcessError),
				Error:       trunc(err.Error()),
			}
			return nil
		}
		// The endpoint PROCESS DIED while the turn was being submitted
		// (cleanupOnExit woke this turn; the events channel carries NO
		// terminal turn event). Classify from the runtime's OWN
		// acceptance signal (the turn/start response or the turn/started
		// notification — isTurnAccepted):
		//
		//   - accepted: the runtime started working on the turn — its
		//     outcome may be partially applied. ErrTurnInterrupted: the
		//     Manager MUST NOT re-submit it.
		//   - not accepted: no work was consumed. ErrEndpointGone: the
		//     Manager re-activates (resuming the materialised session)
		//     and retries the logical submit once.
		if e.state.isTurnAccepted() {
			return session.ErrTurnInterrupted
		}
		return session.ErrEndpointGone
	}
	// The turn/start response is the acceptance signal: from this moment
	// the runtime is working on the submit, so a mid-turn death is an
	// INTERRUPTION, not an unaccepted endpoint death.
	e.state.markTurnAccepted()
	var _ = res
	select {
	case <-done:
		e.mu.Lock()
		gone := e.turnEndpointGone
		e.mu.Unlock()
		if gone {
			// The endpoint PROCESS DIED mid-turn (cleanupOnExit woke this
			// turn; no terminal event was produced). The turn was
			// ACCEPTED (the response above), so its outcome may be
			// partially applied: ErrTurnInterrupted (never auto-retried).
			return session.ErrTurnInterrupted
		}
		return nil
	case <-ctx.Done():
		e.state.clearMachineTurn()
		e.clearTurn()
		return ctx.Err()
	}
}

// Hibernate stops the endpoint, preserving the session (the codex thread
// rollout persists on disk under CODEX_HOME — invariant F). It is a
// no-op when no endpoint is live.
func (c *CodexPersistent) Hibernate(ctx context.Context, sess *session.RuntimeSession) error {
	return c.stopEndpoint(sess.InstanceID)
}

// Stop terminates the endpoint unconditionally (daemon shutdown /
// explicit stop).
func (c *CodexPersistent) Stop(instanceID string) error {
	return c.stopEndpoint(instanceID)
}

// PID is the endpoint's process id (nil when none).
func (c *CodexPersistent) PID(instanceID string) *int {
	c.mu.Lock()
	e := c.endpoints[instanceID]
	c.mu.Unlock()
	if e == nil {
		return nil
	}
	return e.pid()
}

// Live reports whether the instance's endpoint process is still alive. It
// is the liveness probe the Manager consults before trusting a live
// session state: when the endpoint record is absent (dropped by the
// reader's exit path on an unexpected death) or its reader has exited
// (the process is gone), the endpoint is gone and the session must be
// re-activated, not wedged.
func (c *CodexPersistent) Live(instanceID string) bool {
	c.mu.Lock()
	e := c.endpoints[instanceID]
	c.mu.Unlock()
	return e != nil && e.live()
}

// --- endpoint lifecycle ------------------------------------------------------

// codexEndpoint is one live codex app-server endpoint process.
type codexEndpoint struct {
	f          *CodexPersistent // back-reference (the reader's exit path drops this record)
	instanceID string
	h          *proc.Handle // set once at launch, never nilled (immutable)
	state      *codexTurnState
	stdin      io.WriteCloser
	stdout     io.ReadCloser
	stderr     *bytes.Buffer

	// activationCh carries the (synthesized) activation event; closed by
	// the driver after it is delivered.
	activationCh chan session.SessionEvent
	// readerDone is closed when the stdout reader exits (the process has
	// exited — its stdout is closed). It is the liveness signal.
	readerDone chan struct{}

	// JSON-RPC correlation: responses are matched to waiters by id.
	rpcMu   sync.Mutex
	nextID  int64
	pending map[int64]*codexRPCWaiter

	mu                sync.Mutex
	activationSent    bool // the activation event was published (route the turn events from now on)
	currentTurnID     string
	currentTurnEvents chan<- session.SessionEvent
	turnDone          chan struct{}
	// turnEndpointGone distinguishes WHY turnDone was closed: false = the
	// turn settled on a NORMAL terminal event (routeEvent), true = the
	// endpoint PROCESS DIED mid-turn (cleanupOnExit). Both paths close
	// the same channel, so without this flag Submit's `case <-done` cannot
	// tell a completed turn from a cut-off one. Kept in lockstep with
	// QwenPersistent / PersistentFake: every persistent driver carries it.
	turnEndpointGone bool

	// turnSenders counts routeEvent calls that have captured the current
	// turn's channel and have not yet completed their send. The turn's
	// settlement (the three paths that close turnDone) waits for this to
	// drain before closing turnDone, so the Manager's close of the turn
	// channel — which happens only after the prompt's Submit returns,
	// which happens only after turnDone is closed — can never race an
	// in-flight send on that channel. turnCond is signaled when the count
	// reaches zero.
	turnSenders int
	turnCond    *sync.Cond

	stdinMu sync.Mutex
}

// live reports whether the endpoint process is still running. The reader
// closes readerDone when it hits EOF (the process closed its stdout, i.e.
// exited), so a closed readerDone means the process is gone.
func (e *codexEndpoint) live() bool {
	select {
	case <-e.readerDone:
		return false
	default:
		return true
	}
}

func (e *codexEndpoint) pid() *int {
	if e.h == nil {
		return nil
	}
	p := e.h.PID()
	if p == 0 {
		return nil
	}
	return &p
}

func (e *codexEndpoint) endpointInfo(sess *session.RuntimeSession) *session.RuntimeEndpoint {
	ep := &session.RuntimeEndpoint{
		ID:        "ep-" + e.instanceID,
		Runtime:   sess.Runtime,
		Ownership: session.OwnershipPagnet,
		Lease:     session.LeaseClaimed,
		Healthy:   true,
		Transport: "stdio",
		Sessions:  []string{e.state.nativeThreadID()},
		StartedAt: time.Now(),
	}
	if e.h != nil {
		ep.PID = e.h.PID()
		ep.PGID = e.h.PGID()
	}
	return ep
}

// clearTurn resets the in-flight turn state (on a submit failure or ctx
// cancel). It does not close the events channel (the Manager owns that).
// Before closing turnDone it waits for any in-flight routeEvent send on the
// turn's channel to drain, so the Manager's close of that channel (after the
// prompt's Submit returns) can never race a send.
func (e *codexEndpoint) clearTurn() {
	e.mu.Lock()
	e.currentTurnEvents = nil
	e.currentTurnID = ""
	for e.turnSenders > 0 {
		e.turnCond.Wait()
	}
	if e.turnDone != nil {
		close(e.turnDone)
		e.turnDone = nil
	}
	e.mu.Unlock()
}

// launchEndpoint starts the codex app-server endpoint through the
// supervisor (ClassEndpoint: long-lived, process-group isolated, one per
// instance) and performs the handshake (initialize + thread start/resume).
// It returns the endpoint and the (synthesized) activation event.
func (c *CodexPersistent) launchEndpoint(ctx context.Context, sess *session.RuntimeSession) (*codexEndpoint, session.SessionEvent, error) {
	bin, err := c.binary()
	if err != nil {
		return nil, session.SessionEvent{}, err
	}
	if sess.Workspace == "" {
		return nil, session.SessionEvent{}, errors.New("codex persistent: requires a workspace (the thread's cwd)")
	}
	// MCP injection (process start, -c overrides): the daemon-rendered
	// PAGNET_MCP_CONFIG becomes the app-server's mcp_servers config. A
	// missing/invalid config is a VISIBLE launch failure — the endpoint
	// never comes up silently without its network tools.
	mcpArgs, err := codexMCPConfigArgs(sess.Env)
	if err != nil {
		return nil, session.SessionEvent{}, err
	}

	args := []string{"app-server", "--stdio"}
	args = append(args, mcpArgs...)

	cmd := exec.Command(bin, args...)
	cmd.Dir = sess.Workspace
	// Launch env: the endpoint child receives the session's launch
	// environment (the generic spec pairs the daemon injects for the
	// instance — identity vars, MCP bridge config, coordination
	// contract). The env is FIXED AT LAUNCH.
	//
	// The ownership marker (R1): the endpoint child's environment carries
	// PAGNET_INSTANCE_ID=<id>, the SAME pair the supervisor stores in the
	// ownership record (LaunchRequest.Marker).
	env := append([]string(nil), sess.Env...)
	hasMarker := false
	for _, kv := range env {
		if kv == "PAGNET_INSTANCE_ID="+sess.InstanceID {
			hasMarker = true
			break
		}
	}
	if !hasMarker {
		env = append(env, "PAGNET_INSTANCE_ID="+sess.InstanceID)
	}
	cmd.Env = ChildEnv(c.Env, env)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, session.SessionEvent{}, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		stdin.Close()
		return nil, session.SessionEvent{}, err
	}
	stderr := &bytes.Buffer{}
	cmd.Stderr = stderr

	lif := c.life.get()
	el, ok := lif.(proc.EndpointLifecycle)
	if !ok {
		stdin.Close()
		return nil, session.SessionEvent{}, errors.New("codex persistent: lifecycle does not support endpoints")
	}
	// The endpoint is LONG-LIVED: it must survive across turns (the whole
	// point of the persistent model — N turns, 1 process, stable PID).
	// The supervisor's Launch installs a context watcher that terminates
	// the process when the launch ctx is done, so the launch ctx must NOT
	// be a turn's ctx (which is cancelled at turn end) — it is the
	// driver's own lifetime. The endpoint is terminated explicitly
	// (Stop / Hibernate) or by the supervisor's StopAll on daemon
	// shutdown, never by a turn's cancellation.
	h, err := el.Launch(context.Background(), proc.LaunchRequest{
		InstanceID: sess.InstanceID,
		TurnID:     "endpoint",
		Runtime:    string(c.Name()),
		Class:      proc.ClassEndpoint,
		Cmd:        cmd,
		Marker:     "PAGNET_INSTANCE_ID=" + sess.InstanceID,
	})
	if err != nil {
		stdin.Close()
		return nil, session.SessionEvent{}, err
	}

	resuming := sess.NativeID != ""
	e := &codexEndpoint{
		f:            c,
		instanceID:   sess.InstanceID,
		h:            h,
		state:        newCodexTurnState(resuming, sess.NativeID),
		stdin:        stdin,
		stdout:       stdout,
		stderr:       stderr,
		activationCh: make(chan session.SessionEvent, 1),
		readerDone:   make(chan struct{}),
		pending:      map[int64]*codexRPCWaiter{},
	}
	e.turnCond = sync.NewCond(&e.mu)
	go e.readLoop()
	c.mu.Lock()
	c.endpoints[sess.InstanceID] = e
	c.mu.Unlock()

	// The handshake (initialize + thread start/resume) bounds the
	// activation: a process that starts but never completes the handshake
	// is a failure, not a hang. The ctx bounds it (the caller's ctx plus
	// the activation deadline).
	hsCtx, cancel := context.WithTimeout(ctx, activationTimeout)
	defer cancel()
	actEv, herr := e.handshake(hsCtx, sess)
	if herr != nil {
		// The handshake failed: stop the endpoint (TERM → grace → KILL →
		// reap → drop) so a failed activation never leaves a stale
		// endpoint in the supervisor's registry.
		c.stopEndpoint(sess.InstanceID)
		return nil, actEv, herr
	}
	return e, actEv, nil
}

// handshake performs the initialize + thread start/resume exchange and
// returns the synthesized activation event. A failed initialize is a
// launch error (the process is broken — not a session loss). A failed
// thread/resume (the stored thread is gone, or the server re-based onto
// a different one) is a session loss.
func (e *codexEndpoint) handshake(ctx context.Context, sess *session.RuntimeSession) (session.SessionEvent, error) {
	// 1. initialize: the protocol handshake (awaited before any other
	// request — the app-server refuses thread/turn work before it).
	if _, err := e.request(ctx, "initialize", map[string]any{
		"clientInfo": map[string]any{
			"name":    codexClientName,
			"version": codexClientVersion,
		},
	}); err != nil {
		return session.SessionEvent{}, fmt.Errorf("codex initialize failed: %w", err)
	}
	// 2. thread/start (cold) or thread/resume (resume). The standing
	// document rides developerInstructions (Codex's native standing /
	// developer-instructions surface — standing context, NEVER a user
	// chat message). It is FIXED AT LAUNCH (the Manager restarts the
	// endpoint when it changes).
	resuming := sess.NativeID != ""
	method := "thread/start"
	params := map[string]any{"cwd": sess.Workspace}
	if resuming {
		method = "thread/resume"
		params["threadId"] = sess.NativeID
	}
	if sess.StandingInstructions != "" {
		params["developerInstructions"] = sess.StandingInstructions
	}
	if model := e.f.modelFor(sess); model != "" {
		params["model"] = model
	}
	res, err := e.request(ctx, method, params)
	if err != nil {
		if resuming {
			// The stored thread is unrecoverable (or the server refused
			// the resume): a lost session, never a silent fresh one.
			return session.SessionEvent{
				Type:      session.EventSessionLost,
				SessionID: sess.NativeID,
				Error:     "codex thread/resume failed: " + err.Error(),
			}, session.ErrSessionLost
		}
		return session.SessionEvent{}, fmt.Errorf("codex thread/start failed: %w", err)
	}
	var tresp codexThreadStartResponse
	if err := json.Unmarshal(res, &tresp); err != nil || tresp.Thread.ID == "" {
		if resuming {
			return session.SessionEvent{
				Type:      session.EventSessionLost,
				SessionID: sess.NativeID,
				Error:     "codex thread/resume returned no thread id",
			}, session.ErrSessionLost
		}
		return session.SessionEvent{}, errors.New("codex thread/start returned no thread id")
	}
	evs := e.state.setThread(tresp.Thread.ID, tresp.Thread.Model)
	if len(evs) == 0 {
		return session.SessionEvent{}, errors.New("codex thread exchange produced no activation event")
	}
	actEv := evs[0]
	if actEv.Type == session.EventSessionLost {
		// A resume that re-based onto a different thread is a lost
		// session, never a silent fresh one.
		return actEv, session.ErrSessionLost
	}
	// Publish the activation event: from this moment the reader routes
	// turn events (before it, there is no turn to route to).
	e.mu.Lock()
	e.activationSent = true
	e.mu.Unlock()
	return actEv, nil
}

// readLoop reads the endpoint's stdout (one JSON-RPC message per line)
// and dispatches: responses → their waiters (by id), server requests →
// the state machine (interactions), notifications → the state machine
// (turn events). On EOF (process gone) it reaps the process (this
// goroutine is the single Wait owner — it read all of stdout) and
// signals any waiting turn.
func (e *codexEndpoint) readLoop() {
	defer close(e.readerDone)
	scanner := bufio.NewScanner(e.stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var msg codexRPCMessage
		if err := json.Unmarshal(line, &msg); err != nil {
			// A non-JSON-RPC line (a stray log line): ignore — the
			// protocol is one JSON object per line, and a malformed line
			// must not kill the reader.
			continue
		}
		e.dispatchMessage(&msg)
	}
	// EOF: the process exited. Clean up (reap, drop, signal the turn).
	e.cleanupOnExit()
}

// dispatchMessage routes one JSON-RPC message: a response (id +
// result/error) goes to its waiter; a server request (id + method) is a
// native interaction; a notification (method, no id) is a turn event.
func (e *codexEndpoint) dispatchMessage(msg *codexRPCMessage) {
	if msg.Method == "" {
		// A response (or a malformed message): correlate by id.
		id, ok := codexRPCIDToInt(msg.ID)
		if !ok {
			return
		}
		e.rpcMu.Lock()
		w := e.pending[id]
		if w != nil {
			delete(e.pending, id)
		}
		e.rpcMu.Unlock()
		if w == nil {
			// Stale response (the waiter was dropped on ctx cancel /
			// endpoint death): nothing to deliver.
			return
		}
		if msg.Error != nil {
			w.deliver(codexRPCResult{err: &codexRPCErrorValue{Code: msg.Error.Code, Message: msg.Error.Message}})
			return
		}
		w.deliver(codexRPCResult{result: msg.Result})
		return
	}
	if len(msg.ID) > 0 {
		// A server-initiated request (a native interaction).
		id, ok := codexRPCIDToInt(msg.ID)
		if !ok {
			return
		}
		for _, ev := range e.state.processServerRequest(strconv.FormatInt(id, 10), msg.Method, msg.Params) {
			e.routeEvent(ev)
		}
		return
	}
	// A notification (a turn event).
	for _, ev := range e.state.processNotification(msg.Method, msg.Params) {
		e.routeEvent(ev)
	}
}

// routeEvent routes a normalized event: before the activation event is
// published there is no turn to route to (handshake-time noise — the
// thread/started broadcast, MCP startup status, ...); after, events go
// to the current turn (when the TurnID matches).
func (e *codexEndpoint) routeEvent(ev session.SessionEvent) {
	e.mu.Lock()
	if !e.activationSent {
		e.mu.Unlock()
		return
	}
	ch := e.currentTurnEvents
	turnID := e.currentTurnID
	// A turn NOT initiated by the current machine submit (an external
	// turn) carries a different (or empty) turn id. Its events are NOT
	// part of this submit's stream — forwarding them would cross the
	// streams (a double turn.completed for one submit, an attribution
	// anomaly). The machine plane only ever sees events for the turn it
	// submitted.
	willSend := ch != nil && (ev.TurnID == "" || ev.TurnID == turnID)
	// Claim an in-flight-send slot BEFORE sending (under the same lock
	// that read ch), so the turn's settlement — which waits for this
	// count to drain before closing turnDone — cannot miss this send.
	// Without it, a send that captured ch just before the turn settled
	// would race the Manager's close of the turn channel.
	if willSend {
		e.turnSenders++
	}
	e.mu.Unlock()
	if !willSend {
		return
	}
	ch <- ev
	e.mu.Lock()
	e.turnSenders--
	if e.turnSenders == 0 {
		e.turnCond.Broadcast()
	}
	e.mu.Unlock()
	if isTerminalSessionEvent(ev.Type) {
		e.settleTurn(ch)
		e.state.clearMachineTurn()
	}
}

// settleTurn settles the turn whose channel is ch (a no-op when ch is no
// longer the current turn's channel — the turn was replaced or already
// settled). It waits for every in-flight routeEvent send on ch to drain
// BEFORE closing turnDone. Because the Manager closes the turn channel
// only after the prompt's Submit returns, and the prompt's Submit returns
// only after turnDone is closed, this ordering guarantees a send on the
// turn channel can never race the Manager's close of it. Callers must NOT
// hold e.mu.
func (e *codexEndpoint) settleTurn(ch chan<- session.SessionEvent) {
	e.mu.Lock()
	if e.currentTurnEvents != ch {
		e.mu.Unlock()
		return
	}
	// Mark the turn settled: no NEW routeEvent will capture this channel
	// (it reads currentTurnEvents, now nil). Only senders that captured
	// ch before this point remain in flight.
	e.currentTurnEvents = nil
	e.currentTurnID = ""
	for e.turnSenders > 0 {
		e.turnCond.Wait()
	}
	if e.turnDone != nil {
		close(e.turnDone)
		e.turnDone = nil
	}
	e.mu.Unlock()
}

// cleanupOnExit runs when the process exits: it reaps the process
// (single Wait owner — this goroutine read all of stdout), drops the
// endpoint record, fails any pending requests, and signals any waiting
// turn. The turn is "cut off" (no terminal event) — it is marked
// endpoint-gone so the blocked Submit classifies the death from the
// machine-turn state's acceptance signal: accepted →
// session.ErrTurnInterrupted (surfaced, never auto-retried), not
// accepted → session.ErrEndpointGone (the Manager re-activates —
// resuming the materialised session — and retries the logical submit
// once). It must NOT look like a settled turn: that is what left an
// instance persisted as working with no endpoint.
func (e *codexEndpoint) cleanupOnExit() {
	if e.h != nil {
		e.h.Wait()
	}
	// Drop THIS endpoint's record (so Live() reports it gone and Submit
	// cannot find a dead endpoint). It runs AFTER the reap (so the
	// supervisor is already clean).
	e.f.dropEndpointRef(e)
	// Fail any pending requests (the handshake or a turn submit is
	// blocked on a response that will never come).
	e.rpcMu.Lock()
	for id, w := range e.pending {
		w.deliver(codexRPCResult{err: errors.New("codex app-server connection closed")})
		delete(e.pending, id)
	}
	e.rpcMu.Unlock()
	// Signal any in-flight turn so its Submit returns (the Manager
	// settles the session).
	e.mu.Lock()
	if e.currentTurnEvents != nil {
		e.currentTurnEvents = nil
		e.currentTurnID = ""
		// The turn is being cut off by the process death, not settled by
		// a terminal runtime event. Set the reason BEFORE closing turnDone
		// so the woken Submit observes it. Guarded by currentTurnEvents: a
		// turn that routeEvent already settled (nil currentTurnEvents,
		// flag left false) must not be reclassified as endpoint-gone
		// after the fact.
		e.turnEndpointGone = true
	}
	// Wait for any in-flight routeEvent send on the turn's channel to
	// drain before closing turnDone, so the Manager's close of that
	// channel (after the prompt's Submit returns) can never race a send.
	for e.turnSenders > 0 {
		e.turnCond.Wait()
	}
	if e.turnDone != nil {
		close(e.turnDone)
		e.turnDone = nil
	}
	e.mu.Unlock()
	// Close the stdin pipe (the process is gone; a late write must fail
	// fast instead of blocking).
	e.stdinMu.Lock()
	if e.stdin != nil {
		e.stdin.Close()
		e.stdin = nil
	}
	e.stdinMu.Unlock()
}

// stopEndpoint terminates the instance's endpoint (TERM → grace → KILL
// via the supervisor) and drops its state. The codex thread rollout
// persists on disk under CODEX_HOME, so the session survives for a later
// resume (invariant F).
func (c *CodexPersistent) stopEndpoint(instanceID string) error {
	c.mu.Lock()
	e := c.endpoints[instanceID]
	c.mu.Unlock()
	if e == nil {
		return nil
	}
	lif := c.life.get()
	if el, ok := lif.(proc.EndpointLifecycle); ok {
		el.StopEndpoint(instanceID)
	}
	// Wait for the process to be reaped (bounded), then drop the state.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if !e.live() {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	c.dropEndpoint(instanceID)
	return nil
}

func (c *CodexPersistent) dropEndpoint(instanceID string) {
	c.mu.Lock()
	e := c.endpoints[instanceID]
	delete(c.endpoints, instanceID)
	c.mu.Unlock()
	if e != nil {
		// Best-effort: ensure the process is terminated and reaped.
		if e.h != nil {
			e.h.Close()
		}
	}
}

// dropEndpointRef removes a SPECIFIC endpoint record (the one whose
// reader hit exit) from the registry, without touching any other
// endpoint for the same instance. A concurrent re-activation may have
// already launched a fresh endpoint for the instance; this must not drop
// it. It is the exit-path cleanup: the dying endpoint's reader is the
// single owner of this record, and it runs AFTER the reap (so the
// supervisor is already clean).
func (c *CodexPersistent) dropEndpointRef(e *codexEndpoint) {
	c.mu.Lock()
	if c.endpoints[e.instanceID] == e {
		delete(c.endpoints, e.instanceID)
	}
	c.mu.Unlock()
}

// modelFor resolves the launch model: the session's launch model > the
// driver's field > the PAGNET_CODEX_MODEL env > "" (the user default).
func (c *CodexPersistent) modelFor(sess *session.RuntimeSession) string {
	if sess != nil && sess.Model != "" {
		return sess.Model
	}
	if c.Model != "" {
		return c.Model
	}
	return os.Getenv("PAGNET_CODEX_MODEL")
}

// binary resolves the codex CLI path: the explicit field, then PATH, then
// next to the current executable.
func (c *CodexPersistent) binary() (string, error) {
	if c.Binary != "" {
		if _, err := os.Stat(c.Binary); err == nil {
			return c.Binary, nil
		}
	}
	if p, err := exec.LookPath("codex"); err == nil {
		return p, nil
	}
	if self, err := os.Executable(); err == nil {
		cand := filepath.Join(filepath.Dir(self), "codex")
		if _, err := os.Stat(cand); err == nil {
			return cand, nil
		}
	}
	return "", fmt.Errorf("codex CLI not found on PATH")
}

// --- JSON-RPC client -----------------------------------------------------------

// codexRPCMessage is one JSON-RPC 2.0 object on the wire (one per line).
type codexRPCMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *codexRPCError  `json:"error,omitempty"`
}

// codexRPCError is a JSON-RPC error object.
type codexRPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// codexRPCErrorValue is a transport-level or server JSON-RPC error
// returned to a request waiter.
type codexRPCErrorValue struct {
	Code    int
	Message string
}

func (e *codexRPCErrorValue) Error() string {
	return fmt.Sprintf("codex rpc error %d: %s", e.Code, e.Message)
}

// codexRPCWaiter is one outstanding request's delivery channel.
type codexRPCWaiter struct {
	ch chan codexRPCResult
}

type codexRPCResult struct {
	result json.RawMessage
	err    error
}

// deliver hands the result to the waiter exactly once (the channel is
// buffered 1; a second deliver is a no-op).
func (w *codexRPCWaiter) deliver(r codexRPCResult) {
	select {
	case w.ch <- r:
	default:
	}
}

// nextRPCID mints the next request id (monotonic, from 1).
func (e *codexEndpoint) nextRPCID() int64 {
	e.rpcMu.Lock()
	defer e.rpcMu.Unlock()
	e.nextID++
	return e.nextID
}

// request sends one JSON-RPC request and waits for its response (by id).
// It returns the raw result, or an error (a JSON-RPC error response, a
// write failure, the connection closing, or ctx done — the waiter is
// dropped on ctx done so a late response is discarded).
func (e *codexEndpoint) request(ctx context.Context, method string, params any) (json.RawMessage, error) {
	id := e.nextRPCID()
	w := &codexRPCWaiter{ch: make(chan codexRPCResult, 1)}
	e.rpcMu.Lock()
	e.pending[id] = w
	e.rpcMu.Unlock()
	pb, err := json.Marshal(params)
	if err != nil {
		e.dropPending(id)
		return nil, err
	}
	if err := e.writeMessage(codexRPCMessage{
		JSONRPC: "2.0",
		ID:      json.RawMessage(strconv.FormatInt(id, 10)),
		Method:  method,
		Params:  pb,
	}); err != nil {
		e.dropPending(id)
		return nil, err
	}
	select {
	case r := <-w.ch:
		return r.result, r.err
	case <-ctx.Done():
		e.dropPending(id)
		return nil, ctx.Err()
	}
}

// dropPending removes a waiter (on a write failure or ctx cancel) so a
// late response is discarded instead of leaked.
func (e *codexEndpoint) dropPending(id int64) {
	e.rpcMu.Lock()
	delete(e.pending, id)
	e.rpcMu.Unlock()
}

// respondRPC sends the JSON-RPC response to a server request (an
// interaction resolution).
func (e *codexEndpoint) respondRPC(id int64, result json.RawMessage) error {
	return e.writeMessage(codexRPCMessage{
		JSONRPC: "2.0",
		ID:      json.RawMessage(strconv.FormatInt(id, 10)),
		Result:  result,
	})
}

// respondRPCError sends a JSON-RPC error response to a server request
// (a decision that cannot be expressed — never a guessed approval).
func (e *codexEndpoint) respondRPCError(id int64, code int, message string) error {
	return e.writeMessage(codexRPCMessage{
		JSONRPC: "2.0",
		ID:      json.RawMessage(strconv.FormatInt(id, 10)),
		Error:   &codexRPCError{Code: code, Message: message},
	})
}

// writeMessage writes one JSON-RPC object to the endpoint's stdin (one
// line, serialized).
func (e *codexEndpoint) writeMessage(msg codexRPCMessage) error {
	e.stdinMu.Lock()
	defer e.stdinMu.Unlock()
	if e.stdin == nil {
		return errors.New("codex stdin is closed")
	}
	b, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_, err = e.stdin.Write(b)
	return err
}

// codexRPCIDToInt decodes a JSON-RPC id (a number or a string of digits)
// to an int64.
func codexRPCIDToInt(raw json.RawMessage) (int64, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return 0, false
	}
	if trimmed[0] == '"' {
		var s string
		if err := json.Unmarshal(trimmed, &s); err != nil {
			return 0, false
		}
		n, err := strconv.ParseInt(s, 10, 64)
		return n, err == nil
	}
	n, err := strconv.ParseInt(string(trimmed), 10, 64)
	return n, err == nil
}

// --- MCP config injection (-c overrides) ---------------------------------------

// codexMCPConfigArgs builds the -c config-override args that inject the
// daemon-rendered PAGNET_MCP_CONFIG into the app-server's MCP server
// config (mcp_servers.<name> = {command, args, env}). The -c value is
// parsed as TOML, so each server is an inline table. A missing/invalid
// config is a VISIBLE failure (the endpoint would otherwise come up
// silently without its network tools).
func codexMCPConfigArgs(env []string) ([]string, error) {
	mcpJSON := pagnetMCPConfig(env)
	if mcpJSON == "" {
		return nil, errors.New("PAGNET_MCP_CONFIG missing: the codex endpoint would come up without network tools")
	}
	var src struct {
		MCPServers map[string]struct {
			Command string            `json:"command"`
			Args    []string          `json:"args"`
			Env     map[string]string `json:"env"`
		} `json:"mcpServers"`
	}
	if err := json.Unmarshal([]byte(mcpJSON), &src); err != nil {
		return nil, fmt.Errorf("invalid PAGNET_MCP_CONFIG: %w", err)
	}
	if len(src.MCPServers) == 0 {
		return nil, errors.New("PAGNET_MCP_CONFIG has no mcpServers")
	}
	names := make([]string, 0, len(src.MCPServers))
	for name := range src.MCPServers {
		names = append(names, name)
	}
	sort.Strings(names) // deterministic argv (map iteration is not)
	var args []string
	for _, name := range names {
		s := src.MCPServers[name]
		if s.Command == "" {
			return nil, fmt.Errorf("PAGNET_MCP_CONFIG server %q has no command", name)
		}
		args = append(args, "-c", "mcp_servers."+tomlBareKey(name)+"="+tomlInlineMCPServer(s.Command, s.Args, s.Env))
	}
	return args, nil
}

// tomlBareKey returns the name as a TOML bare key when it is valid
// ([A-Za-z0-9_-]+), quoted as a basic string otherwise.
func tomlBareKey(name string) string {
	ok := name != ""
	for _, r := range name {
		if !(r == '-' || r == '_' ||
			(r >= '0' && r <= '9') ||
			(r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z')) {
			ok = false
			break
		}
	}
	if ok {
		return name
	}
	return tomlString(name)
}

// tomlInlineMCPServer renders one MCP server as a TOML inline table
// ({command=...,args=[...],env={...}}) — the -c value shape.
func tomlInlineMCPServer(command string, args []string, env map[string]string) string {
	var b strings.Builder
	b.WriteString("{command=")
	b.WriteString(tomlString(command))
	b.WriteString(",args=[")
	for i, a := range args {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(tomlString(a))
	}
	b.WriteString("]")
	if len(env) > 0 {
		keys := make([]string, 0, len(env))
		for k := range env {
			keys = append(keys, k)
		}
		sort.Strings(keys) // deterministic argv (map iteration is not)
		b.WriteString(",env={")
		for i, k := range keys {
			if i > 0 {
				b.WriteString(",")
			}
			b.WriteString(tomlBareKey(k))
			b.WriteString("=")
			b.WriteString(tomlString(env[k]))
		}
		b.WriteString("}")
	}
	b.WriteString("}")
	return b.String()
}

// tomlString renders a TOML basic string (escaped).
func tomlString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(&b, `\u%04X`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}
