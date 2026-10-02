package sessionworker

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/internal/localpeer"
)

// Admission is the current controller's public control-plane session binding.
// It carries no credential. The controller must obtain fresh server admission
// and enforce its current grants before servicing a forwarded call. Worker
// possession never bypasses that authenticated control-plane transport.
type Admission struct {
	NativeAdmissionID string    `json:"nativeAdmissionId"`
	Scope             Scope     `json:"scope"`
	TenantID          string    `json:"tenantId"`
	NetworkID         string    `json:"networkId"`
	Kind              string    `json:"kind"`
	RunnerID          string    `json:"runnerId"`
	RunnerEpoch       time.Time `json:"runnerEpoch"`
	BootID            string    `json:"bootId"`
}
type BridgeCall struct {
	NativeSessionID  string            `json:"nativeSessionId,omitempty"`
	TurnSource       *NativeTurnSource `json:"turnSource,omitempty"`
	ID               string            `json:"id"`
	Scope            Scope             `json:"scope"`
	NativeGeneration string            `json:"nativeGeneration"`
	Origin           json.RawMessage   `json:"origin,omitempty"`
	Admission        Admission         `json:"admission"`
	Tool             string            `json:"tool"`
	Args             json.RawMessage   `json:"args"`
}
type BridgeResult struct {
	ID        string          `json:"id"`
	OK        bool            `json:"ok"`
	Result    json.RawMessage `json:"result,omitempty"`
	Error     string          `json:"error,omitempty"`
	ErrorCode string          `json:"errorCode,omitempty"`
	Retryable bool            `json:"retryable,omitempty"`
}
type relayTicket struct {
	call   BridgeCall
	lease  int64
	issued bool
	done   chan BridgeResult
}
type relayBroker struct {
	nativeGeneration string
	activation       *activationTicket
	mu               sync.Mutex
	scope            Scope
	spec             NativeSpec
	lease            int64
	admission        *Admission
	pending          map[string]*relayTicket
	order            []string
	closed           bool
}

func newRelayBroker(scope Scope, spec NativeSpec) *relayBroker {
	return &relayBroker{scope: scope, spec: spec, pending: map[string]*relayTicket{}}
}
func (b *relayBroker) bindLease(lease int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if lease <= b.lease {
		return
	}
	b.lease = lease
	b.admission = nil
	b.invalidateIssued()
}
func (b *relayBroker) disconnect(lease int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.lease == lease {
		b.admission = nil
		b.invalidateIssued()
	}
}
func (b *relayBroker) invalidateIssued() {
	if b.activation != nil {
		b.activation.issued = false
		b.activation.lease = 0
	}
	for id, ticket := range b.pending {
		if ticket.issued {
			ticket.done <- BridgeResult{ID: id, Error: "Pagnet controller changed; this operation may already have been applied. Inspect its result before retrying."}
			delete(b.pending, id)
		}
	}
	b.compact()
}
func (b *relayBroker) compact() {
	out := b.order[:0]
	for _, id := range b.order {
		if _, ok := b.pending[id]; ok {
			out = append(out, id)
		}
	}
	b.order = out
}
func (b *relayBroker) admit(lease int64, a Admission) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed || lease != b.lease {
		return ErrFenced
	}
	if a.NativeAdmissionID == "" || len(a.NativeAdmissionID) > 256 || a.Scope != b.scope || a.TenantID != b.spec.TenantID || a.NetworkID != b.spec.NetworkID || a.Kind != b.spec.Kind || a.RunnerID == "" || len(a.RunnerID) > 256 || a.RunnerEpoch.IsZero() || a.BootID == "" || len(a.BootID) > 256 {
		return errors.New("control-plane admission does not match worker scope")
	}
	if b.admission != nil && *b.admission != a {
		b.invalidateIssued()
	}
	copy := a
	b.admission = &copy
	return nil
}
func (b *relayBroker) poll(lease int64) (*BridgeCall, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed || lease != b.lease {
		return nil, ErrFenced
	}
	if b.admission == nil {
		return nil, errors.New("fresh control-plane admission is required")
	}
	for _, id := range b.order {
		ticket := b.pending[id]
		if ticket == nil || ticket.issued {
			continue
		}
		ticket.issued = true
		ticket.lease = lease
		ticket.call.Admission = *b.admission
		copy := ticket.call
		return &copy, nil
	}
	return nil, nil
}
func (b *relayBroker) complete(lease int64, result BridgeResult) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed || lease != b.lease || b.admission == nil {
		return ErrFenced
	}
	ticket := b.pending[result.ID]
	if ticket == nil || !ticket.issued || ticket.lease != lease {
		return errors.New("native relay is no longer pending")
	}
	if len(result.Result) > 128<<10 || len(result.Error) > 4096 || (len(result.Result) > 0 && !json.Valid(result.Result)) {
		return errors.New("invalid native relay result")
	}
	ticket.done <- result
	delete(b.pending, result.ID)
	b.compact()
	return nil
}
func (b *relayBroker) call(ctx context.Context, call BridgeCall) BridgeResult {
	ticket, denied := b.enqueue(call)
	if ticket == nil {
		return denied
	}
	return b.await(ctx, ticket)
}
func (b *relayBroker) enqueue(call BridgeCall) (*relayTicket, BridgeResult) {
	b.mu.Lock()
	if b.closed || b.admission == nil || call.NativeGeneration != b.nativeGeneration || len(b.pending) >= 16 {
		b.mu.Unlock()
		return nil, BridgeResult{Error: "Pagnet control-plane connection is unavailable; this operation was not forwarded."}
	}
	call.ID = uuid.NewString()
	ticket := &relayTicket{call: call, done: make(chan BridgeResult, 1)}
	b.pending[call.ID] = ticket
	b.order = append(b.order, call.ID)
	b.mu.Unlock()
	return ticket, BridgeResult{}
}
func (b *relayBroker) await(ctx context.Context, ticket *relayTicket) BridgeResult {
	select {
	case result := <-ticket.done:
		return result
	case <-ctx.Done():
		b.mu.Lock()
		issued := ticket.issued
		delete(b.pending, ticket.call.ID)
		b.compact()
		b.mu.Unlock()
		if issued {
			return BridgeResult{Error: "Pagnet relay timed out; this operation may already have been applied. Inspect its result before retrying."}
		}
		return BridgeResult{Error: "Pagnet relay timed out before forwarding; this operation was not applied."}
	}
}
func (b *relayBroker) close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	b.admission = nil
	for id, ticket := range b.pending {
		ticket.done <- BridgeResult{ID: id, Error: "Pagnet session worker is stopping; the relay outcome may be uncertain."}
		delete(b.pending, id)
	}
	b.order = nil
}

// ServeBridge owns a stable native MCP socket and actual per-activation nonce.
// Native clients stay connected across controller changes and daemon socket
// replacement, while each subsequent call requires a current fenced admission.
func (o *SessionOwner) serveBridge(ctx context.Context, ready chan<- struct{}) error {
	path, err := NativeSocketPath(o.journal.dir)
	if err != nil {
		return err
	}
	if err := removeStaleSocket(path); err != nil {
		return err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return err
	}
	defer listener.Close()
	if err := privateSocket(path); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { <-ctx.Done(); _ = listener.Close() }()
	close(ready) // Required listener is bound, private and ready before control advertisement.
	slots := make(chan struct{}, 8)
	var wg sync.WaitGroup
	defer func() { cancel(); wg.Wait() }()
	for {
		c, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		select {
		case slots <- struct{}{}:
		default:
			_ = c.Close()
			continue
		}
		wg.Go(func() { defer func() { <-slots }(); defer c.Close(); o.nativeBridgeConnection(ctx, c) })
	}
}
func bridgeWrite(c net.Conn, value any) error {
	_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	_, err = c.Write(raw)
	return err
}
func (o *SessionOwner) nativeBridgeConnection(ctx context.Context, c *net.UnixConn) {
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	scanner := bufio.NewScanner(c)
	scanner.Buffer(make([]byte, 4096), maxFrame)
	if !scanner.Scan() {
		return
	}
	var auth struct {
		Type       string `json:"type"`
		InstanceID string `json:"instanceId"`
		NetworkID  string `json:"networkId"`
		Nonce      string `json:"nonce"`
		Kind       string `json:"kind"`
	}
	if json.Unmarshal(scanner.Bytes(), &auth) != nil || auth.Type != "auth" || auth.InstanceID != o.journal.scope.InstanceID || auth.NetworkID != o.spec.NetworkID || auth.Kind != o.spec.Kind {
		_ = bridgeWrite(c, map[string]any{"type": "error", "error": "native bridge scope rejected"})
		return
	}
	o.mu.Lock()
	nonce, generation := o.nonce, o.generation
	o.mu.Unlock()
	if nonce == "" || subtle.ConstantTimeCompare([]byte(nonce), []byte(auth.Nonce)) != 1 {
		_ = bridgeWrite(c, map[string]any{"type": "error", "error": "native activation nonce rejected"})
		return
	}
	root := o.supervisor.EndpointPID(o.journal.scope.InstanceID)
	if root == nil {
		return
	}
	authCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	identity, err := o.supervisor.OwnedStartIdentity(authCtx, *root)
	cancel()
	if err != nil || localpeer.VerifyOwned(c, *root, identity) != nil {
		_ = bridgeWrite(c, map[string]any{"type": "error", "error": "native process ownership rejected"})
		return
	}
	if bridgeWrite(c, map[string]any{"type": "auth_ok", "instanceId": o.journal.scope.InstanceID}) != nil {
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = c.Close()
		case <-done:
		}
	}()
	for scanner.Scan() {
		var req struct {
			ID   string          `json:"id"`
			Tool string          `json:"tool"`
			Args json.RawMessage `json:"args"`
		}
		if json.Unmarshal(scanner.Bytes(), &req) != nil || req.ID == "" || len(req.ID) > 256 || len(req.Tool) > 128 || len(req.Args) > 128<<10 {
			_ = bridgeWrite(c, map[string]any{"id": req.ID, "ok": false, "error": "invalid bounded native request"})
			continue
		}
		prefix := "network_"
		if o.spec.Kind == "representative" {
			prefix = "control_"
		}
		if !strings.HasPrefix(req.Tool, prefix) {
			_ = bridgeWrite(c, map[string]any{"id": req.ID, "ok": false, "error": "tool is outside this native identity's surface"})
			continue
		}
		o.mu.Lock()
		valid := generation == o.generation && o.nonce == nonce
		origin := append(json.RawMessage(nil), o.origin...)
		o.mu.Unlock()
		if !valid || !o.driver.Live(o.journal.scope.InstanceID) || localpeer.VerifyOwned(c, *root, identity) != nil {
			return
		}
		if len(req.Args) == 0 {
			req.Args = json.RawMessage(`{}`)
		}
		if !json.Valid(req.Args) {
			_ = bridgeWrite(c, map[string]any{"id": req.ID, "ok": false, "error": "invalid native arguments"})
			continue
		}
		callCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
		sid, known := o.manager.TryNativeID(o.journal.scope.InstanceID)
		if !known || sid == "" {
			cancel()
			return
		}
		source, sourceErr := o.activeBridgeTurnSource(callCtx, generation)
		if sourceErr != nil {
			cancel()
			_ = bridgeWrite(c, map[string]any{"id": req.ID, "ok": false, "error": "native source unavailable"})
			continue
		}
		result := o.forwardBridgeCall(callCtx, BridgeCall{Scope: o.journal.scope, NativeGeneration: generation, NativeSessionID: sid, Origin: origin, Tool: req.Tool, Args: append(json.RawMessage(nil), req.Args...), TurnSource: source})
		cancel()
		result.ID = req.ID
		if bridgeWrite(c, result) != nil {
			return
		}
	}
}

func (b *relayBroker) bindNative(generation string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.nativeGeneration = generation
	for id, ticket := range b.pending {
		message := "Native session changed before this operation was forwarded; it was not applied."
		if ticket.issued {
			message = "Native session changed; this operation may already have been applied. Inspect before retrying."
		}
		ticket.done <- BridgeResult{ID: id, Error: message}
		delete(b.pending, id)
	}
	b.order = nil
}

func (b *relayBroker) authorizeNativeEffect(lease int64) (*Admission, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed || lease != b.lease {
		return nil, ErrFenced
	}
	if b.admission == nil {
		return nil, errors.New("fresh control-plane admission is required before new native effects")
	}
	copy := *b.admission
	return &copy, nil
}

// Native requests cannot nominate a source. Read the actual accepted turn and
// require its still-held original producer capability before forwarding it.
func (o *SessionOwner) activeBridgeTurnSource(ctx context.Context, generation string) (*NativeTurnSource, error) {
	o.mu.Lock()
	candidate := o.candidateTurnSource
	valid := o.generation == generation && !o.closing
	o.mu.Unlock()
	if !valid {
		return nil, ErrFenced
	}
	if candidate.Sequence <= 0 {
		return nil, nil
	}
	sid, ok := o.manager.TryNativeID(o.journal.scope.InstanceID)
	if !ok || sid == "" {
		return nil, ErrConflict
	}
	source, err := o.journal.activeNativeBridgeSource(ctx, generation, sid, logicalWorkerTurn(candidate.Sequence))
	if err != nil || source == nil {
		return nil, err
	}
	if source.InputKind != "task" {
		return source, nil
	}
	if source.SourceTask == nil {
		return nil, ErrConflict
	}
	key, available := o.originalTaskContentPin(source)
	clear(key[:])
	if !available {
		return nil, ErrConflict
	}
	source.SourceTask = cloneNativeTaskSource(source.SourceTask)
	return source, nil
}
