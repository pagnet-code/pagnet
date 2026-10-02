package runtime

// ACP's newline-delimited JSON-RPC transport is independent of any vendor.
// Stdout is exclusively protocol data; stderr stays in the process supervisor.
import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/pagnet-code/pagnet/internal/session"
	"io"
	"sync"
)

const acpMaxFrame = 16 << 20

var errACPDeliveryUncertain = errors.New("ACP delivery outcome uncertain")

type acpMessage struct {
	replyMethod      string
	nativePermission *session.InteractionEvent
	JSONRPC          string          `json:"jsonrpc"`
	ID               json.RawMessage `json:"id,omitempty"`
	Method           string          `json:"method,omitempty"`
	Params           json.RawMessage `json:"params,omitempty"`
	Result           json.RawMessage `json:"result,omitempty"`
	Error            *acpRPCError    `json:"error,omitempty"`
}
type acpRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *acpRPCError) Error() string { return fmt.Sprintf("ACP request failed (code %d)", e.Code) }

type acpWrite struct {
	data   []byte
	result chan error
}
type acpCall struct {
	id       string
	response chan acpMessage
}
type acpConnection struct {
	observe        func(*acpMessage) error
	pendingMethods map[string]string
	input          io.WriteCloser
	output         io.ReadCloser
	writes         chan acpWrite
	messages       chan acpMessage
	done           chan struct{}
	readerDone     chan struct{}
	retire         func()
	once           sync.Once
	mu             sync.Mutex
	next           uint64
	pending        map[string]chan acpMessage
	err            error
}

func newACPConnection(input io.WriteCloser, output io.ReadCloser) *acpConnection {
	return newOwnedACPConnection(input, output, nil)
}
func newOwnedACPConnection(input io.WriteCloser, output io.ReadCloser, retire func(), observers ...func(*acpMessage) error) *acpConnection {
	c := &acpConnection{input: input, output: output, writes: make(chan acpWrite, 16), messages: make(chan acpMessage, 128), done: make(chan struct{}), pending: map[string]chan acpMessage{}, readerDone: make(chan struct{}), retire: retire}
	c.pendingMethods = map[string]string{}
	if len(observers) > 0 {
		c.observe = observers[0]
	}
	go c.writeLoop()
	go c.readLoop()
	return c
}
func (c *acpConnection) close(err error) {
	c.once.Do(func() {
		c.mu.Lock()
		c.err = err
		c.mu.Unlock()
		close(c.done)
		_ = c.input.Close()
		_ = c.output.Close()
	})
}
func (c *acpConnection) failure() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return c.err
	}
	return io.EOF
}
func (c *acpConnection) writeLoop() {
	for {
		select {
		case <-c.done:
			return
		case w := <-c.writes:
			n, err := c.input.Write(w.data)
			if err == nil && n != len(w.data) {
				err = io.ErrShortWrite
			}
			if err != nil && n > 0 {
				err = fmt.Errorf("%w: %w", errACPDeliveryUncertain, err)
			}
			w.result <- err
			if err != nil {
				c.close(err)
				return
			}
		}
	}
}
func (c *acpConnection) readLoop() {
	defer close(c.readerDone)
	if c.retire != nil {
		defer c.retire()
	}
	scanner := bufio.NewScanner(c.output)
	scanner.Buffer(make([]byte, 4096), acpMaxFrame)
	for scanner.Scan() {
		var m acpMessage
		if json.Unmarshal(scanner.Bytes(), &m) != nil || m.JSONRPC != "2.0" {
			c.close(errors.New("ACP received malformed protocol frame"))
			return
		}
		if m.Method == "" {
			if len(m.ID) == 0 || (len(m.Result) == 0) == (m.Error == nil) {
				c.close(errors.New("ACP received malformed response"))
				return
			}
			c.mu.Lock()
			pending := c.pending[string(m.ID)]
			m.replyMethod = c.pendingMethods[string(m.ID)]
			c.mu.Unlock()
			if c.observe != nil {
				if err := c.observe(&m); err != nil {
					c.close(err)
					return
				}
			}
			if pending != nil {
				select {
				case pending <- m:
				default:
					c.close(errors.New("ACP duplicate response"))
					return
				}
			}
			continue
		}
		if c.observe != nil {
			if err := c.observe(&m); err != nil {
				c.close(err)
				return
			}
		}
		select {
		case c.messages <- m:
		case <-c.done:
			return
		default:
			c.close(errors.New("ACP protocol event buffer overflow"))
			return
		}
	}
	err := scanner.Err()
	if err == nil {
		err = io.EOF
	}
	c.close(err)
}
func (c *acpConnection) send(ctx context.Context, message any) error {
	data, err := json.Marshal(message)
	if err != nil {
		return err
	}
	if len(data) > acpMaxFrame-1 {
		return errors.New("ACP frame too large")
	}
	data = append(data, '\n')
	write := acpWrite{data: data, result: make(chan error, 1)}
	select {
	case c.writes <- write:
	case <-ctx.Done():
		return ctx.Err()
	case <-c.done:
		return c.failure()
	}
	select {
	case err := <-write.result:
		return err
	case <-ctx.Done():
		return fmt.Errorf("%w: %w", errACPDeliveryUncertain, ctx.Err())
	case <-c.done:
		// Prefer a completed write acknowledgement over EOF: a complete prompt
		// may already have applied tools and must never be retried automatically.
		select {
		case err := <-write.result:
			return err
		default:
			return fmt.Errorf("%w: %w", errACPDeliveryUncertain, c.failure())
		}
	}
}
func (c *acpConnection) begin(ctx context.Context, method string, params any) (*acpCall, error) {
	c.mu.Lock()
	c.next++
	id := fmt.Sprint(c.next)
	reply := make(chan acpMessage, 1)
	c.pending[id] = reply
	c.pendingMethods[id] = method
	c.mu.Unlock()
	call := &acpCall{id: id, response: reply}
	if err := c.send(ctx, map[string]any{"jsonrpc": "2.0", "id": json.RawMessage(id), "method": method, "params": params}); err != nil {
		c.finish(call)
		return nil, err
	}
	return call, nil
}
func (c *acpConnection) finish(call *acpCall) {
	c.mu.Lock()
	delete(c.pending, call.id)
	delete(c.pendingMethods, call.id)
	c.mu.Unlock()
}
func (c *acpConnection) notify(ctx context.Context, method string, params any) error {
	return c.send(ctx, map[string]any{"jsonrpc": "2.0", "method": method, "params": params})
}
func (c *acpConnection) respond(ctx context.Context, id json.RawMessage, result any) error {
	return c.send(ctx, map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
}
func (c *acpConnection) reject(ctx context.Context, id json.RawMessage, code int) error {
	return c.send(ctx, map[string]any{"jsonrpc": "2.0", "id": id, "error": acpRPCError{Code: code, Message: "Unsupported client method"}})
}
func (c *acpConnection) request(ctx context.Context, method string, params any, result any) error {
	call, err := c.begin(ctx, method, params)
	if err != nil {
		return err
	}
	defer c.finish(call)
	for {
		select {
		case response := <-call.response:
			if response.Error != nil {
				return response.Error
			}
			if result != nil {
				return json.Unmarshal(response.Result, result)
			}
			return nil
		case message := <-c.messages: // Session/load history is replay, never a new turn.
			if len(message.ID) > 0 {
				if err := c.reject(ctx, message.ID, -32601); err != nil {
					return err
				}
			}
		case <-ctx.Done():
			return ctx.Err()
		case <-c.done:
			return c.failure()
		}
	}
}
