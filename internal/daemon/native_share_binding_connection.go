package daemon

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
)

const nativeShareBindingPayloadLimit = 16 << 10
const nativeShareBindingQueueLimit = 8
const nativeShareBindingError = "native share binding unavailable"

// Deliberately uncomposed in production. The executor must be a ready holder
// store; this interface keeps the dormant socket lane portable to remote CLIs.
type nativeShareBindingExecutor interface {
	nativeShareBindingReady() bool
	Prepare(transport.NativeShareBindingPreparePayload, string, transport.HostSessionPayload) (transport.NativeShareBindingPreparedPayload, error)
	Prove(transport.NativeShareBindingProvePayload, string, transport.HostSessionPayload) (transport.NativeShareBindingProvedPayload, error)
}

type nativeShareBindingAttempt struct {
	id      domain.ID
	prepare *transport.NativeShareBindingPreparePayload
	prove   *transport.NativeShareBindingProvePayload
	session transport.HostSessionPayload
}

type nativeShareBindingConnection struct {
	d        *Daemon
	socket   *websocket.Conn
	native   *NativeObservationConnection
	executor nativeShareBindingExecutor
	endpoint string
	mu       sync.Mutex
	stopped  bool
	pending  map[domain.ID]bool
	queue    chan nativeShareBindingAttempt
	done     chan struct{}
}

func newNativeShareBindingConnection(d *Daemon, socket *websocket.Conn, native *NativeObservationConnection) *nativeShareBindingConnection {
	c := &nativeShareBindingConnection{d: d, socket: socket, native: native, executor: d.nativeShareBindings, endpoint: native.serverURL, pending: make(map[domain.ID]bool), queue: make(chan nativeShareBindingAttempt, nativeShareBindingQueueLimit), done: make(chan struct{})}
	if c.executor != nil && c.executor.nativeShareBindingReady() {
		go c.run()
	}
	return c
}
func (c *nativeShareBindingConnection) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.stopped {
		c.stopped = true
		close(c.done)
	}
}

func (c *nativeShareBindingConnection) active() bool {
	c.d.connMu.Lock()
	defer c.d.connMu.Unlock()
	if c.d.curConn != c.socket || c.d.nativeConn != c.native {
		return false
	}
	select {
	case <-c.native.closed:
		return false
	default:
	}
	select {
	case <-c.done:
		return false
	default:
		return true
	}
}

func (c *nativeShareBindingConnection) handle(env transport.Envelope) bool {
	if env.Type != transport.MsgNativeShareBindingPrepare && env.Type != transport.MsgNativeShareBindingProve {
		return false
	}
	var a nativeShareBindingAttempt
	var err error
	if env.Type == transport.MsgNativeShareBindingPrepare {
		a.prepare = new(transport.NativeShareBindingPreparePayload)
		err = decodeNativeShareBindingPayload(env.Payload, a.prepare)
		a.id = a.prepare.CommandID
	} else {
		a.prove = new(transport.NativeShareBindingProvePayload)
		err = decodeNativeShareBindingPayload(env.Payload, a.prove)
		a.id = a.prove.CommandID
	}
	// Malformed payloads cannot supply an authoritative correlation identifier.
	if err != nil {
		return true
	}
	if _, err = domain.ParseID(string(a.id)); err != nil {
		return true
	}
	a.session, err = c.native.AuthenticatedNativeHostSession()
	count := 0
	for _, f := range a.session.ProtocolFeatures {
		if f == transport.NativeShareBindingProtocol {
			count++
		}
	}
	if err != nil || count != 1 || (c.executor == nil || !c.executor.nativeShareBindingReady()) || !c.active() {
		c.ack(a.id, nil)
		return true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stopped || c.pending[a.id] {
		return true
	}
	if len(c.pending) >= nativeShareBindingQueueLimit {
		c.ack(a.id, nil)
		return true
	}
	c.pending[a.id] = true
	c.queue <- a
	return true
}

func (c *nativeShareBindingConnection) run() {
	for {
		select {
		case <-c.done:
			return
		case a := <-c.queue:
			if c.active() {
				if a.prepare != nil {
					result, err := c.executor.Prepare(*a.prepare, c.endpoint, a.session)
					if err == nil {
						c.ack(a.id, result)
					} else {
						c.ack(a.id, nil)
					}
				} else {
					result, err := c.executor.Prove(*a.prove, c.endpoint, a.session)
					if err == nil {
						c.ack(a.id, result)
					} else {
						c.ack(a.id, nil)
					}
					clear(result.Challenge)
					clear(result.Signature)
				}
			}
			c.mu.Lock()
			delete(c.pending, a.id)
			c.mu.Unlock()
		}
	}
}

// No generic send/ACK helper: those may retarget and/or persist command results.
func (c *nativeShareBindingConnection) ack(id domain.ID, result any) {
	payload := struct {
		CommandID domain.ID `json:"commandId"`
		Error     string    `json:"error,omitempty"`
		Result    any       `json:"result,omitempty"`
	}{CommandID: id, Result: result}
	if result == nil {
		payload.Error = nativeShareBindingError
	}
	env, err := transport.NewEnvelope(transport.MsgCommandAck, payload)
	if err != nil {
		return
	}
	defer clear(env.Payload)
	raw, err := json.Marshal(env)
	if err != nil {
		return
	}
	defer clear(raw)
	// Serialize before checking ownership so a writer waiting behind another
	// frame cannot reply after supersession. Keep ownership fenced through write.
	c.d.writeMu.Lock()
	c.d.connMu.Lock()
	c.native.mu.Lock()
	if c.d.curConn != c.socket || c.d.nativeConn != c.native || c.native.session == nil {
		c.native.mu.Unlock()
		c.d.connMu.Unlock()
		c.d.writeMu.Unlock()
		return
	}
	select {
	case <-c.done:
		c.native.mu.Unlock()
		c.d.connMu.Unlock()
		c.d.writeMu.Unlock()
		return
	default:
	}
	_ = c.socket.SetWriteDeadline(time.Now().Add(c.d.writeTimeout))
	err = c.socket.WriteMessage(websocket.TextMessage, raw)
	c.native.mu.Unlock()
	c.d.connMu.Unlock()
	c.d.writeMu.Unlock()
	if err != nil {
		c.d.invalidateCurrentConnection(c.socket)
	}
}

// Token validation precedes typed decoding: encoding/json alone accepts duplicate
// keys and case-insensitive field aliases. Every object uses exact JSON tags.
func decodeNativeShareBindingPayload(raw []byte, target any) error {
	if len(raw) == 0 || len(raw) > nativeShareBindingPayloadLimit {
		return errors.New(nativeShareBindingError)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := nativeShareBindingJSONValue(dec, reflect.TypeOf(target).Elem(), 0); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New(nativeShareBindingError)
	}
	return json.Unmarshal(raw, target)
}
func nativeShareBindingJSONValue(dec *json.Decoder, typ reflect.Type, depth int) error {
	if depth > 8 {
		return errors.New(nativeShareBindingError)
	}
	token, err := dec.Token()
	if err != nil {
		return err
	}
	if typ.Kind() != reflect.Struct {
		if _, ok := token.(json.Delim); ok {
			return errors.New(nativeShareBindingError)
		}
		return nil
	}
	if token != json.Delim('{') {
		return errors.New(nativeShareBindingError)
	}
	fields := make(map[string]reflect.Type)
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		fields[strings.Split(f.Tag.Get("json"), ",")[0]] = f.Type
	}
	seen := make(map[string]bool)
	for dec.More() {
		token, err = dec.Token()
		if err != nil {
			return err
		}
		name, ok := token.(string)
		if !ok || seen[name] || fields[name] == nil {
			return errors.New(nativeShareBindingError)
		}
		seen[name] = true
		if err = nativeShareBindingJSONValue(dec, fields[name], depth+1); err != nil {
			return err
		}
	}
	token, err = dec.Token()
	if err != nil || token != json.Delim('}') {
		return errors.New(nativeShareBindingError)
	}
	return nil
}
