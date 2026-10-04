package a2a

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/pagnet-code/pagnet/fabric"
	"io"
	"strings"
	"sync"
)

var errBound = errors.New("A2A bounded wire event or stream exhausted")

type rawTap struct {
	mu      sync.Mutex
	records []json.RawMessage
	bytes   int
	max     int
	id      json.RawMessage
}

func (t *rawTap) push(raw []byte) error {
	var response struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  json.RawMessage `json:"result"`
		Error   json.RawMessage `json:"error"`
	}
	limits := fabric.DefaultWireLimits
	limits.MaxBytes = t.max + 1024
	if fabric.DecodeJSONWithLimits(raw, &response, limits) != nil || response.JSONRPC != "2.0" || !bytes.Equal(bytes.TrimSpace(response.ID), bytes.TrimSpace(t.id)) {
		return ErrAssociation
	}
	if len(response.Error) != 0 && string(response.Error) != "null" {
		return nil
	}
	if len(response.Result) == 0 || len(response.Result) > t.max {
		return errBound
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.bytes+len(response.Result) > t.max+8192 || len(t.records) >= 128 {
		return errBound
	}
	t.records = append(t.records, append(json.RawMessage(nil), response.Result...))
	t.bytes += len(response.Result)
	return nil
}
func (t *rawTap) take() (json.RawMessage, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.records) == 0 {
		return nil, ErrAssociation
	}
	raw := t.records[0]
	t.records[0] = nil
	t.records = t.records[1:]
	t.bytes -= len(raw)
	return raw, nil
}

// boundedBody observes SDK-selected JSON-RPC results without altering protocol
// negotiation or yielding reserialized maps. Reads are bounded to avoid the
// scanner reading arbitrarily many not-yet-consumed event records ahead.
type boundedBody struct {
	source      io.ReadCloser
	tap         *rawTap
	max         int
	total       int64
	budget      int64
	line, event []byte
	failure     error
	ended       bool
}

func (b *boundedBody) Read(p []byte) (int, error) {
	if b.failure != nil {
		return 0, b.failure
	}
	if b.ended {
		return 0, io.EOF
	}
	if len(p) > 4096 {
		p = p[:4096]
	}
	n, e := b.source.Read(p)
	b.total += int64(n)
	if b.total > b.budget {
		b.failure = errBound
		return 0, b.failure
	}

	for _, ch := range p[:n] {
		if ch == '\n' {
			if err := b.lineDone(); err != nil {
				b.failure = err
				return 0, err
			}
		} else {
			b.line = append(b.line, ch)
			if len(b.line) > b.max+1024 {
				b.failure = errBound
				return 0, b.failure
			}
		}
	}
	if e == io.EOF {
		b.ended = true
		if len(b.line) > 0 {
			if err := b.lineDone(); err != nil {
				return 0, err
			}
		}
		if len(b.event) > 0 {
			if err := b.tap.push(b.event); err != nil {
				return 0, err
			}
		}
	}
	return n, e
}
func (b *boundedBody) lineDone() error {
	line := bytes.TrimSuffix(b.line, []byte{'\r'})
	b.line = nil
	if len(line) == 0 {
		if len(b.event) > 0 {
			e := b.tap.push(b.event)
			b.event = nil
			return e
		}
		return nil
	}
	if bytes.HasPrefix(line, []byte("data:")) {
		value := strings.TrimPrefix(string(line), "data:")
		value = strings.TrimPrefix(value, " ")
		if len(b.event) > 0 {
			b.event = append(b.event, '\n')
		}
		b.event = append(b.event, value...)
		if len(b.event) > b.max+1024 {
			return errBound
		}
	}
	return nil
}
func (b *boundedBody) Close() error { return b.source.Close() }
