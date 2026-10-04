// Package snapshot retains finite authenticated ranked-result horizons.
// The owning retriever supplies fresh policy and index validation on every page.
package snapshot

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
)

var ErrStale = errors.New("discovery snapshot expired or its authority/index changed")

type Config struct {
	MaxSnapshots, MaxBytes int
	TTL                    time.Duration
	Key                    []byte
	Now                    func() time.Time
}
type State struct {
	Binding, Scope   string
	Policy, Revision fabric.Revision
	IndexRevisions   []fabric.Revision
	Candidates       []fabric.Candidate
}
type Validate func(context.Context, fabric.DiscoverRequest, State, []fabric.Candidate) error
type entry struct {
	state    State
	id       string
	expires  time.Time
	size     int
	sequence uint64
}
type Pager struct {
	config   Config
	key      []byte
	mu       sync.Mutex
	entries  map[string]*entry
	bytes    int
	sequence uint64
}

func New(c Config) (*Pager, error) {
	if c.MaxSnapshots == 0 {
		c.MaxSnapshots = 64
	}
	if c.MaxBytes == 0 {
		c.MaxBytes = 4 << 20
	}
	if c.TTL == 0 {
		c.TTL = 5 * time.Minute
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.MaxSnapshots < 1 || c.MaxSnapshots > 4096 || c.MaxBytes < 1 || c.MaxBytes > 64<<20 || c.TTL <= 0 || c.TTL > time.Hour {
		return nil, errors.New("invalid finite snapshot limits")
	}
	key := append([]byte(nil), c.Key...)
	if len(key) == 0 {
		key = make([]byte, 32)
		if _, e := rand.Read(key); e != nil {
			return nil, e
		}
	}
	if len(key) < 32 || len(key) > 4096 {
		return nil, errors.New("cursor key must contain32..4096 bytes")
	}
	c.Key = nil
	return &Pager{config: c, key: key, entries: map[string]*entry{}}, nil
}
func clone[T any](v T) T {
	raw, _ := json.Marshal(v)
	var out T
	_ = json.Unmarshal(raw, &out)
	return out
}
func valid(s State) bool {
	if s.Binding == "" || len(s.Binding) > 256 || s.Scope == "" || len(s.Scope) > 1024 || s.Policy == "" || len(s.Policy) > 256 || s.Revision == "" || len(s.Revision) > 256 || len(s.IndexRevisions) > 8 || len(s.Candidates) > 200 {
		return false
	}
	seen := map[string]bool{}
	for _, c := range s.Candidates {
		key := c.Document.Ref.String()
		if _, e := fabric.ParseEndpointRef(key); e != nil || seen[key] || c.Document.Revision == "" || math.IsNaN(c.Score) || math.IsInf(c.Score, 0) {
			return false
		}
		seen[key] = true
	}
	return true
}
func (p *Pager) Store(ctx context.Context, r fabric.DiscoverRequest, s State) (fabric.DiscoverResult, error) {
	if err := ctx.Err(); err != nil {
		return fabric.DiscoverResult{}, err
	}
	if err := r.Validate(); err != nil {
		return fabric.DiscoverResult{}, err
	}
	if r.Cursor != "" || !valid(s) {
		return fabric.DiscoverResult{}, errors.New("invalid ranked snapshot")
	}
	raw, e := json.Marshal(s)
	if e != nil {
		return fabric.DiscoverResult{}, e
	}
	if len(raw) > p.config.MaxBytes {
		return fabric.DiscoverResult{}, errors.New("ranked snapshot exceeds configured byte budget")
	}
	s = clone(s)
	if len(s.Candidates) <= r.Limit {
		return fabric.DiscoverResult{Candidates: s.Candidates, IndexRevision: s.Revision}, ctx.Err()
	}
	id := make([]byte, 24)
	if _, e = rand.Read(id); e != nil {
		return fabric.DiscoverResult{}, e
	}
	item := &entry{state: s, id: base64.RawURLEncoding.EncodeToString(id), expires: p.config.Now().Add(p.config.TTL), size: len(raw) + 128}
	if item.size > p.config.MaxBytes {
		return fabric.DiscoverResult{}, errors.New("ranked snapshot exceeds configured byte budget")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return fabric.DiscoverResult{}, err
	}
	now := p.config.Now()
	for id, old := range p.entries {
		if !old.expires.After(now) {
			delete(p.entries, id)
			p.bytes -= old.size
		}
	}
	for len(p.entries) >= p.config.MaxSnapshots || p.bytes+item.size > p.config.MaxBytes {
		var oldest *entry
		for _, old := range p.entries {
			if oldest == nil || old.sequence < oldest.sequence {
				oldest = old
			}
		}
		delete(p.entries, oldest.id)
		p.bytes -= oldest.size
	}
	p.sequence++
	item.sequence = p.sequence
	p.entries[item.id] = item
	p.bytes += item.size
	return p.slice(item, 0, r.Limit), ctx.Err()
}

type cursor struct {
	Snapshot, Binding, Scope string
	Policy                   fabric.Revision
	Offset                   int
}

func (p *Pager) token(e *entry, offset int) string {
	raw, _ := json.Marshal(cursor{e.id, e.state.Binding, e.state.Scope, e.state.Policy, offset})
	mac := hmac.New(sha256.New, p.key)
	_, _ = mac.Write(raw)
	return base64.RawURLEncoding.EncodeToString(raw) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
func (p *Pager) decode(token string) (cursor, error) {
	var c cursor
	if len(token) > 4096 {
		return c, ErrStale
	}
	left, right, ok := strings.Cut(token, ".")
	raw, e := base64.RawURLEncoding.DecodeString(left)
	sig, e2 := base64.RawURLEncoding.DecodeString(right)
	if !ok || e != nil || e2 != nil {
		return c, ErrStale
	}
	mac := hmac.New(sha256.New, p.key)
	_, _ = mac.Write(raw)
	if !hmac.Equal(sig, mac.Sum(nil)) || json.Unmarshal(raw, &c) != nil {
		return c, ErrStale
	}
	return c, nil
}
func (p *Pager) slice(e *entry, offset, limit int) fabric.DiscoverResult {
	end := offset + limit
	if end > len(e.state.Candidates) {
		end = len(e.state.Candidates)
	}
	r := fabric.DiscoverResult{Candidates: clone(e.state.Candidates[offset:end]), IndexRevision: e.state.Revision}
	if end < len(e.state.Candidates) {
		r.NextCursor = p.token(e, end)
	}
	return r
}
func (p *Pager) Page(ctx context.Context, r fabric.DiscoverRequest, binding string, validate Validate) (fabric.DiscoverResult, error) {
	if err := ctx.Err(); err != nil {
		return fabric.DiscoverResult{}, err
	}
	if err := r.Validate(); err != nil {
		return fabric.DiscoverResult{}, err
	}
	c, err := p.decode(r.Cursor)
	if err != nil {
		return fabric.DiscoverResult{}, err
	}
	p.mu.Lock()
	e := p.entries[c.Snapshot]
	p.mu.Unlock()
	if e == nil || !e.expires.After(p.config.Now()) || c.Offset < 1 || c.Offset >= len(e.state.Candidates) || c.Binding != e.state.Binding || c.Scope != e.state.Scope || c.Policy != e.state.Policy || binding != e.state.Binding || validate == nil {
		return fabric.DiscoverResult{}, ErrStale
	}
	result := p.slice(e, c.Offset, r.Limit)
	if err = validate(ctx, clone(r), clone(e.state), clone(result.Candidates)); err != nil {
		return fabric.DiscoverResult{}, err
	}
	return result, ctx.Err()
}
func (p *Pager) Stats() (count, bytes int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.entries), p.bytes
}
