package actions

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/events/durable"
	"github.com/pagnet-code/pagnet/fabric/internal/privatefs"
)

type Store struct {
	config      Config
	queue       *durable.Store
	lock        io.Closer
	definitions map[string]TriggerDefinition
	matches     map[triggerKey][]TriggerDefinition
	mu          sync.Mutex
	closed      bool
	active      sync.WaitGroup
	activeCount int
	done        chan struct{}
	closeError  error
	worker      *durable.Workers
}
type triggerKey struct{ source, kind string }
type checkpoint struct {
	Version                                                    int                 `json:"version"`
	Scope                                                      durable.Scope       `json:"scope"`
	Definitions                                                []TriggerDefinition `json:"definitions"`
	MaxDefinitions, MaxFanout, MaxProofBytes, MaxEnvelopeBytes int
	Queue                                                      durable.Config       `json:"queue"`
	Key                                                        durable.KeyReference `json:"key"`
}

func invalid() error {
	return fabric.NewError(fabric.CodeInvalidInput, "Invalid durable action configuration or input")
}
func denied() error {
	return fabric.NewError(fabric.CodeUnauthenticated, "Current authenticated action authority required")
}
func unavailable() error {
	return fabric.NewError(fabric.CodeProtocolError, "Protected action state unavailable")
}
func digest(b []byte) string { d := sha256.Sum256(b); return hex.EncodeToString(d[:]) }
func Bootstrap(ctx context.Context, dir string, c Config) (*Store, error) {
	return open(ctx, dir, c, true)
}
func Open(ctx context.Context, dir string, c Config) (*Store, error) { return open(ctx, dir, c, false) }
func open(ctx context.Context, dir string, c Config, create bool) (*Store, error) {
	// The Admitter is a delivery-time dependency (consumed by the worker
	// handler), not an open-time one: an explicit setup/open that only verifies
	// the retained queue/registrations may legitimately carry no Admitter.
	if ctx == nil || ctx.Err() != nil || c.Scope.Audience == "" || c.Scope.Domain == "" || c.Protector == nil || c.SourceAuthority == nil || c.DefinitionAuthority == nil || c.Authorizer == nil || c.MaxDefinitions < 1 || c.MaxDefinitions > 1024 || len(c.Definitions) > c.MaxDefinitions || c.MaxFanout < 1 || c.MaxFanout > 128 || c.MaxProofBytes < 1 || c.MaxProofBytes > 65536 || c.MaxEnvelopeBytes < 1024 || c.MaxEnvelopeBytes > 65536 {
		return nil, invalid()
	}
	if len(c.Queue.Subscriptions) != 1 || c.Queue.Subscriptions[0].ID != "actions.dispatch" || len(c.Queue.Subscriptions[0].Types) != 1 || c.Queue.Subscriptions[0].Types[0] != "dev.pagnet.actions.queued" {
		return nil, invalid()
	}
	defs := append([]TriggerDefinition(nil), c.Definitions...)
	sort.Slice(defs, func(i, j int) bool { return defs[i].ID < defs[j].ID })
	byID := map[string]TriggerDefinition{}
	for i, d := range defs {
		if !fabric.ValidNamespacedName(d.ID) || len(d.ID) > 128 || len(d.Revision) == 0 || len(d.Revision) > 128 || len(d.Source) == 0 || len(d.Source) > 4096 || !validSource(d.Source) || !fabric.ValidNamespacedName(d.Type) || d.Target.String() == "" || len(d.TargetRevision) == 0 || len(d.TargetRevision) > 128 || len(d.BindingDigest) != 64 || len(d.SignedAuthorization) == 0 || len(d.SignedAuthorization) > 65536 || byID[d.ID].ID != "" {
			return nil, invalid()
		}
		if _, e := hex.DecodeString(d.BindingDigest); e != nil {
			return nil, invalid()
		}
		if e := fabric.DecodeJSON(d.SignedAuthorization, new(any)); e != nil {
			return nil, invalid()
		}
		d.SignedAuthorization = bytes.Clone(d.SignedAuthorization)
		if c.DefinitionAuthority.Verify(ctx, c.Scope, cloneDefinition(d)) != nil {
			return nil, denied()
		}
		byID[d.ID] = d
		defs[i] = d
	}
	c.Definitions = defs
	raw, e := json.Marshal(checkpoint{1, c.Scope, defs, c.MaxDefinitions, c.MaxFanout, c.MaxProofBytes, c.MaxEnvelopeBytes, c.Queue, c.Protector.Reference()})
	if e != nil || len(raw) > 512<<10 {
		return nil, invalid()
	}
	// Own the normalized checkpoint slices; later caller mutation is not registration.
	var owned checkpoint
	if fabric.DecodeJSONWithLimits(raw, &owned, fabric.WireLimits{MaxBytes: 512 << 10, MaxDepth: 64, MaxMembers: 16384}) != nil {
		return nil, invalid()
	}
	byID = map[string]TriggerDefinition{}
	matches := map[triggerKey][]TriggerDefinition{}
	for _, d := range owned.Definitions {
		byID[d.ID] = cloneDefinition(d)
		key := triggerKey{d.Source, d.Type}
		matches[key] = append(matches[key], cloneDefinition(d))
	}
	c.Definitions = owned.Definitions
	c.Queue = owned.Queue
	aad, _ := json.Marshal(struct {
		Version int
		Scope   durable.Scope
		Key     durable.KeyReference
	}{1, c.Scope, c.Protector.Reference()})
	if create {
		if e = privatefs.CreateDirectory(dir); e != nil {
			return nil, unavailable()
		}
	}
	lock, e := privatefs.Acquire(dir, "actions.lock")
	if e != nil {
		return nil, unavailable()
	}
	keep := false
	defer func() {
		if !keep {
			lock.Close()
		}
	}()
	path := filepath.Join(dir, "registrations.sealed")
	if create {
		cipher, e := c.Protector.Seal(aad, raw)
		if e != nil || len(cipher) > 520<<10 {
			return nil, unavailable()
		}
		f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return nil, unavailable()
		}
		_, e = f.Write(cipher)
		if e == nil {
			e = f.Sync()
		}
		ce := f.Close()
		if e != nil || ce != nil || privatefs.SyncDirectory(dir) != nil {
			return nil, unavailable()
		}
	} else {
		cipher, e := privatefs.ReadFile(path, 520<<10)
		if e != nil {
			return nil, unavailable()
		}
		plain, e := c.Protector.Open(aad, cipher)
		if e != nil || !bytes.Equal(plain, raw) {
			return nil, unavailable()
		}
	}
	var q *durable.Store
	if create {
		q, e = durable.Bootstrap(ctx, filepath.Join(dir, "queue"), c.Scope, c.Queue, c.Protector)
	} else {
		q, e = durable.Open(ctx, filepath.Join(dir, "queue"), c.Scope, c.Queue, c.Protector)
	}
	if e != nil {
		return nil, e
	}
	keep = true
	return &Store{config: c, queue: q, lock: lock, definitions: byID, matches: matches, done: make(chan struct{})}, nil
}
func (s *Store) begin() (func(), error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.activeCount >= 32 {
		return nil, unavailable()
	}
	s.active.Add(1)
	s.activeCount++
	return func() { s.mu.Lock(); s.activeCount--; s.mu.Unlock(); s.active.Done() }, nil
}

// CloseContext cancels the owned worker and joins original callbacks before
// releasing the private writer lease. Ignoring providers honestly retain it.
func (s *Store) CloseContext(ctx context.Context) error {
	if ctx == nil {
		return invalid()
	}
	s.mu.Lock()
	if !s.closed {
		s.closed = true
		worker := s.worker
		go func() {
			if worker != nil {
				_ = worker.Close(context.Background())
			}
			s.active.Wait()
			e := s.queue.Close()
			le := s.lock.Close()
			if e == nil {
				e = le
			}
			s.mu.Lock()
			s.closeError = e
			s.mu.Unlock()
			close(s.done)
		}()
	}
	s.mu.Unlock()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.done:
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.closeError
	}
}
func (s *Store) Close() error { return s.CloseContext(context.Background()) }

func validSource(s string) bool {
	if !utf8.ValidString(s) || strings.ContainsAny(s, "\x00\r\n") {
		return false
	}
	u, e := url.Parse(s)
	return e == nil && u.IsAbs() && u.User == nil && u.String() == s && ((u.Scheme != "http" && u.Scheme != "https") || u.Host != "")
}
