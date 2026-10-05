package fabricservices

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/events/durable"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

// Startup records only an operator's explicit connection choices, not catalog
// discovery or authority. Its encrypted manifest belongs to the SAME root.
// A startup handshake may publish tool metadata but never executes a tool.
type Startup struct {
	ledger *Invocations
	max    int
}
type StartupSelection struct {
	Scope       registry.DescriptorBatchScope `json:"scope"`
	Protocol    string                        `json:"protocol"`
	Version     string                        `json:"version"`
	Account     [32]byte                      `json:"account"`
	Fingerprint [32]byte                      `json:"fingerprint"`
}
type startupHead struct {
	Format     int                  `json:"format"`
	Key        durable.KeyReference `json:"key"`
	Max        int                  `json:"max"`
	Generation uint64               `json:"generation"`
	Count      int                  `json:"count"`
	Digest     [32]byte             `json:"digest"`
}
type startupPage struct {
	Generation uint64             `json:"generation"`
	Selections []StartupSelection `json:"selections"`
}

const startupPageSize = 16

func startupID(n int) string { return fmt.Sprintf("startup/page/%d", n) }
func startupDigest(v []StartupSelection) [32]byte {
	raw, _ := json.Marshal(v)
	defer clear(raw)
	return sha256.Sum256(raw)
}
func newStartup(i *Invocations, max int) (*Startup, error) {
	if i == nil || max < 1 || max > 256 {
		return nil, denied()
	}
	return &Startup{i, max}, nil
}

// BootstrapStartup is explicit first setup. Missing manifests never regenerate
// during Open or service lookup; changed capacity/key is not a valid Open.
func BootstrapStartup(ctx context.Context, i *Invocations, max int) (*Startup, error) {
	s, e := newStartup(i, max)
	if e != nil {
		return nil, e
	}
	e = i.with(ctx, registry.DescriptorBatchScope{}, func(_ context.Context, tx *registry.AuthorityTx) error {
		if _, _, e := i.state(tx); e != nil {
			return e
		}
		if _, e := tx.Get(serviceKey("startup/header")); !missing(e) {
			return denied()
		}
		empty := []StartupSelection{}
		raw, e := i.encode("startup/header", startupHead{Format: 1, Key: i.profiles.protector.Reference(), Max: max, Generation: 1, Digest: startupDigest(empty)})
		if e != nil {
			return e
		}
		_, e = tx.CAS(serviceKey("startup/header"), 0, raw, false)
		return e
	})
	if e != nil {
		return nil, e
	}
	return s, nil
}
func OpenStartup(ctx context.Context, i *Invocations, max int) (*Startup, error) {
	s, e := newStartup(i, max)
	if e != nil {
		return nil, e
	}
	_, e = s.Selections(ctx)
	if e != nil {
		return nil, e
	}
	return s, nil
}
func (s *Startup) load(tx *registry.AuthorityTx) (startupHead, registry.AuthorityRecord, []StartupSelection, error) {
	var h startupHead
	row, e := s.ledger.decode(tx, "startup/header", &h)
	if e != nil {
		return h, row, nil, e
	}
	if h.Format != 1 || h.Key != s.ledger.profiles.protector.Reference() || h.Max != s.max || h.Generation == 0 || h.Count < 0 || h.Count > s.max {
		return h, row, nil, denied()
	}
	choices := make([]StartupSelection, 0, h.Count)
	for page := 0; page < (h.Count+startupPageSize-1)/startupPageSize; page++ {
		var p startupPage
		if _, e = s.ledger.decode(tx, startupID(page), &p); e != nil {
			return h, row, nil, e
		}
		expected := startupPageSize
		if page == h.Count/startupPageSize {
			expected = h.Count % startupPageSize
		}
		if p.Generation != h.Generation || len(p.Selections) != expected {
			return h, row, nil, denied()
		}
		for _, c := range p.Selections {
			if c.Scope.Endpoint.String() == "" || c.Scope.ExpectedEndpointRevision == "" || c.Scope.BindingID == "" || c.Scope.ExpectedProjectionRevision != 0 || c.Account == ([32]byte{}) || c.Fingerprint == ([32]byte{}) || (c.Protocol != "mcp.tools" && c.Protocol != "a2a.jsonrpc") || !validText(c.Version, 128) {
				return h, row, nil, denied()
			}
			choices = append(choices, c)
		}
	}
	if len(choices) != h.Count || startupDigest(choices) != h.Digest {
		return h, row, nil, denied()
	}
	for n := 1; n < len(choices); n++ {
		if connectionKey(choices[n-1].Scope) >= connectionKey(choices[n].Scope) {
			return h, row, nil, denied()
		}
	}
	return h, row, choices, nil
}
func (s *Startup) Selections(ctx context.Context) ([]StartupSelection, error) {
	if s == nil {
		return nil, denied()
	}
	var choices []StartupSelection
	e := s.with(ctx, registry.DescriptorBatchScope{}, func(_ context.Context, tx *registry.AuthorityTx) error {
		if _, _, e := s.ledger.state(tx); e != nil {
			return e
		}
		_, _, v, e := s.load(tx)
		choices = v
		return e
	})
	return choices, e
}
func (s *Startup) save(tx *registry.AuthorityTx, h startupHead, row registry.AuthorityRecord, choices []StartupSelection) error {
	if h.Generation == ^uint64(0) || len(choices) > s.max {
		return denied()
	}
	h.Generation++
	h.Count = len(choices)
	h.Digest = startupDigest(choices)
	for page := 0; page < (len(choices)+startupPageSize-1)/startupPageSize; page++ {
		end := (page + 1) * startupPageSize
		if end > len(choices) {
			end = len(choices)
		}
		id := startupID(page)
		raw, e := s.ledger.encode(id, startupPage{h.Generation, choices[page*startupPageSize : end]})
		if e != nil {
			return e
		}
		old, e := tx.Get(serviceKey(id))
		if e != nil && !missing(e) {
			return e
		}
		revision := uint64(0)
		if e == nil {
			revision = old.Revision
		}
		if _, e = tx.CAS(serviceKey(id), revision, raw, false); e != nil {
			return e
		}
	}
	// Unused prior pages remain encrypted immutable ledger history, unreachable
	// by the authenticated count/digest. No replay/source history is purged.
	raw, e := s.ledger.encode("startup/header", h)
	if e != nil {
		return e
	}
	_, e = tx.CAS(serviceKey("startup/header"), row.Revision, raw, false)
	return e
}

// Select persists choice BEFORE opening an external connection. A failed
// handshake remains selected/offline; it never routes to an alternative.
func (s *Startup) Select(ctx context.Context, scope registry.DescriptorBatchScope) (StartupSelection, error) {
	if s == nil {
		return StartupSelection{}, denied()
	}
	var selected StartupSelection
	e := s.with(ctx, scope, func(_ context.Context, tx *registry.AuthorityTx) error {
		h, row, choices, e := s.load(tx)
		if e != nil {
			return e
		}
		p, gen, e := s.ledger.profiles.GetTx(tx, scope)
		if e != nil {
			return e
		}
		selected = StartupSelection{scope, p.Protocol, p.Version, p.BindingDigest, Fingerprint(scope, p, gen)}
		key := connectionKey(scope)
		found := false
		for n, c := range choices {
			if connectionKey(c.Scope) == key {
				if c == selected {
					return nil
				}
				choices[n] = selected
				found = true
				break
			}
		}
		if !found {
			if len(choices) >= s.max {
				return fabric.NewError(fabric.CodeTargetUnavailable, "Explicit service startup capacity exhausted")
			}
			choices = append(choices, selected)
		}
		sort.Slice(choices, func(a, b int) bool { return connectionKey(choices[a].Scope) < connectionKey(choices[b].Scope) })
		return s.save(tx, h, row, choices)
	})
	return selected, e
}
func (s *Startup) Remove(ctx context.Context, scope registry.DescriptorBatchScope) error {
	if s == nil {
		return denied()
	}
	return s.with(ctx, registry.DescriptorBatchScope{}, func(_ context.Context, tx *registry.AuthorityTx) error {
		h, row, v, e := s.load(tx)
		if e != nil {
			return e
		}
		key := connectionKey(scope)
		for n, c := range v {
			if connectionKey(c.Scope) == key {
				return s.save(tx, h, row, append(v[:n], v[n+1:]...))
			}
		}
		return nil
	})
}

// BootstrapServiceState creates both infrastructure headers in ONE signed FULL
// transaction, so interrupted initialization cannot strand a half-created
// replay fence. It remains an explicit operator initialization command.
func BootstrapServiceState(ctx context.Context, p *ProfileStore, c InvocationConfig, policy InvocationPolicy, max int) (*Invocations, *Startup, error) {
	return bootstrapServiceState(ctx, p, c, policy, max, nil)
}
func bootstrapServiceState(ctx context.Context, p *ProfileStore, c InvocationConfig, policy InvocationPolicy, max int, setting []byte) (*Invocations, *Startup, error) {
	i, e := newInvocations(p, c, policy)
	if e != nil {
		return nil, nil, e
	}
	s, e := newStartup(i, max)
	if e != nil {
		return nil, nil, e
	}
	state, e := i.encode("configuration", invocationState{Format: 1, Key: p.protector.Reference(), Config: c})
	if e != nil {
		return nil, nil, e
	}
	head, e := i.encode("startup/header", startupHead{Format: 1, Key: p.protector.Reference(), Max: max, Generation: 1, Digest: startupDigest([]StartupSelection{})})
	if e != nil {
		return nil, nil, e
	}
	e = i.with(ctx, registry.DescriptorBatchScope{}, func(_ context.Context, tx *registry.AuthorityTx) error {
		for _, id := range []string{"configuration", "startup/header"} {
			if _, e := tx.Get(serviceKey(id)); !missing(e) {
				return denied()
			}
		}
		if len(setting) > 0 {
			if _, e := tx.Get(InstalledServiceConfigurationKey()); !missing(e) {
				return denied()
			}
			if _, e := tx.CAS(InstalledServiceConfigurationKey(), 0, setting, false); e != nil {
				return e
			}
		}
		if _, e := tx.CAS(serviceKey("configuration"), 0, state, false); e != nil {
			return e
		}
		_, e := tx.CAS(serviceKey("startup/header"), 0, head, false)
		return e
	})
	if e != nil {
		return nil, nil, e
	}
	return i, s, nil
}

// The manifest has at most16 protected pages. A selection rewrite is finite
// (at most52 indexed reads/CAS operations), independently bounded from hot
// invocation transactions and never proportional to the network catalog.
func (s *Startup) with(ctx context.Context, scope registry.DescriptorBatchScope, next func(context.Context, *registry.AuthorityTx) error) error {
	if s == nil || ctx == nil {
		return denied()
	}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	owner, e := s.ledger.profiles.owner(bounded)
	if e != nil {
		return e
	}
	return s.ledger.profiles.store.WithNativeAuthority(bounded, owner, registry.AuthorityScope{Endpoint: scope.Endpoint, ExpectedRevision: scope.ExpectedEndpointRevision, BindingID: scope.BindingID, MaxOperations: 64, Timeout: 5 * time.Second}, func(tx *registry.AuthorityTx) error { return next(bounded, tx) })
}
