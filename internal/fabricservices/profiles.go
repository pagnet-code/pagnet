// Package fabricservices composes explicitly installed private services with the
// actual retained Fabric registry. Installation is not invocation or discovery.
package fabricservices

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/url"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	a2asdk "github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/adapters/a2a"
	"github.com/pagnet-code/pagnet/fabric/adapters/mcp"
	"github.com/pagnet-code/pagnet/fabric/events/durable"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

// Profile is encrypted operator configuration, NEVER a public descriptor. It
// contains a selector and pinned account digest, not credential values. Stdio
// launches an exact installed executable without a shell; HTTP is explicit.
type Profile struct {
	Protocol           string      `json:"protocol"`
	Version            string      `json:"version"`
	CredentialSelector string      `json:"credentialSelector"`
	BindingDigest      [32]byte    `json:"bindingDigest"`
	MCP                *MCPProfile `json:"mcp,omitempty"`
	A2A                *A2AProfile `json:"a2a,omitempty"`
}
type MCPProfile struct {
	URL       string     `json:"url,omitempty"`
	Binary    string     `json:"binary,omitempty"`
	Args      []string   `json:"args,omitempty"`
	AllowHTTP bool       `json:"allowHttp"`
	Limits    mcp.Limits `json:"limits"`
}
type A2AProfile struct {
	Card         *a2asdk.AgentCard     `json:"card"`
	Interface    a2asdk.AgentInterface `json:"interface"`
	AllowHTTP    bool                  `json:"allowHttp"`
	Cancellation bool                  `json:"cancellation"`
	Limits       a2a.Limits            `json:"limits"`
}
type OwnerProvider func(context.Context) (fabric.ExecutionContext, error)
type ProfileStore struct {
	store     *registry.Store
	owner     OwnerProvider
	root      registry.AuthorityIdentity
	protector durable.DataProtector
}
type profileRecord struct {
	Format  int                  `json:"format"`
	Key     durable.KeyReference `json:"key"`
	Profile Profile              `json:"profile"`
}

func denied() error {
	return fabric.NewError(fabric.CodeProtocolError, "Private service configuration unavailable or changed")
}
func missing(e error) bool {
	var f *fabric.Error
	return errors.As(e, &f) && f.Code == fabric.CodeNotFound
}
func validText(s string, max int) bool {
	return s != "" && len(s) <= max && utf8.ValidString(s) && !strings.ContainsAny(s, "\x00\r\n")
}
func validURL(s string, allowHTTP bool) bool {
	u, e := url.Parse(s)
	return e == nil && u.Host != "" && u.User == nil && u.RawQuery == "" && u.Fragment == "" && (u.Scheme == "https" || allowHTTP && u.Scheme == "http")
}
func validate(p Profile) error {
	if !boundedValue(p, 32<<10, 2048) {
		return denied()
	}
	if !validText(p.Version, 128) || !validText(p.CredentialSelector, 256) || p.BindingDigest == ([32]byte{}) {
		return denied()
	}
	switch p.Protocol {
	case "mcp.tools":
		if p.MCP == nil || p.A2A != nil {
			return denied()
		}
		m := p.MCP
		if (m.URL == "") == (m.Binary == "") || len(m.Args) > 128 {
			return denied()
		}
		if m.URL != "" {
			if !validURL(m.URL, m.AllowHTTP) || len(m.Args) != 0 {
				return denied()
			}
		} else if !filepath.IsAbs(m.Binary) || filepath.Clean(m.Binary) != m.Binary || len(m.Binary) > 4096 {
			return denied()
		}
		n := len(m.Binary) + len(m.URL)
		for _, a := range m.Args {
			n += len(a)
			if strings.ContainsRune(a, 0) || n > 16<<10 {
				return denied()
			}
		}
		l := m.Limits
		if l.MaxTools < 1 || l.MaxTools > 4096 || l.MaxPages < 1 || l.MaxPages > 128 || l.MaxPending < 1 || l.MaxPending > 128 || l.MaxResultBytes < 1024 || l.MaxResultBytes > 16<<20 || l.MaxCatalogBytes < 1024 || l.MaxCatalogBytes > 16<<20 {
			return denied()
		}
	case "a2a.jsonrpc":
		if p.A2A == nil || p.MCP != nil || p.Version != string(a2asdk.Version) {
			return denied()
		}
		a := p.A2A
		if a.Card == nil || a.Interface.ProtocolBinding != a2asdk.TransportProtocolJSONRPC || string(a.Interface.ProtocolVersion) != p.Version || !validURL(a.Interface.URL, a.AllowHTTP) {
			return denied()
		}
		selected := false
		for _, candidate := range a.Card.SupportedInterfaces {
			if candidate != nil && *candidate == a.Interface {
				selected = true
			}
		}
		if !selected {
			return denied()
		}
		l := a.Limits
		if l.MaxEventBytes < 1024 || l.MaxEventBytes > 1<<20 || l.MaxRequestBytes < 1024 || l.MaxRequestBytes > 1<<20 || l.MaxStreamBytes < 1 || l.MaxStreamBytes > 64<<20 || l.Lifetime <= 0 || l.Lifetime > 5*time.Minute {
			return denied()
		}
	default:
		return fabric.NewError(fabric.CodeUnsupported, "Service protocol is not explicitly installed")
	}
	return nil
}

// ValidateProfile performs pure bounded configuration validation before an
// operator publishes an endpoint. It opens no store and resolves no provider.
func ValidateProfile(p Profile) error { return validate(p) }

func NewProfileStore(ctx context.Context, s *registry.Store, owner OwnerProvider, p durable.DataProtector) (*ProfileStore, error) {
	if ctx == nil || s == nil || owner == nil || p == nil || !validText(p.Reference().ID, 256) || !validText(p.Reference().Version, 128) {
		return nil, denied()
	}
	root, e := s.CurrentAuthorityIdentity(ctx)
	if e != nil {
		return nil, e
	}
	c, e := owner(ctx)
	if e != nil || c.VerifyAuthenticated(root.Namespace) != nil || c.PrincipalView() != root.Owner {
		return nil, denied()
	}
	return &ProfileStore{s, owner, root, p}, nil
}
func (s *ProfileStore) key(scope registry.DescriptorBatchScope) registry.AuthorityKey {
	return registry.AuthorityKey{Kind: registry.AuthorityServiceBinding, Endpoint: scope.Endpoint, ID: scope.BindingID}
}
func (s *ProfileStore) aad(scope registry.DescriptorBatchScope) []byte {
	raw, _ := json.Marshal(struct{ Purpose, Domain, Store, Endpoint, Binding string }{"pagnet.service.profile.v1", s.root.Namespace, s.root.StoreID, scope.Endpoint.String(), scope.BindingID})
	return raw
}
func (s *ProfileStore) with(ctx context.Context, scope registry.DescriptorBatchScope, fn func(*registry.AuthorityTx) error) error {
	if s == nil || ctx == nil || scope.ExpectedProjectionRevision != 0 {
		return denied()
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	owner, e := s.owner(ctx)
	if e != nil {
		return e
	}
	return s.store.WithNativeAuthority(ctx, owner, registry.AuthorityScope{Endpoint: scope.Endpoint, ExpectedRevision: scope.ExpectedEndpointRevision, BindingID: scope.BindingID, MaxOperations: 8, Timeout: 5 * time.Second}, fn)
}

// Install is explicit immutable installation. Missing state is never recreated by
// Get. Exact retries return the existing generation; profile changes need a new
// published binding. All profile bytes are sealed before the actual FULL CAS.
func (s *ProfileStore) Install(ctx context.Context, scope registry.DescriptorBatchScope, p Profile) (uint64, error) {
	if s == nil || validate(p) != nil {
		return 0, denied()
	}
	d, e := s.store.GetEndpoint(ctx, scope.Endpoint, scope.ExpectedEndpointRevision)
	if e != nil {
		return 0, e
	}
	found := false
	for _, b := range d.Bindings {
		if b.ID == scope.BindingID && b.Protocol == p.Protocol && b.Version == p.Version {
			if p.A2A != nil && (b.Streaming != p.A2A.Card.Capabilities.Streaming || b.Cancellation != p.A2A.Cancellation) {
				return 0, denied()
			}
			found = true
		}
	}
	if !found {
		return 0, denied()
	}
	raw, e := json.Marshal(profileRecord{1, s.protector.Reference(), p})
	if e != nil || len(raw) > 32<<10 {
		return 0, denied()
	}
	defer clear(raw)
	sealed, e := s.protector.Seal(s.aad(scope), raw)
	if e != nil || len(sealed) > 48<<10 {
		return 0, denied()
	}
	defer clear(sealed)
	value, _ := json.Marshal(struct {
		Cipher []byte `json:"cipher"`
	}{sealed})
	if len(value) > 64<<10 {
		return 0, denied()
	}
	var gen uint64
	e = s.with(ctx, scope, func(tx *registry.AuthorityTx) error {
		old, err := tx.Get(s.key(scope))
		if err == nil {
			current, _, x := s.getTx(tx, scope)
			if x != nil {
				return x
			}
			existing, _ := json.Marshal(profileRecord{1, s.protector.Reference(), current})
			defer clear(existing)
			if !bytes.Equal(raw, existing) {
				return fabric.NewError(fabric.CodeStaleReference, "Changing service connection or account requires a new binding")
			}
			gen = old.Revision
			return nil
		}
		if !missing(err) {
			return err
		}
		r, err := tx.CAS(s.key(scope), 0, value, false)
		gen = r.Revision
		return err
	})
	return gen, e
}
func (s *ProfileStore) getTx(tx *registry.AuthorityTx, scope registry.DescriptorBatchScope) (Profile, uint64, error) {
	r, e := tx.Get(s.key(scope))
	if e != nil {
		return Profile{}, 0, e
	}
	if r.Retired || registry.VerifyAuthorityRecord(s.root, r) != nil || len(r.Value) > 64<<10 {
		return Profile{}, 0, denied()
	}
	var v struct {
		Cipher []byte `json:"cipher"`
	}
	if fabric.DecodeJSONWithLimits(r.Value, &v, fabric.WireLimits{MaxBytes: 64 << 10, MaxDepth: 4, MaxMembers: 4}) != nil || len(v.Cipher) > 48<<10 {
		return Profile{}, 0, denied()
	}
	raw, e := s.protector.Open(s.aad(scope), v.Cipher)
	if e != nil {
		return Profile{}, 0, denied()
	}
	defer clear(raw)
	var rec profileRecord
	if fabric.DecodeJSONWithLimits(raw, &rec, fabric.WireLimits{MaxBytes: 32 << 10, MaxDepth: 32, MaxMembers: 2048}) != nil || rec.Format != 1 || rec.Key != s.protector.Reference() || validate(rec.Profile) != nil {
		return Profile{}, 0, denied()
	}
	return rec.Profile, r.Revision, nil
}

// GetTx is only for trusted same-store admission composition. DataProtector must
// be pre-resolved synchronous bounded local crypto; no provider IO under SQL.
func (s *ProfileStore) GetTx(tx *registry.AuthorityTx, scope registry.DescriptorBatchScope) (Profile, uint64, error) {
	if s == nil || tx == nil {
		return Profile{}, 0, denied()
	}
	return s.getTx(tx, scope)
}
func (s *ProfileStore) Get(ctx context.Context, scope registry.DescriptorBatchScope) (Profile, uint64, error) {
	var p Profile
	var gen uint64
	e := s.with(ctx, scope, func(tx *registry.AuthorityTx) error { var e error; p, gen, e = s.getTx(tx, scope); return e })
	return p, gen, e
}

// Fingerprint commits private selected profile and descriptor revision, never
// credential token bytes. Return only the digest to the routing/admission layer.
func Fingerprint(scope registry.DescriptorBatchScope, p Profile, generation uint64) [32]byte {
	raw, _ := json.Marshal(struct {
		Scope      registry.DescriptorBatchScope
		Profile    Profile
		Generation uint64
	}{scope, p, generation})
	defer clear(raw)
	return sha256.Sum256(raw)
}
