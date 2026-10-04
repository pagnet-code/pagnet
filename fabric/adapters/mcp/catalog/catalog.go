// Package catalog maps explicit downstream MCP bindings into the genuine local
// signed registry. It has no second authoritative database and no cloud client.
package catalog

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"sync"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/adapters/mcp"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

type DataProtector interface {
	Seal(aad, plaintext []byte) ([]byte, error)
	Open(aad, ciphertext []byte) ([]byte, error)
}
type Config struct {
	BindingDigest     [32]byte
	Store             *registry.Store
	Owner             fabric.ExecutionContext
	Scope             registry.DescriptorBatchScope
	Limits            registry.DescriptorBatchLimits
	MaxTools          int
	Protector         DataProtector
	KeyID, KeyVersion string
}
type privateConfig struct {
	BindingDigest                                                   [32]byte
	Format                                                          int
	Domain, StoreID, Audience, Endpoint, Binding, KeyID, KeyVersion string
	MaxTools                                                        int
	Limits                                                          registry.DescriptorBatchLimits
}
type metadata struct{ Name, Fingerprint string }
type Catalog struct {
	mu           sync.Mutex
	config       Config
	identity     registry.AuthorityIdentity
	private      privateConfig
	sealedConfig []byte
	generation   uint64
	current      map[string]registry.BindingProjectionRow
}

func invalid(s string) error { return fabric.NewError(fabric.CodeInvalidInput, s) }
func unavailable() error {
	return fabric.NewError(fabric.CodeProtocolError, "Private MCP catalog state unavailable")
}
func stale() error {
	return fabric.NewError(fabric.CodeStaleReference, "MCP catalog snapshot or remembered offer changed")
}
func configCatalog(c Config) (*Catalog, error) {
	if c.Store == nil || c.Protector == nil || c.BindingDigest == ([32]byte{}) || c.MaxTools < 1 || c.MaxTools > 65536 || c.KeyID == "" || len(c.KeyID) > 256 || c.KeyVersion == "" || len(c.KeyVersion) > 128 {
		return nil, invalid("Invalid explicit MCP catalog configuration")
	}
	if c.Limits == (registry.DescriptorBatchLimits{}) {
		c.Limits = registry.DefaultDescriptorBatchLimits()
	}
	identity := c.Store.AuthorityIdentity()
	if c.Owner.VerifyAuthenticated(identity.Namespace) != nil || c.Owner.PrincipalView() != identity.Owner || c.Scope.Endpoint.IsOffer() || c.Scope.Endpoint.Domain() != identity.Namespace || c.Scope.ExpectedEndpointRevision == "" || c.Scope.BindingID == "" || c.MaxTools > c.Limits.MaxRows {
		return nil, invalid("MCP catalog requires genuine local owner and binding scope")
	}
	p := privateConfig{c.BindingDigest, 1, identity.Namespace, identity.StoreID, identity.Namespace, c.Scope.Endpoint.String(), c.Scope.BindingID, c.KeyID, c.KeyVersion, c.MaxTools, c.Limits}
	return &Catalog{config: c, identity: identity, private: p, current: map[string]registry.BindingProjectionRow{}}, nil
}
func (c *Catalog) aad(selector, ref string) []byte {
	raw, _ := json.Marshal(struct {
		BindingDigest                                                                          [32]byte
		Format, Domain, StoreID, Audience, Endpoint, Binding, KeyID, KeyVersion, Selector, Ref string
	}{c.private.BindingDigest, "mcp-catalog-1", c.private.Domain, c.private.StoreID, c.private.Audience, c.private.Endpoint, c.private.Binding, c.private.KeyID, c.private.KeyVersion, selector, ref})
	return raw
}

// Bootstrap initializes the signed local binding explicitly. It is never called
// by Open or by discovery when projection state is missing.
func Bootstrap(ctx context.Context, config Config) (*Catalog, error) {
	c, err := configCatalog(config)
	if err != nil {
		return nil, err
	}
	page, err := c.config.Store.ReadBindingProjection(ctx, c.config.Owner, c.config.Scope, "", 1)
	if err == nil || page.Generation != 0 {
		return nil, invalid("MCP catalog already initialized")
	}
	var typed *fabric.Error
	if !errors.As(err, &typed) || typed.Code != fabric.CodeNotFound {
		return nil, err
	}
	raw, _ := json.Marshal(c.private)
	sealed, err := c.config.Protector.Seal(c.aad("", "configuration"), raw)
	clear(raw)
	if err != nil || len(sealed) > c.config.Limits.MaxValueBytes {
		return nil, unavailable()
	}
	scope := c.config.Scope
	scope.ExpectedProjectionRevision = 0
	if _, err = c.config.Store.InitializeBindingProjection(ctx, c.config.Owner, scope, c.config.Limits, sealed); err != nil {
		return nil, err
	}
	return Open(ctx, config)
}
func Open(ctx context.Context, config Config) (*Catalog, error) {
	c, err := configCatalog(config)
	if err != nil {
		return nil, err
	}
	page, err := c.config.Store.ReadBindingProjection(ctx, c.config.Owner, c.config.Scope, "", 1)
	if err != nil {
		return nil, err
	}
	if err = c.verifyConfig(page.PrivateConfig); err != nil {
		return nil, err
	}
	c.sealedConfig = bytes.Clone(page.PrivateConfig)
	if _, err = c.Current(ctx, c.config.Scope.BindingID); err != nil {
		return nil, err
	}
	return c, nil
}
func (c *Catalog) verifyConfig(sealed []byte) error {
	if len(sealed) == 0 || len(sealed) > c.config.Limits.MaxValueBytes {
		return unavailable()
	}
	plain, err := c.config.Protector.Open(c.aad("", "configuration"), sealed)
	if err != nil {
		return unavailable()
	}
	defer clear(plain)
	expected, _ := json.Marshal(c.private)
	if !bytes.Equal(plain, expected) {
		return unavailable()
	}
	return nil
}
func selector(name string) string {
	sum := sha256.Sum256([]byte(name))
	return hex.EncodeToString(sum[:])
}
func validDigest(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 32 && hex.EncodeToString(b) == s
}
func (c *Catalog) decode(row registry.BindingProjectionRow) (metadata, error) {
	if row.Ref.Endpoint() != c.config.Scope.Endpoint || len(row.Value) == 0 || len(row.Value) > c.config.Limits.MaxValueBytes {
		return metadata{}, unavailable()
	}
	plain, err := c.config.Protector.Open(c.aad(row.Selector, row.Ref.String()), row.Value)
	if err != nil {
		return metadata{}, unavailable()
	}
	defer clear(plain)
	var m metadata
	if fabric.DecodeJSONWithLimits(plain, &m, fabric.WireLimits{MaxBytes: 4096, MaxDepth: 8, MaxMembers: 16}) != nil || m.Name == "" || len(m.Name) > 256 || !validDigest(m.Fingerprint) || selector(m.Name) != row.Selector {
		return metadata{}, unavailable()
	}
	return m, nil
}
func (c *Catalog) Current(ctx context.Context, binding string) ([]mcp.ToolIdentity, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if binding != c.config.Scope.BindingID {
		return nil, invalid("MCP catalog binding differs")
	}
	cursor := ""
	next := map[string]registry.BindingProjectionRow{}
	var out []mcp.ToolIdentity
	var generation uint64
	for {
		page, err := c.config.Store.ReadBindingProjection(ctx, c.config.Owner, c.config.Scope, cursor, 100)
		if err != nil {
			return nil, err
		}
		if generation != 0 && page.Generation != generation {
			return nil, stale()
		}
		generation = page.Generation
		if err = c.verifyConfig(page.PrivateConfig); err != nil {
			return nil, err
		}
		for _, row := range page.Rows {
			if len(next) >= c.config.MaxTools {
				return nil, invalid("MCP tool catalog exceeds configured bound")
			}
			m, err := c.decode(row)
			if err != nil {
				return nil, err
			}
			if _, exists := next[m.Name]; exists {
				return nil, unavailable()
			}
			next[m.Name] = row
			out = append(out, mcp.ToolIdentity{ToolName: m.Name, Fingerprint: m.Fingerprint})
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ToolName < out[j].ToolName })
	c.current, c.generation = next, generation
	return out, nil
}
func (c *Catalog) Resolve(ctx context.Context, binding string, ref fabric.EndpointRef, revision fabric.Revision) (mcp.ToolBinding, error) {
	if binding != c.config.Scope.BindingID || ref.Endpoint() != c.config.Scope.Endpoint || !ref.IsOffer() {
		return mcp.ToolBinding{}, stale()
	}
	row, _, err := c.config.Store.LookupBindingProjectionByRef(ctx, c.config.Owner, c.config.Scope, ref)
	if err != nil {
		return mcp.ToolBinding{}, err
	}
	if revision != "" && revision != row.OfferRevision {
		return mcp.ToolBinding{}, stale()
	}
	m, err := c.decode(row)
	if err != nil {
		return mcp.ToolBinding{}, err
	}
	offer, err := c.config.Store.GetOffer(ctx, ref, row.OfferRevision)
	if err != nil {
		return mcp.ToolBinding{}, err
	}
	if offer.BindingID != binding || offer.Name != m.Name {
		return mcp.ToolBinding{}, unavailable()
	}
	return mcp.ToolBinding{Offer: offer, ToolName: m.Name, Fingerprint: m.Fingerprint}, nil
}
func toolFingerprint(d mcp.ToolDescriptor) string {
	raw, _ := json.Marshal(struct {
		Name         string          `json:"name"`
		Description  string          `json:"description"`
		InputSchema  json.RawMessage `json:"inputSchema"`
		OutputSchema json.RawMessage `json:"outputSchema"`
	}{d.Name, d.Description, d.InputSchema, d.OutputSchema})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func (c *Catalog) Apply(ctx context.Context, binding string, endpoint fabric.EndpointRef, delta mcp.CatalogDelta) ([]mcp.ToolBinding, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if binding != c.config.Scope.BindingID || endpoint != c.config.Scope.Endpoint || c.generation == 0 {
		return nil, stale()
	}
	if len(delta.Upsert)+len(delta.Remove) < 1 || len(delta.Upsert)+len(delta.Remove) > c.config.Limits.MaxChanges {
		return nil, invalid("Invalid bounded MCP catalog delta")
	}
	batch := registry.DescriptorBatch{Limits: c.config.Limits, PrivateConfig: bytes.Clone(c.sealedConfig)}
	seen := map[string]bool{}
	count := len(c.current)
	for _, name := range delta.Remove {
		if seen[name] {
			return nil, invalid("Duplicate MCP selector delta")
		}
		seen[name] = true
		old, ok := c.current[name]
		if !ok {
			return nil, stale()
		}
		batch.Retirements = append(batch.Retirements, registry.OfferRetirement{Ref: old.Ref, ExpectedRevision: old.OfferRevision})
		retired := old
		retired.OfferRevision = ""
		retired.Retired = true
		batch.Projection = append(batch.Projection, retired)
		count--
	}
	for _, d := range delta.Upsert {
		if seen[d.Name] || !validDigest(d.Fingerprint) || d.Fingerprint != toolFingerprint(d) {
			return nil, invalid("Invalid exact MCP descriptor fingerprint")
		}
		seen[d.Name] = true
		ref := fabric.EndpointRef{}
		expected := fabric.Revision("")
		if old, ok := c.current[d.Name]; ok {
			ref, expected = old.Ref, old.OfferRevision
		} else {
			var id [32]byte
			if _, err := rand.Read(id[:]); err != nil {
				return nil, unavailable()
			}
			var err error
			ref, err = endpoint.WithOfferID(id[:])
			if err != nil {
				return nil, err
			}
			count++
		}
		raw, _ := json.Marshal(metadata{Name: d.Name, Fingerprint: d.Fingerprint})
		sealed, err := c.config.Protector.Seal(c.aad(selector(d.Name), ref.String()), raw)
		clear(raw)
		if err != nil || len(sealed) > c.config.Limits.MaxValueBytes {
			return nil, unavailable()
		}
		batch.Upserts = append(batch.Upserts, registry.OfferChange{Descriptor: fabric.OfferDescriptor{Ref: ref, Name: d.Name, Description: d.Description, InputSchema: bytes.Clone(d.InputSchema), OutputSchema: bytes.Clone(d.OutputSchema), BindingID: binding}, ExpectedRevision: expected})
		batch.Projection = append(batch.Projection, registry.BindingProjectionRow{Ref: ref, Selector: selector(d.Name), Value: sealed})
	}
	if count > c.config.MaxTools {
		return nil, invalid("MCP catalog active tool capacity reached")
	}
	scope := c.config.Scope
	scope.ExpectedProjectionRevision = c.generation
	request, _ := json.Marshal(struct {
		Scope registry.DescriptorBatchScope
		Batch registry.DescriptorBatch
	}{scope, batch})
	sum := sha256.Sum256(request)
	batch.RequestID = hex.EncodeToString(sum[:])
	result, err := c.config.Store.ApplyDescriptorBatch(ctx, c.config.Owner, scope, batch)
	if err != nil {
		return nil, err
	}
	var out []mcp.ToolBinding
	for _, row := range result.Rows {
		m, err := c.decode(row)
		if err != nil {
			return nil, err
		}
		if row.Retired {
			delete(c.current, m.Name)
			continue
		}
		c.current[m.Name] = row
		offer, err := c.config.Store.GetOffer(ctx, row.Ref, row.OfferRevision)
		if err != nil {
			return nil, err
		}
		out = append(out, mcp.ToolBinding{Offer: offer, ToolName: m.Name, Fingerprint: m.Fingerprint})
	}
	c.generation = result.ProjectionRevision
	return out, nil
}

var _ mcp.Catalog = (*Catalog)(nil)
