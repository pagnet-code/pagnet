package registry

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"sort"

	"github.com/pagnet-code/pagnet/fabric"
)

type DescriptorBatchScope struct {
	Endpoint                   fabric.EndpointRef `json:"endpoint"`
	ExpectedEndpointRevision   fabric.Revision    `json:"expectedEndpointRevision"`
	BindingID                  string             `json:"bindingId"`
	ExpectedProjectionRevision uint64             `json:"expectedProjectionRevision,string"`
}
type DescriptorBatchLimits struct {
	MaxRows       int   `json:"maxRows"`
	MaxBytes      int64 `json:"maxBytes"`
	MaxChanges    int   `json:"maxChanges"`
	MaxValueBytes int   `json:"maxValueBytes"`
}

func DefaultDescriptorBatchLimits() DescriptorBatchLimits {
	return DescriptorBatchLimits{16384, 16 << 20, 4096, 64 << 10}
}

type OfferChange struct {
	Descriptor       fabric.OfferDescriptor `json:"descriptor"`
	ExpectedRevision fabric.Revision        `json:"expectedRevision"`
}
type OfferRetirement struct {
	Ref              fabric.EndpointRef `json:"ref"`
	ExpectedRevision fabric.Revision    `json:"expectedRevision"`
}

// BindingProjectionRow is local-private adapter metadata. Selector is an opaque
// stable hash, Ref immutable identity, Value owned opaque bytes. OfferRevision is
// filled by the registry's genuine signed mutation, never accepted from caller.
type BindingProjectionRow struct {
	Selector      string             `json:"selector"`
	Ref           fabric.EndpointRef `json:"ref"`
	OfferRevision fabric.Revision    `json:"offerRevision"`
	Retired       bool               `json:"retired"`
	Value         []byte             `json:"value"`
}
type DescriptorBatch struct {
	PrivateConfig []byte                 `json:"privateConfig"`
	RequestID     string                 `json:"requestId"`
	Limits        DescriptorBatchLimits  `json:"limits"`
	Upserts       []OfferChange          `json:"upserts"`
	Retirements   []OfferRetirement      `json:"retirements"`
	Projection    []BindingProjectionRow `json:"projection"`
}
type DescriptorBatchResult struct {
	ProjectionRevision uint64                 `json:"projectionRevision,string"`
	Rows               []BindingProjectionRow `json:"rows"`
}
type projectionBody struct {
	PrivateConfig                                 []byte `json:"privateConfig"`
	Format                                        int    `json:"format"`
	Namespace, StoreID                            string
	Owner                                         fabric.Principal
	KeyRevision                                   uint64
	Scope                                         DescriptorBatchScope
	Limits                                        DescriptorBatchLimits
	Generation                                    uint64
	Previous                                      [32]byte
	RequestID, RequestDigest                      string
	RegistryBeforeSequence, RegistryAfterSequence uint64
	RegistryBeforeHead, RegistryAfterHead         [32]byte
	Rows                                          []BindingProjectionRow
}
type projectionRecord struct {
	Body      json.RawMessage `json:"body"`
	Signature []byte          `json:"signature"`
}

const projectionSchema = `CREATE TABLE descriptor_projection_format(singleton INTEGER PRIMARY KEY CHECK(singleton=1),version INTEGER NOT NULL);INSERT INTO descriptor_projection_format VALUES(1,1);
CREATE TABLE descriptor_projection_heads(endpoint TEXT NOT NULL,binding TEXT NOT NULL,generation INTEGER NOT NULL,head BLOB NOT NULL,limits BLOB NOT NULL,rows INTEGER NOT NULL,bytes INTEGER NOT NULL,config BLOB NOT NULL,PRIMARY KEY(endpoint,binding));
CREATE TABLE descriptor_projection_rows(endpoint TEXT NOT NULL,binding TEXT NOT NULL,ref TEXT NOT NULL,selector TEXT NOT NULL,retired INTEGER NOT NULL,row BLOB NOT NULL,cost INTEGER NOT NULL,PRIMARY KEY(endpoint,binding,ref));
CREATE UNIQUE INDEX descriptor_active_selector ON descriptor_projection_rows(endpoint,binding,selector) WHERE retired=0;
CREATE INDEX descriptor_projection_page ON descriptor_projection_rows(endpoint,binding,retired,ref);
CREATE TABLE descriptor_projection_log(endpoint TEXT NOT NULL,binding TEXT NOT NULL,generation INTEGER NOT NULL,request_id TEXT NOT NULL,record BLOB NOT NULL,PRIMARY KEY(endpoint,binding,generation),UNIQUE(endpoint,binding,request_id));`

func projectionTables(ctx context.Context, q indexQuery) (int, error) {
	var n int
	e := q.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('descriptor_projection_format','descriptor_projection_heads','descriptor_projection_rows','descriptor_projection_log')").Scan(&n)
	if e != nil {
		return 0, e
	}
	if n != 0 && n != 4 {
		return n, invalid("Incomplete descriptor projection format")
	}
	if n == 4 {
		var indexes int
		if q.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type='index' AND name IN ('descriptor_active_selector','descriptor_projection_page')").Scan(&indexes) != nil || indexes != 2 {
			return n, invalid("Descriptor projection indexes missing")
		}
		var v int
		if e = q.QueryRowContext(ctx, "SELECT version FROM descriptor_projection_format WHERE singleton=1").Scan(&v); e != nil || v != 1 {
			return n, invalid("Unsupported descriptor projection format")
		}
	}
	return n, nil
}
func validBatchLimits(l DescriptorBatchLimits) bool {
	return l.MaxRows >= 1 && l.MaxRows <= 100000 && l.MaxBytes >= 1 && l.MaxBytes <= 128<<20 && l.MaxChanges >= 1 && l.MaxChanges <= 4096 && l.MaxValueBytes >= 1 && l.MaxValueBytes <= 1<<20
}
func projectionSigning(raw []byte) []byte {
	sum := sha256.Sum256(raw)
	return append([]byte("pagnet.fabric.private-descriptor-projection.v1\x00"), sum[:]...)
}
func projectionHash(r projectionRecord) [32]byte {
	h := sha256.New()
	h.Write(r.Body)
	h.Write(r.Signature)
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum
}
func decodeProjection(raw []byte) (projectionRecord, projectionBody, error) {
	var r projectionRecord
	var b projectionBody
	if e := fabric.DecodeJSONWithLimits(raw, &r, fabric.WireLimits{MaxBytes: 16 << 20, MaxDepth: 64, MaxMembers: 65536}); e != nil {
		return r, b, e
	}
	if e := fabric.DecodeJSONWithLimits(r.Body, &b, fabric.WireLimits{MaxBytes: 12 << 20, MaxDepth: 64, MaxMembers: 65536}); e != nil {
		return r, b, e
	}
	return r, b, nil
}
func projectionCost(r BindingProjectionRow) int64 {
	raw, _ := json.Marshal(r)
	return int64(len(raw) + 256)
}
func hexHash(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == s
}
func (s *Store) validateProjectionScope(ctx context.Context, q indexQuery, scope DescriptorBatchScope) error {
	if scope.Endpoint.IsOffer() || scope.Endpoint.Domain() != s.identity.Namespace || scope.ExpectedEndpointRevision == "" || !text(scope.BindingID, 256, false) || scope.ExpectedProjectionRevision > math.MaxInt64 {
		return invalid("Incomplete local descriptor batch scope")
	}
	o, e := loadObject(ctx, q, scope.Endpoint.String())
	if e != nil || o.retired || o.revision != scope.ExpectedEndpointRevision {
		return conflict("Descriptor batch endpoint retired or stale")
	}
	var d fabric.EndpointDescriptor
	if e = s.decode(o.payload, &d); e != nil {
		return e
	}
	for _, b := range d.Bindings {
		if b.ID == scope.BindingID {
			return nil
		}
	}
	return invalid("Descriptor batch binding absent")
}
func (s *Store) ApplyDescriptorBatch(ctx context.Context, owner fabric.ExecutionContext, scope DescriptorBatchScope, batch DescriptorBatch) (DescriptorBatchResult, error) {
	if ctx == nil || !text(scope.BindingID, 256, false) || len(scope.ExpectedEndpointRevision) > 256 || !validBatchLimits(batch.Limits) || !hexHash(batch.RequestID) || len(batch.PrivateConfig) == 0 || len(batch.PrivateConfig) > batch.Limits.MaxValueBytes || len(batch.Projection) > batch.Limits.MaxChanges || len(batch.Upserts)+len(batch.Retirements) != len(batch.Projection) {
		return DescriptorBatchResult{}, invalid("Invalid bounded descriptor batch")
	}
	// Bound typed aggregate before JSON/base64 allocation. Raw schemas may expand
	// sixfold when HTML escaping; opaque values expand at most twice by base64.
	estimate := int64(len(batch.PrivateConfig))*2 + 4096
	for _, row := range batch.Projection {
		if !hexHash(row.Selector) || len(row.Value) > batch.Limits.MaxValueBytes {
			return DescriptorBatchResult{}, invalid("Projection value exceeds bound")
		}
		estimate += int64(len(row.Value))*2 + 2048
	}
	for _, change := range batch.Upserts {
		d := change.Descriptor
		if len(d.BindingID) > 256 || len(d.Revision) > 256 || len(change.ExpectedRevision) > 256 {
			return DescriptorBatchResult{}, invalid("Descriptor batch identity exceeds bound")
		}
		size := len(d.Name) + len(d.Description) + len(d.InputSchema) + len(d.OutputSchema)
		for _, v := range d.Examples {
			size += len(v)
		}
		for _, v := range d.Tags {
			size += len(v)
		}
		estimate += int64(size)*6 + 2048
		if estimate > 12<<20 {
			return DescriptorBatchResult{}, invalid("Descriptor batch exceeds encoded byte admission")
		}
	}
	if estimate > 12<<20 {
		return DescriptorBatchResult{}, invalid("Descriptor batch exceeds encoded byte admission")
	}
	for _, retirement := range batch.Retirements {
		if len(retirement.ExpectedRevision) > 256 {
			return DescriptorBatchResult{}, invalid("Retirement revision exceeds bound")
		}
	}
	// Exact request content/ordering binds ambiguous retry; no mutable dispatch ID.
	requestRaw, e := json.Marshal(struct {
		Scope DescriptorBatchScope
		Batch DescriptorBatch
	}{scope, batch})
	if e != nil || len(requestRaw) > 12<<20 {
		return DescriptorBatchResult{}, invalid("Descriptor batch exceeds wire bound")
	}
	requestSum := sha256.Sum256(requestRaw)
	requestDigest := hex.EncodeToString(requestSum[:])
	s.mu.Lock()
	defer s.mu.Unlock()
	if e = s.authorize(owner); e != nil {
		return DescriptorBatchResult{}, e
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return DescriptorBatchResult{}, e
	}
	defer tx.Rollback()
	tables, e := projectionTables(ctx, tx)
	if e != nil {
		return DescriptorBatchResult{}, e
	}
	if tables == 0 {
		if e = s.validateProjectionScope(ctx, tx, scope); e != nil {
			return DescriptorBatchResult{}, e
		}
		if _, e = tx.ExecContext(ctx, projectionSchema); e != nil {
			return DescriptorBatchResult{}, e
		}
	}
	var previousRaw []byte
	e = tx.QueryRowContext(ctx, "SELECT CASE WHEN length(record)<=16777216 THEN record END FROM descriptor_projection_log WHERE endpoint=? AND binding=? AND request_id=?", scope.Endpoint.String(), scope.BindingID, batch.RequestID).Scan(&previousRaw)
	if e == nil {
		r, b, x := decodeProjection(previousRaw)
		if x != nil || b.RequestDigest != requestDigest || b.Namespace != s.identity.Namespace || b.StoreID != s.identity.StoreID || !ed25519.Verify(s.identity.PublicKey, projectionSigning(r.Body), r.Signature) {
			return DescriptorBatchResult{}, invalid("Descriptor batch retry content differs")
		}
		return DescriptorBatchResult{b.Generation, b.Rows}, nil
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return DescriptorBatchResult{}, e
	}
	if e = s.validateProjectionScope(ctx, tx, scope); e != nil {
		return DescriptorBatchResult{}, e
	}
	var generation uint64
	var previous []byte
	var savedLimits, savedConfig []byte
	var count, total int64
	e = tx.QueryRowContext(ctx, "SELECT generation,head,limits,rows,bytes,config FROM descriptor_projection_heads WHERE endpoint=? AND binding=?", scope.Endpoint.String(), scope.BindingID).Scan(&generation, &previous, &savedLimits, &count, &total, &savedConfig)
	limitsRaw, _ := json.Marshal(batch.Limits)
	if errors.Is(e, sql.ErrNoRows) {
		generation = 0
		previous = make([]byte, 32)
	} else if e != nil {
		return DescriptorBatchResult{}, e
	} else if !bytes.Equal(savedLimits, limitsRaw) || !bytes.Equal(savedConfig, batch.PrivateConfig) {
		return DescriptorBatchResult{}, invalid("Descriptor projection limits changed")
	}
	if len(batch.Projection) == 0 && generation != 0 {
		return DescriptorBatchResult{}, invalid("Empty batch is only explicit binding initialization")
	}
	if generation != scope.ExpectedProjectionRevision || generation >= math.MaxInt64 || len(previous) != 32 {
		return DescriptorBatchResult{}, conflict("Descriptor projection generation stale")
	}
	seen := map[string]bool{}
	upserts := map[string]OfferChange{}
	retires := map[string]OfferRetirement{}
	for _, change := range batch.Upserts {
		d := change.Descriptor
		if d.Ref.Endpoint() != scope.Endpoint || d.BindingID != scope.BindingID || d.Revision != "" || validateOffer(d, s.options.Limits.MaxPayloadBytes) != nil || seen[d.Ref.String()] {
			return DescriptorBatchResult{}, invalid("Invalid exact batch offer")
		}
		seen[d.Ref.String()] = true
		upserts[d.Ref.String()] = change
	}
	for _, change := range batch.Retirements {
		if change.Ref.Endpoint() != scope.Endpoint || !change.Ref.IsOffer() || change.ExpectedRevision == "" || seen[change.Ref.String()] {
			return DescriptorBatchResult{}, invalid("Invalid exact batch retirement")
		}
		seen[change.Ref.String()] = true
		retires[change.Ref.String()] = change
	}
	rows := append([]BindingProjectionRow(nil), batch.Projection...)
	sort.Slice(rows, func(i, j int) bool { return rows[i].Ref.String() < rows[j].Ref.String() })
	var deltaCost int64
	newRows := int64(0)
	for i, row := range rows {
		if !row.Ref.IsOffer() || row.Ref.Endpoint() != scope.Endpoint || !hexHash(row.Selector) || row.OfferRevision != "" || len(row.Value) == 0 || len(row.Value) > batch.Limits.MaxValueBytes || !seen[row.Ref.String()] || (i > 0 && rows[i-1].Ref == row.Ref) {
			return DescriptorBatchResult{}, invalid("Invalid descriptor projection row")
		}
		var oldRaw []byte
		var oldCost int64
		x := tx.QueryRowContext(ctx, "SELECT row,cost FROM descriptor_projection_rows WHERE endpoint=? AND binding=? AND ref=?", scope.Endpoint.String(), scope.BindingID, row.Ref.String()).Scan(&oldRaw, &oldCost)
		if x == nil {
			var old BindingProjectionRow
			if fabric.DecodeJSONWithLimits(oldRaw, &old, fabric.WireLimits{MaxBytes: 2 << 20, MaxDepth: 64, MaxMembers: 4096}) != nil || old.Retired || old.Selector != row.Selector {
				return DescriptorBatchResult{}, conflict("Descriptor selector identity is immutable or retired")
			}
			if change, ok := upserts[row.Ref.String()]; ok && change.ExpectedRevision != old.OfferRevision {
				return DescriptorBatchResult{}, conflict("Projection offer revision stale")
			}
			if change, ok := retires[row.Ref.String()]; ok && change.ExpectedRevision != old.OfferRevision {
				return DescriptorBatchResult{}, conflict("Projection retirement revision stale")
			}
		} else if errors.Is(x, sql.ErrNoRows) {
			if row.Retired {
				return DescriptorBatchResult{}, invalid("Projection cannot begin retired")
			}
			if change, ok := upserts[row.Ref.String()]; !ok || change.ExpectedRevision != "" {
				return DescriptorBatchResult{}, invalid("New projection must create a new offer identity")
			}
			newRows++
		} else {
			return DescriptorBatchResult{}, x
		}
		if row.Retired {
			if _, ok := retires[row.Ref.String()]; !ok {
				return DescriptorBatchResult{}, invalid("Projection tombstone requires genuine retirement")
			}
		} else {
			if _, ok := upserts[row.Ref.String()]; !ok {
				return DescriptorBatchResult{}, invalid("Active projection requires genuine offer publication")
			}
		}
		// Revision is always a registry-allocated 64-byte digest; reserve exact size.
		reserve := row
		reserve.OfferRevision = fabric.Revision(string(bytes.Repeat([]byte("0"), 64)))
		deltaCost += projectionCost(reserve) - oldCost
	}
	if newRows > int64(batch.Limits.MaxRows)-count || deltaCost > batch.Limits.MaxBytes-total {
		return DescriptorBatchResult{}, invalid("Descriptor projection capacity reached")
	}
	beforeSequence, beforeHead, e := head(ctx, tx, s.identity.Namespace)
	if e != nil {
		return DescriptorBatchResult{}, e
	}
	// Remove active selector slots for retirements first, without deleting identity.
	for _, row := range rows {
		if row.Retired {
			if _, e = tx.ExecContext(ctx, "UPDATE descriptor_projection_rows SET retired=1 WHERE endpoint=? AND binding=? AND ref=?", scope.Endpoint.String(), scope.BindingID, row.Ref.String()); e != nil {
				return DescriptorBatchResult{}, e
			}
		}
	}
	for i, row := range rows {
		if change, ok := upserts[row.Ref.String()]; ok {
			d := change.Descriptor
			unsigned, _ := json.Marshal(d)
			revision, x := s.mutateTx(ctx, tx, d.Ref, change.ExpectedRevision, "offer.publish", unsigned, func(rev fabric.Revision) ([]byte, error) { d.Revision = rev; return json.Marshal(d) })
			if x != nil {
				return DescriptorBatchResult{}, x
			}
			rows[i].OfferRevision = revision
		} else {
			change := retires[row.Ref.String()]
			d := tombstone{Ref: change.Ref, Kind: "offer"}
			unsigned, _ := json.Marshal(d)
			revision, x := s.mutateTx(ctx, tx, d.Ref, change.ExpectedRevision, "offer.retire", unsigned, func(rev fabric.Revision) ([]byte, error) { d.Revision = rev; return json.Marshal(d) })
			if x != nil {
				return DescriptorBatchResult{}, x
			}
			rows[i].OfferRevision = revision
		}
		encoded, _ := json.Marshal(rows[i])
		if _, e = tx.ExecContext(ctx, "INSERT INTO descriptor_projection_rows VALUES(?,?,?,?,?,?,?) ON CONFLICT(endpoint,binding,ref) DO UPDATE SET retired=excluded.retired,row=excluded.row,cost=excluded.cost", scope.Endpoint.String(), scope.BindingID, row.Ref.String(), row.Selector, row.Retired, encoded, projectionCost(rows[i])); e != nil {
			return DescriptorBatchResult{}, e
		}
	}
	afterSequence, afterHead, e := head(ctx, tx, s.identity.Namespace)
	if e != nil {
		return DescriptorBatchResult{}, e
	}
	if afterSequence-beforeSequence != uint64(len(rows)) {
		return DescriptorBatchResult{}, invalid("Projection must bind freshly committed exact offer mutations")
	}
	var prev [32]byte
	copy(prev[:], previous)
	body := projectionBody{PrivateConfig: bytes.Clone(batch.PrivateConfig), Format: 1, Namespace: s.identity.Namespace, StoreID: s.identity.StoreID, Owner: s.identity.Owner, KeyRevision: 1, Scope: scope, Limits: batch.Limits, Generation: generation + 1, Previous: prev, RequestID: batch.RequestID, RequestDigest: requestDigest, RegistryBeforeSequence: beforeSequence, RegistryAfterSequence: afterSequence, RegistryBeforeHead: beforeHead, RegistryAfterHead: afterHead, Rows: rows}
	rawBody, _ := json.Marshal(body)
	record := projectionRecord{Body: rawBody, Signature: ed25519.Sign(s.key, projectionSigning(rawBody))}
	encoded, _ := json.Marshal(record)
	if len(encoded) > 16<<20 {
		return DescriptorBatchResult{}, invalid("Projection signed record exceeds bound")
	}
	var ledgerCount, ledgerBytes int64
	if tx.QueryRowContext(ctx, "SELECT records,bytes FROM ledger_budget WHERE singleton=1").Scan(&ledgerCount, &ledgerBytes) != nil {
		return DescriptorBatchResult{}, invalid("Registry ledger budget unavailable")
	}
	if uint64(ledgerCount) >= s.options.Limits.MaxRecords || int64(len(encoded)) > s.options.Limits.MaxLedgerBytes-ledgerBytes {
		return DescriptorBatchResult{}, invalid("Registry signed history capacity reached")
	}
	digest := projectionHash(record)
	if _, e = tx.ExecContext(ctx, "INSERT INTO descriptor_projection_log VALUES(?,?,?,?,?)", scope.Endpoint.String(), scope.BindingID, generation+1, batch.RequestID, encoded); e != nil {
		return DescriptorBatchResult{}, e
	}
	if _, e = tx.ExecContext(ctx, "INSERT INTO descriptor_projection_heads VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(endpoint,binding) DO UPDATE SET generation=excluded.generation,head=excluded.head,rows=excluded.rows,bytes=excluded.bytes", scope.Endpoint.String(), scope.BindingID, generation+1, digest[:], limitsRaw, count+newRows, total+deltaCost, batch.PrivateConfig); e != nil {
		return DescriptorBatchResult{}, e
	}
	if _, e = tx.ExecContext(ctx, "UPDATE ledger_budget SET records=records+1,bytes=bytes+? WHERE singleton=1", len(encoded)); e != nil {
		return DescriptorBatchResult{}, e
	}
	if e = tx.Commit(); e != nil {
		return DescriptorBatchResult{}, e
	}
	return DescriptorBatchResult{generation + 1, rows}, nil
}

// InitializeBindingProjection is explicit owner composition, never an Open fallback.
func (s *Store) InitializeBindingProjection(ctx context.Context, owner fabric.ExecutionContext, scope DescriptorBatchScope, limits DescriptorBatchLimits, privateConfig []byte) (DescriptorBatchResult, error) {
	raw, _ := json.Marshal(struct {
		Scope  DescriptorBatchScope
		Limits DescriptorBatchLimits
		Config []byte
		Action string
	}{scope, limits, privateConfig, "initialize"})
	sum := sha256.Sum256(raw)
	return s.ApplyDescriptorBatch(ctx, owner, scope, DescriptorBatch{RequestID: hex.EncodeToString(sum[:]), Limits: limits, PrivateConfig: bytes.Clone(privateConfig)})
}
