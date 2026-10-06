package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/fabric/search"
	"github.com/pagnet-code/pagnet/transport"
)

// hostedCatalogProtocol is the sealed body protocol shared by the publish
// path (PrepareHostedCatalog) and this import path.
const hostedCatalogProtocol = "pagnet.hosted.catalog.v1"

// hostedCatalogProjectionObjectType is the AAD object type of the at-rest
// sealed projection payload (daemon-local sealing; the relay envelope itself
// uses transport.ObjectTypeFabricDescriptor).
const hostedCatalogProjectionObjectType = "hosted_catalog_projection"

const (
	// hostedCatalogRefreshEvery is the daemon loop's bounded periodic
	// refresh (a refresh, with backoff on failure — never polling of the
	// worker and never a blocking turn operation).
	hostedCatalogRefreshEvery = 30 * time.Second
	hostedCatalogBackoffBase  = time.Second
	hostedCatalogBackoffMax   = time.Minute
	// hostedCatalogPassPages bounds one sync pass's page count (the bounded
	// relay deltas: cursor-scoped page requests, not an unbounded pull).
	hostedCatalogPassPages = 32
)

// HostedCatalogFeedFunc is the incremental index feed: the composition
// supplies a real search backend (step 6 wires the node's); nil = the
// projection is retained but not indexed. The batch's UpstreamCursor is the
// projection's own import watermark — never the registry outbox's.
type HostedCatalogFeedFunc func(ctx context.Context, networkID string, batch search.Batch) error

// triggerHostedCatalogSync starts a bounded import pass for every configured
// network on the CURRENT native connection. It is the host-connection
// establishment hook and the periodic refresh tick: non-blocking, and a
// disconnected (or not-yet-established) daemon simply does nothing.
func (d *Daemon) triggerHostedCatalogSync(ctx context.Context) {
	i := d.HostedCatalogImporter
	if i == nil {
		return
	}
	d.connMu.Lock()
	conn := d.nativeConn
	d.connMu.Unlock()
	if conn == nil {
		return
	}
	for _, networkID := range i.Networks() {
		i.StartNetworkSync(ctx, conn, networkID)
	}
}

// HostedCatalogImporterConfig is the explicit trusted composition for the
// hosted catalog import.
type HostedCatalogImporterConfig struct {
	// TrustedRoots is the EXPLICIT trust set: one self-certifying genesis
	// per domain the daemon may import, composed from the daemon's own
	// local authority (the local installation's registry root — the same
	// root the publisher uses as DomainPublicKey). No code path may add a
	// root from a received record, a descriptor field or a default; an
	// empty set is a composition error (importing nothing is the nil
	// importer, not an empty trust set).
	TrustedRoots []registry.GenesisRecord
	// Networks are the networks whose hosted catalog the daemon imports.
	Networks []string
	// Feed is the incremental index feed (nil = retained, not indexed).
	Feed HostedCatalogFeedFunc
	// MaxRows/MaxBytes are the per-network projection hard limits
	// (0 = the product defaults).
	MaxRows  int
	MaxBytes int
	// BackoffBase/BackoffMax bound the retry backoff after a failed pass
	// (0 = the defaults).
	BackoffBase time.Duration
	BackoffMax  time.Duration
}

// HostedCatalogImporter is the daemon's import side of the hosted catalog:
// bounded relay deltas over the authenticated host connection, verified per
// record against an explicitly trusted domain root, projected into the
// daemon's SEPARATE verified non-authoritative store (the local registry
// can never hold foreign-domain objects), and fed as search.Batch deltas
// into the configured index. A signed isolated record proves authenticity,
// not contiguous foreign ledger or freshness — freshness at invoke time
// stays with the server's admission.
type HostedCatalogImporter struct {
	mu          sync.Mutex
	roots       map[string]registry.GenesisRecord // keyed by domain namespace — configuration only
	networks    []string
	feed        HostedCatalogFeedFunc
	maxRows     int
	maxBytes    int
	backoffBase time.Duration
	backoffMax  time.Duration
	state       *State
	decrypt     func(networkID string, env e2ee.EncryptedPayloadV1, aad e2ee.AAD) (string, error)
	seal        func(networkID, objectID string, plaintext []byte) (e2ee.EncryptedPayloadV1, e2ee.AAD, error)

	// Per-network sync state (guarded by mu): single-flight + backoff.
	inFlight    map[string]bool
	failed      map[string]int
	nextAttempt map[string]time.Time
}

func NewHostedCatalogImporter(d *Daemon, cfg HostedCatalogImporterConfig) (*HostedCatalogImporter, error) {
	if d == nil {
		return nil, errors.New("hosted catalog import requires a daemon")
	}
	if len(cfg.TrustedRoots) == 0 {
		return nil, errors.New("hosted catalog import requires explicitly trusted roots (a nil importer imports nothing)")
	}
	roots := make(map[string]registry.GenesisRecord, len(cfg.TrustedRoots))
	for _, g := range cfg.TrustedRoots {
		body, err := registry.ValidateGenesis(g)
		if err != nil {
			return nil, fmt.Errorf("hosted catalog trusted root: %w", err)
		}
		if _, exists := roots[body.Namespace]; exists {
			return nil, fmt.Errorf("hosted catalog trusted roots conflict for domain %s", body.Namespace)
		}
		roots[body.Namespace] = g
	}
	networks := make([]string, 0, len(cfg.Networks))
	seenNetwork := map[string]bool{}
	for _, n := range cfg.Networks {
		if _, err := domain.ParseID(n); err != nil || seenNetwork[n] {
			return nil, errors.New("hosted catalog import requires unique valid network ids")
		}
		seenNetwork[n] = true
		networks = append(networks, n)
	}
	if len(networks) == 0 {
		return nil, errors.New("hosted catalog import requires at least one network")
	}
	maxRows := cfg.MaxRows
	if maxRows <= 0 {
		maxRows = HostedCatalogDefaultMaxRows
	}
	maxBytes := cfg.MaxBytes
	if maxBytes <= 0 {
		maxBytes = HostedCatalogDefaultMaxBytes
	}
	backoffBase := cfg.BackoffBase
	if backoffBase <= 0 {
		backoffBase = hostedCatalogBackoffBase
	}
	backoffMax := cfg.BackoffMax
	if backoffMax <= 0 {
		backoffMax = hostedCatalogBackoffMax
	}
	if backoffMax < backoffBase {
		backoffMax = backoffBase
	}
	i := &HostedCatalogImporter{
		roots:       roots,
		networks:    networks,
		feed:        cfg.Feed,
		maxRows:     maxRows,
		maxBytes:    maxBytes,
		backoffBase: backoffBase,
		backoffMax:  backoffMax,
		state:       d.state,
		decrypt:     d.decryptProtected,
		inFlight:    map[string]bool{},
		failed:      map[string]int{},
		nextAttempt: map[string]time.Time{},
	}
	// At-rest sealing: the descriptor payload is sealed under the network's
	// CURRENT announced epoch (the binding epoch rule, same as the publish
	// path) so the daemon state never holds the descriptor plaintext. The
	// pinned AAD (retained with the ciphertext) carries the epoch the read
	// port decrypts under — a record is never decrypted against the current
	// or another epoch.
	i.seal = func(networkID, objectID string, plaintext []byte) (e2ee.EncryptedPayloadV1, e2ee.AAD, error) {
		st, err := d.contentCryptoReady(networkID)
		if err != nil {
			return e2ee.EncryptedPayloadV1{}, e2ee.AAD{}, err
		}
		return d.encryptProtected(st, hostedCatalogProjectionObjectType, objectID, d.HostID, "", string(plaintext))
	}
	return i, nil
}

// Networks returns the configured import networks (a copy).
func (i *HostedCatalogImporter) Networks() []string {
	if i == nil {
		return nil
	}
	return slices.Clone(i.networks)
}

// TrustedDomains returns the explicitly trusted domain namespaces (a copy).
func (i *HostedCatalogImporter) TrustedDomains() []string {
	if i == nil {
		return nil
	}
	out := make([]string, 0, len(i.roots))
	for ns := range i.roots {
		out = append(out, ns)
	}
	return out
}

// StartNetworkSync runs one bounded import pass for networkID in its own
// goroutine, unless the network is already syncing or its backoff window is
// still open. It never blocks the caller (the host-connection loop) and the
// pass is fenced to the exact native connection it is given: a disconnect
// never selects a new connection.
func (i *HostedCatalogImporter) StartNetworkSync(ctx context.Context, conn *NativeObservationConnection, networkID string) {
	if i == nil || conn == nil || !i.knownNetwork(networkID) {
		return
	}
	i.mu.Lock()
	if i.inFlight[networkID] || time.Now().Before(i.nextAttempt[networkID]) {
		i.mu.Unlock()
		return
	}
	i.inFlight[networkID] = true
	i.mu.Unlock()
	go func() {
		defer func() {
			i.mu.Lock()
			delete(i.inFlight, networkID)
			i.mu.Unlock()
		}()
		if err := i.SyncNetwork(ctx, conn, networkID); err != nil {
			i.passFailed(networkID)
		} else {
			i.passSucceeded(networkID)
		}
	}()
}

// SyncNetwork runs one bounded import pass: it pulls bounded pages from the
// network's committed cursor until the page is terminal, the cursor stops
// advancing, or the pass-page bound is reached. Deltas are cursor-scoped
// page requests — never an unbounded ledger pull.
func (i *HostedCatalogImporter) SyncNetwork(ctx context.Context, conn *NativeObservationConnection, networkID string) error {
	if i == nil || conn == nil || !i.knownNetwork(networkID) {
		return ErrNativeObservationConflict
	}
	cursor, _, err := i.state.LoadHostedCatalogCursor(ctx, networkID)
	if err != nil {
		return err
	}
	for pages := 0; pages < hostedCatalogPassPages; pages++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		req := transport.FabricHostedCatalogRequest{
			RequestID:  domain.NewID().String(),
			NetworkID:  networkID,
			Cursor:     cursor,
			MaxBytes:   transport.FabricHostedCatalogPageMaxBytes,
			MaxRecords: transport.FabricHostedCatalogPageMaxRecords,
		}
		page, err := conn.RequestHostedFabricCatalog(ctx, req)
		if err != nil {
			return err
		}
		if err := i.ImportPage(ctx, networkID, page); err != nil {
			return err
		}
		if page.Terminal || page.NextCursor == "" {
			return nil
		}
		if page.NextCursor == cursor {
			// The server did not advance the cursor: stop (a non-advancing
			// cursor must never turn the pass into a loop).
			return nil
		}
		cursor = page.NextCursor
	}
	return nil
}

func (i *HostedCatalogImporter) knownNetwork(networkID string) bool {
	if i == nil {
		return false
	}
	return slices.Contains(i.networks, networkID)
}

func (i *HostedCatalogImporter) passFailed(networkID string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.failed[networkID]++
	n := i.failed[networkID] - 1
	if n > 8 {
		n = 8
	}
	delay := i.backoffBase * (1 << uint(n))
	if delay < 0 || delay > i.backoffMax {
		delay = i.backoffMax
	}
	i.nextAttempt[networkID] = time.Now().Add(delay)
}

func (i *HostedCatalogImporter) passSucceeded(networkID string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	delete(i.failed, networkID)
	delete(i.nextAttempt, networkID)
}

// ImportPage verifies every record of one validated page against the
// explicitly trusted roots, retains the verified records (sealed at rest),
// feeds the incremental batch to the configured feed and then advances the
// network's import watermark. A page is atomic: one untrusted, tampered or
// non-advancing record refuses the whole page with an honest error and
// retains nothing (the cursor does not advance, so the next pass re-requests
// the page once the fault is fixed — silently skipping it would be a lie).
func (i *HostedCatalogImporter) ImportPage(ctx context.Context, networkID string, page transport.FabricHostedCatalogPage) error {
	if i == nil || page.NetworkID != networkID {
		return ErrNativeObservationConflict
	}
	oldCursor, _, err := i.state.LoadHostedCatalogCursor(ctx, networkID)
	if err != nil {
		return err
	}
	verified := make([]HostedCatalogRetainedRecord, 0, len(page.Records))
	docs := make([]fabric.SearchDocument, 0, len(page.Records))
	for _, r := range page.Records {
		rec, doc, retired, err := i.verifyPageRecord(ctx, networkID, r)
		if err != nil {
			return err
		}
		recordJSON, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		rr := HostedCatalogRetainedRecord{
			Ref:           r.Ref.String(),
			Kind:          recordKind(rec.Frame.ActionKind),
			Revision:      rec.Frame.NewRevision,
			Sequence:      rec.Frame.Sequence,
			Retired:       retired,
			RootNamespace: r.Ref.Domain(),
			RecordJSON:    recordJSON,
			DataBytes:     len(recordJSON),
		}
		if (rr.Kind == "offer") != r.Ref.IsOffer() {
			return fabric.NewError(fabric.CodeInvalidInput, "hosted catalog record action kind differs from the reference")
		}
		if !retired {
			// Seal the descriptor payload at rest under the network keyring
			// (pinned epoch in the retained AAD) — the daemon state never
			// holds the plaintext.
			cipher, aad, err := i.seal(networkID, r.Ref.String(), rec.Payload)
			if err != nil {
				return fmt.Errorf("hosted catalog projection seal: %w", err)
			}
			cipherJSON, err := json.Marshal(cipher)
			if err != nil {
				return err
			}
			aadJSON, err := json.Marshal(aad)
			if err != nil {
				return err
			}
			rr.Ciphertext = cipherJSON
			rr.AAD = string(aadJSON)
			rr.DataBytes += len(cipherJSON)
		}
		verified = append(verified, rr)
		docs = append(docs, doc)
	}
	changes, err := i.state.RetainHostedCatalogPage(ctx, networkID, i.maxRows, i.maxBytes, verified)
	if err != nil {
		return err
	}
	batch := search.Batch{UpstreamCursor: page.NextCursor}
	for k, ch := range changes {
		if ch.Retired {
			if ch.ReplacedRevision != "" {
				ref, err := fabric.ParseEndpointRef(ch.Ref)
				if err != nil {
					return err
				}
				batch.Deletes = append(batch.Deletes, search.Deletion{Ref: ref, ExpectedRevision: ch.ReplacedRevision})
			}
			continue
		}
		batch.Upserts = append(batch.Upserts, docs[k])
	}
	if i.feed != nil {
		if err := i.feed(ctx, networkID, batch); err != nil {
			// The page is retained; the watermark does NOT advance, so the
			// next pass re-fetches the same page and re-feeds it (the feed
			// batch is recomputable from the page + retained rows).
			return err
		}
	}
	if page.Terminal || page.NextCursor == "" {
		// A terminal page carries no new watermark; the next pass re-requests
		// from the last committed cursor and the server answers terminal
		// again (the retained duplicates are idempotent no-ops).
		return nil
	}
	return i.state.AdvanceHostedCatalogCursor(ctx, networkID, oldCursor, page.NextCursor)
}

// verifyPageRecord authenticates one relayed record: the explicit
// trusted-root gate → the sealed envelope's AAD scope → decryption under the
// envelope's PINNED epoch (refused when that epoch is not in the network
// keyring) → the exported body's self-consistency → the signed record
// against the EXPLICIT trusted root (never the relayed one) → the published
// search document. It never adds a root to the trust set from received data:
// an untrusted domain is refused fail-closed before any retention.
func (i *HostedCatalogImporter) verifyPageRecord(ctx context.Context, networkID string, r transport.FabricHostedCatalogRecord) (registry.Record, fabric.SearchDocument, bool, error) {
	if i == nil {
		return registry.Record{}, fabric.SearchDocument{}, false, ErrNativeObservationConflict
	}
	namespace, err := fabric.DomainNamespace(r.DomainPublicKey)
	if err != nil {
		return registry.Record{}, fabric.SearchDocument{}, false, fabric.NewError(fabric.CodeInvalidInput, "hosted catalog record domain key is invalid")
	}
	trusted, ok := i.roots[namespace]
	if !ok || r.Ref.Domain() != namespace {
		// Fail-closed, honest refusal: the domain root is not EXPLICITLY
		// trusted by this daemon's composition. This is how a forged
		// DomainPublicKey dies — the record is never retained.
		return registry.Record{}, fabric.SearchDocument{}, false, fabric.NewError(fabric.CodeUnauthenticated, "hosted catalog domain is not explicitly trusted")
	}
	if r.AAD.NetworkID != networkID || r.AAD.ObjectID != r.Ref.String() || r.AAD.ObjectType != transport.ObjectTypeFabricDescriptor || r.AAD.Recipient != r.Ref.String() || r.AAD.KeyEpochID != r.Envelope.KeyEpochID || r.AAD.ProtectedContext != nil || r.AAD.NativeContent != nil {
		return registry.Record{}, fabric.SearchDocument{}, false, fabric.NewError(fabric.CodeInvalidInput, "hosted catalog record envelope scope differs from the signed routing")
	}
	plain, err := i.decrypt(networkID, r.Envelope, r.AAD)
	if err != nil {
		return registry.Record{}, fabric.SearchDocument{}, false, fmt.Errorf("hosted catalog record does not authenticate under the pinned network epoch: %w", err)
	}
	var body HostedCatalogBody
	if err := fabric.DecodeJSONWithLimits([]byte(plain), &body, fabric.WireLimits{MaxBytes: 128 << 10, MaxDepth: 64, MaxMembers: 4096}); err != nil {
		return registry.Record{}, fabric.SearchDocument{}, false, fabric.NewError(fabric.CodeInvalidInput, "hosted catalog record body is malformed")
	}
	if body.Protocol != hostedCatalogProtocol {
		return registry.Record{}, fabric.SearchDocument{}, false, fabric.NewError(fabric.CodeInvalidInput, "hosted catalog record body protocol differs")
	}
	// The relayed genesis must be the explicitly trusted root itself (same
	// domain and key). The signature check below uses the explicit root —
	// the relayed one is information, never authority.
	bodyRoot, err := registry.ValidateGenesis(body.Genesis)
	if err != nil {
		return registry.Record{}, fabric.SearchDocument{}, false, err
	}
	trustedRoot, err := registry.ValidateGenesis(trusted)
	if err != nil {
		return registry.Record{}, fabric.SearchDocument{}, false, err
	}
	if bodyRoot.Namespace != trustedRoot.Namespace || string(bodyRoot.PublicKey) != string(trustedRoot.PublicKey) {
		return registry.Record{}, fabric.SearchDocument{}, false, fabric.NewError(fabric.CodeUnauthenticated, "hosted catalog genesis differs from the explicitly trusted root")
	}
	if err := registry.VerifyCatalogRecord(trusted, body.Record, r.Ref, r.Revision); err != nil {
		return registry.Record{}, fabric.SearchDocument{}, false, err
	}
	retired := strings.HasSuffix(body.Record.Frame.ActionKind, ".retire")
	if r.Tombstone != retired {
		return registry.Record{}, fabric.SearchDocument{}, false, fabric.NewError(fabric.CodeInvalidInput, "hosted catalog tombstone flag differs from the signed action")
	}
	doc, err := hostedCatalogSearchDocument(body.Record)
	if err != nil {
		return registry.Record{}, fabric.SearchDocument{}, false, err
	}
	return body.Record, doc, retired, nil
}

func recordKind(action string) string {
	switch action {
	case "endpoint.publish", "endpoint.retire":
		return "endpoint"
	case "offer.publish", "offer.retire":
		return "offer"
	}
	return ""
}

// hostedCatalogSearchDocument maps a verified signed record to the compact
// discovery document: the published descriptor fields only (name / kind /
// description, plus offer tags and the input-schema fingerprint). Never
// protected or instruction content — a signed record authenticates the
// descriptor; the document is what discovery may show. The description is
// carried byte-exact (no compaction): the exactness of the projection is the
// point.
func hostedCatalogSearchDocument(rec registry.Record) (fabric.SearchDocument, error) {
	doc := fabric.SearchDocument{Ref: rec.Frame.ExactTargetRef, Revision: rec.Frame.NewRevision}
	switch rec.Frame.ActionKind {
	case "endpoint.publish":
		var d fabric.EndpointDescriptor
		if err := fabric.DecodeJSONWithLimits(rec.Payload, &d, fabric.WireLimits{MaxBytes: len(rec.Payload), MaxDepth: 64, MaxMembers: 4096}); err != nil {
			return fabric.SearchDocument{}, err
		}
		doc.Name = d.Name
		doc.ShortDescription = d.Description
		doc.Kind = d.Kind
	case "offer.publish":
		var d fabric.OfferDescriptor
		if err := fabric.DecodeJSONWithLimits(rec.Payload, &d, fabric.WireLimits{MaxBytes: len(rec.Payload), MaxDepth: 64, MaxMembers: 4096}); err != nil {
			return fabric.SearchDocument{}, err
		}
		doc.Name = d.Name
		doc.ShortDescription = d.Description
		doc.Tags = d.Tags
		doc.Kind = "fabric.offer"
		if len(d.InputSchema) > 0 {
			digest := sha256.Sum256(d.InputSchema)
			doc.SchemaFingerprint = hex.EncodeToString(digest[:])
		}
	default:
		// Tombstones carry no published fields; the feed emits a delete for
		// them, never an upsert.
	}
	return doc, nil
}

// HostedCatalogProjection is the read-port view of one retained projection
// (the seam step 6 serves discover/describe from).
type HostedCatalogProjection struct {
	NetworkID     string
	Ref           fabric.EndpointRef
	Revision      fabric.Revision
	Sequence      uint64
	Kind          string
	Tombstone     bool
	RootNamespace string
	FirstSeen     time.Time
	LastSeen      time.Time
}

// HostedCatalogProjectionDocument is a live projection with its published
// document decoded from the at-rest sealed payload.
type HostedCatalogProjectionDocument struct {
	HostedCatalogProjection
	Document fabric.SearchDocument
}

// LookupProjection returns the retained projection for (network, ref)
// (ok=false when the projection has never seen it — including tombstones,
// which are read through their tombstone flag).
func (i *HostedCatalogImporter) LookupProjection(ctx context.Context, networkID string, ref fabric.EndpointRef) (HostedCatalogProjection, bool, error) {
	if i == nil {
		return HostedCatalogProjection{}, false, ErrNativeObservationConflict
	}
	if _, err := fabric.ParseEndpointRef(ref.String()); err != nil {
		return HostedCatalogProjection{}, false, err
	}
	row, ok, err := i.state.LookupHostedCatalogProjection(ctx, networkID, ref.String())
	if err != nil || !ok {
		return HostedCatalogProjection{}, false, err
	}
	parsed, err := fabric.ParseEndpointRef(row.Ref)
	if err != nil {
		return HostedCatalogProjection{}, false, err
	}
	return HostedCatalogProjection{
		NetworkID:     row.NetworkID,
		Ref:           parsed,
		Revision:      row.Revision,
		Sequence:      row.Sequence,
		Kind:          row.Kind,
		Tombstone:     row.Retired,
		RootNamespace: row.RootNamespace,
		FirstSeen:     row.FirstSeen,
		LastSeen:      row.LastSeen,
	}, true, nil
}

// LookupProjectionDocument returns a LIVE projection's published document,
// decoded from the at-rest sealed payload under its pinned epoch (a
// tombstone or an unknown ref is ok=false; a payload that no longer
// authenticates under the pinned AAD is an honest error — the projection is
// corrupted, not absent).
func (i *HostedCatalogImporter) LookupProjectionDocument(ctx context.Context, networkID string, ref fabric.EndpointRef) (HostedCatalogProjectionDocument, bool, error) {
	p, ok, err := i.LookupProjection(ctx, networkID, ref)
	if err != nil || !ok || p.Tombstone {
		return HostedCatalogProjectionDocument{}, false, err
	}
	row, ok, err := i.state.LookupHostedCatalogProjection(ctx, networkID, ref.String())
	if err != nil || !ok {
		return HostedCatalogProjectionDocument{}, false, err
	}
	var cipher e2ee.EncryptedPayloadV1
	var aad e2ee.AAD
	if err := json.Unmarshal(row.Ciphertext, &cipher); err != nil {
		return HostedCatalogProjectionDocument{}, false, fmt.Errorf("hosted catalog projection ciphertext is malformed: %w", err)
	}
	if err := json.Unmarshal([]byte(row.AAD), &aad); err != nil {
		return HostedCatalogProjectionDocument{}, false, fmt.Errorf("hosted catalog projection AAD is malformed: %w", err)
	}
	plain, err := i.decrypt(networkID, cipher, aad)
	if err != nil {
		return HostedCatalogProjectionDocument{}, false, fmt.Errorf("hosted catalog projection no longer authenticates under its pinned epoch: %w", err)
	}
	var rec registry.Record
	if err := fabric.DecodeJSONWithLimits(row.Record, &rec, fabric.WireLimits{MaxBytes: 128 << 10, MaxDepth: 64, MaxMembers: 4096}); err != nil {
		return HostedCatalogProjectionDocument{}, false, err
	}
	if string(rec.Payload) != plain {
		return HostedCatalogProjectionDocument{}, false, errors.New("hosted catalog projection sealed payload differs from the retained signed record")
	}
	doc, err := hostedCatalogSearchDocumentFromPayload(rec, []byte(plain))
	if err != nil {
		return HostedCatalogProjectionDocument{}, false, err
	}
	return HostedCatalogProjectionDocument{HostedCatalogProjection: p, Document: doc}, true, nil
}

// ListProjections returns the network's retained projections in ref order,
// bounded (the rebuild seam: a configured index is reproducible from the
// projection alone).
func (i *HostedCatalogImporter) ListProjections(ctx context.Context, networkID string, limit int) ([]HostedCatalogProjection, error) {
	if i == nil {
		return nil, ErrNativeObservationConflict
	}
	rows, err := i.state.ListHostedCatalogProjections(ctx, networkID, limit)
	if err != nil {
		return nil, err
	}
	out := make([]HostedCatalogProjection, 0, len(rows))
	for _, row := range rows {
		parsed, err := fabric.ParseEndpointRef(row.Ref)
		if err != nil {
			return nil, err
		}
		out = append(out, HostedCatalogProjection{
			NetworkID:     row.NetworkID,
			Ref:           parsed,
			Revision:      row.Revision,
			Sequence:      row.Sequence,
			Kind:          row.Kind,
			Tombstone:     row.Retired,
			RootNamespace: row.RootNamespace,
			FirstSeen:     row.FirstSeen,
			LastSeen:      row.LastSeen,
		})
	}
	return out, nil
}

// hostedCatalogSearchDocumentFromPayload builds the discovery document from
// the DECRYPTED payload bytes (the read port's actual path) and refuses a
// payload that does not decode to the record's signed descriptor shape.
func hostedCatalogSearchDocumentFromPayload(rec registry.Record, plain []byte) (fabric.SearchDocument, error) {
	doc := fabric.SearchDocument{Ref: rec.Frame.ExactTargetRef, Revision: rec.Frame.NewRevision}
	switch rec.Frame.ActionKind {
	case "endpoint.publish":
		var d fabric.EndpointDescriptor
		if err := fabric.DecodeJSONWithLimits(plain, &d, fabric.WireLimits{MaxBytes: len(plain), MaxDepth: 64, MaxMembers: 4096}); err != nil {
			return fabric.SearchDocument{}, err
		}
		if d.Ref != rec.Frame.ExactTargetRef || d.Revision != rec.Frame.NewRevision {
			return fabric.SearchDocument{}, errors.New("hosted catalog projection payload differs from the signed record")
		}
		doc.Name = d.Name
		doc.ShortDescription = d.Description
		doc.Kind = d.Kind
	case "offer.publish":
		var d fabric.OfferDescriptor
		if err := fabric.DecodeJSONWithLimits(plain, &d, fabric.WireLimits{MaxBytes: len(plain), MaxDepth: 64, MaxMembers: 4096}); err != nil {
			return fabric.SearchDocument{}, err
		}
		if d.Ref != rec.Frame.ExactTargetRef || d.Revision != rec.Frame.NewRevision {
			return fabric.SearchDocument{}, errors.New("hosted catalog projection payload differs from the signed record")
		}
		doc.Name = d.Name
		doc.ShortDescription = d.Description
		doc.Tags = d.Tags
		doc.Kind = "fabric.offer"
		if len(d.InputSchema) > 0 {
			digest := sha256.Sum256(d.InputSchema)
			doc.SchemaFingerprint = hex.EncodeToString(digest[:])
		}
	default:
		return fabric.SearchDocument{}, errors.New("hosted catalog projection has no published document")
	}
	return doc, nil
}
