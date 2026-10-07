//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/localinstallation"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/fabric/search"
	"github.com/pagnet-code/pagnet/transport"
)

// newForeignInstallation bootstraps a genuine, independent local
// installation (its own domain, its own root key): the "original worker's"
// registry for the hosted catalog import tests.
func newForeignInstallation(t *testing.T, ctx context.Context, name string) (*localinstallation.Installation, fabric.ExecutionContext, registry.AuthorityIdentity) {
	t.Helper()
	parent := t.TempDir()
	socket := filepath.Join(parent, "run", name+".sock")
	inst, err := localinstallation.Bootstrap(ctx, filepath.Join(parent, "local-"+name), localinstallation.Options{Settings: localinstallation.DefaultSettings(socket)})
	if err != nil {
		t.Fatalf("bootstrap %s installation: %v", name, err)
	}
	t.Cleanup(func() { inst.Close() })
	owner, err := inst.Operator(ctx)
	if err != nil {
		t.Fatalf("%s operator: %v", name, err)
	}
	return inst, owner, inst.Store.AuthorityIdentity()
}

func registerForeignEndpoint(t *testing.T, ctx context.Context, inst *localinstallation.Installation, owner fabric.ExecutionContext, root registry.AuthorityIdentity, name, description string, metadata map[string]json.RawMessage) (fabric.EndpointRef, fabric.Revision) {
	t.Helper()
	ref, err := fabric.NewEndpointRef(root.PublicKey)
	if err != nil {
		t.Fatalf("new endpoint ref: %v", err)
	}
	d := fabric.EndpointDescriptor{Ref: ref, Kind: "actor.agent", Name: name, Description: description, Bindings: []fabric.BindingSummary{{ID: "original", Protocol: "pagnet.agent.hosted-native.v1", Version: "1"}}, Metadata: metadata}
	rev, err := inst.Store.Register(ctx, owner, fabric.RegistryUpdate{Descriptor: d})
	if err != nil {
		t.Fatalf("register foreign endpoint: %v", err)
	}
	return ref, rev
}

// updateForeignEndpoint publishes a newer revision of the same endpoint.
func updateForeignEndpoint(t *testing.T, ctx context.Context, inst *localinstallation.Installation, owner fabric.ExecutionContext, ref fabric.EndpointRef, expected fabric.Revision, description string) fabric.Revision {
	t.Helper()
	d := fabric.EndpointDescriptor{Ref: ref, Kind: "actor.agent", Name: "same", Description: description, Bindings: []fabric.BindingSummary{{ID: "original", Protocol: "pagnet.agent.hosted-native.v1", Version: "1"}}}
	rev, err := inst.Store.Update(ctx, owner, fabric.RegistryUpdate{Descriptor: d, ExpectedRevision: expected})
	if err != nil {
		t.Fatalf("update foreign endpoint: %v", err)
	}
	return rev
}

// exportCurrentRecord exports the exact CURRENT signed record through a real
// CatalogExporter over the given installation (the export side, unmodified).
func exportCurrentRecord(t *testing.T, ctx context.Context, inst *localinstallation.Installation, owner fabric.ExecutionContext, ref fabric.EndpointRef, revision fabric.Revision) registry.Record {
	t.Helper()
	exporter, err := registry.NewCatalogExporter(ctx, inst.Store, owner)
	if err != nil {
		t.Fatalf("catalog exporter: %v", err)
	}
	rec, err := exporter.Exact(ctx, ref, revision)
	if err != nil {
		t.Fatalf("export current record: %v", err)
	}
	return rec
}

// hostedCatalogTestServer is the server-side half of the new message pair
// for the import tests: bounded pages of REAL exported records, cursor-
// scoped, answered on the daemon's real authenticated connection exactly
// like the control plane would. The queued pages are test-controlled (the
// server frames them with cursor semantics; every record inside is a
// genuine signed export sealed under the network epoch).
type hostedCatalogTestServer struct {
	t      *testing.T
	conn   *NativeObservationConnection
	pages  []transport.FabricHostedCatalogPage
	// base is the persisted import cursor when the pages were queued, so
	// each re-queue is served from its own head (the importer keeps its
	// global watermark across queue generations).
	base int
	// served counts served pages; the request goroutine increments it and
	// the test goroutine polls it.
	served int64
	// echoPublish, when set, makes the server ECHO the stored publish:
	// every request is answered with a single-record terminal page built
	// from the publication the fake host last accepted on
	// MsgFabricHostedPublish — the same sealed envelope, routing and
	// stored tombstone flag the real server will serve (Phase C). It
	// ignores the queued pages entirely.
	echoPublish func() (transport.FabricHostedPublication, bool)
}

func (s *hostedCatalogTestServer) serveRequest(req transport.FabricHostedCatalogRequest) {
	s.t.Helper()
	if s.echoPublish != nil {
		atomic.AddInt64(&s.served, 1)
		pub, ok := s.echoPublish()
		if !ok {
			// Nothing stored yet: an empty terminal page.
			s.conn.hostedFabricCatalogPageDisposition(transport.FabricHostedCatalogPage{RequestID: req.RequestID, NetworkID: req.NetworkID, Terminal: true})
			return
		}
		page := transport.FabricHostedCatalogPage{
			RequestID: req.RequestID,
			NetworkID: req.NetworkID,
			Records: []transport.FabricHostedCatalogRecord{{
				Ref:             pub.Ref,
				Revision:        pub.Revision,
				DomainPublicKey: pub.DomainPublicKey,
				Tombstone:       pub.Tombstone,
				Envelope:        pub.Envelope,
				AAD:             pub.AAD,
			}},
			Terminal: true,
		}
		s.conn.hostedFabricCatalogPageDisposition(page)
		return
	}
	offset := 0
	if req.Cursor != "" {
		n, err := strconv.Atoi(req.Cursor)
		if err != nil || n < 0 {
			s.t.Fatalf("server: unparseable import cursor %q", req.Cursor)
		}
		offset = n
	}
	offset -= s.base
	atomic.AddInt64(&s.served, 1)
	if offset < 0 || offset >= len(s.pages) {
		// Past the tail: an empty terminal page.
		s.conn.hostedFabricCatalogPageDisposition(transport.FabricHostedCatalogPage{RequestID: req.RequestID, NetworkID: req.NetworkID, Terminal: true})
		return
	}
	page := s.pages[offset]
	page.RequestID = req.RequestID
	page.NetworkID = req.NetworkID
	if !page.Terminal {
		page.NextCursor = strconv.Itoa(offset + 1)
	}
	s.conn.hostedFabricCatalogPageDisposition(page)
}

// buildCatalogPageRecord stores one REAL exported record the way the server
// does: the HostedCatalogBody (protocol + the domain's genesis + the signed
// record) sealed under the network epoch, with the routing AAD.
func (f *hostedGuardFixture) buildCatalogPageRecord(t *testing.T, rec registry.Record, genesis registry.GenesisRecord, ref fabric.EndpointRef, revision fabric.Revision, domainPublicKey []byte, tombstone bool) transport.FabricHostedCatalogRecord {
	t.Helper()
	body, err := json.Marshal(HostedCatalogBody{hostedCatalogProtocol, genesis, rec})
	if err != nil {
		t.Fatalf("marshal hosted catalog body: %v", err)
	}
	aad := e2ee.AAD{
		ProtocolVersion: transport.ProtocolVersion,
		TenantID:        f.admission.TenantID,
		NetworkID:       f.networkID,
		ObjectType:      transport.ObjectTypeFabricDescriptor,
		ObjectID:        ref.String(),
		Sender:          "origin-worker",
		Recipient:       ref.String(),
		CreatedAt:       "2026-10-05T00:00:00Z",
		KeyEpochID:      f.keyEpochID,
	}
	cipher, err := e2ee.Encrypt(body, f.key, aad)
	if err != nil {
		t.Fatalf("encrypt hosted catalog body: %v", err)
	}
	return transport.FabricHostedCatalogRecord{Ref: ref, Revision: revision, DomainPublicKey: domainPublicKey, Tombstone: tombstone, Envelope: cipher, AAD: aad}
}

// queuePagesFor pins the queued generation to the importer's current
// persisted cursor (each queue generation is served from its own head).
func (f *hostedGuardFixture) queuePagesFor(t *testing.T, pages ...transport.FabricHostedCatalogPage) {
	t.Helper()
	server := &hostedCatalogTestServer{t: t, conn: f.ownerConn, pages: pages}
	if usage, ok, err := f.d.state.LoadHostedCatalogUsage(t.Context(), f.networkID); err == nil && ok {
		server.base, _ = strconv.Atoi(usage.Cursor)
	}
	f.catalogServer.Store(server)
}

// queueRecordPages queues one bounded page per record (the last page
// terminal) on a fresh test server.
func (f *hostedGuardFixture) queueRecordPages(t *testing.T, records ...transport.FabricHostedCatalogRecord) {
	t.Helper()
	var pages []transport.FabricHostedCatalogPage
	for i, r := range records {
		pages = append(pages, transport.FabricHostedCatalogPage{
			NetworkID: f.networkID,
			Records:   []transport.FabricHostedCatalogRecord{r},
			Terminal:  i == len(records)-1,
		})
	}
	f.queuePagesFor(t, pages...)
}

// queueEchoPublishPages queues an echo-mode test server (step 6c): every
// READ request is answered from the publication the fake host last stored
// from a publish message — the stored flag rides the page, no queued pages.
func (f *hostedGuardFixture) queueEchoPublishPages(t *testing.T) {
	t.Helper()
	server := &hostedCatalogTestServer{
		t:    t,
		conn: f.ownerConn,
		echoPublish: func() (transport.FabricHostedPublication, bool) {
			pub := f.publishStore.Load()
			if pub == nil {
				return transport.FabricHostedPublication{}, false
			}
			return *pub, true
		},
	}
	f.catalogServer.Store(server)
}

func (f *hostedGuardFixture) newCatalogImporter(t *testing.T, trustedRoots []registry.GenesisRecord, feed HostedCatalogFeedFunc, maxRows, maxBytes int, backoffBase, backoffMax time.Duration) *HostedCatalogImporter {
	t.Helper()
	i, err := NewHostedCatalogImporter(f.d, HostedCatalogImporterConfig{
		TrustedRoots: trustedRoots,
		Networks:     []string{f.networkID},
		Feed:         feed,
		MaxRows:      maxRows,
		MaxBytes:     maxBytes,
		BackoffBase:  backoffBase,
		BackoffMax:   backoffMax,
	})
	if err != nil {
		t.Fatalf("compose hosted catalog importer: %v", err)
	}
	f.d.HostedCatalogImporter = i
	return i
}

// waitForProjection polls the read port (test-side waiting on daemon state,
// like the step-4 tests) until the projection for ref reaches wanted
// presence.
func (f *hostedGuardFixture) waitForProjection(t *testing.T, i *HostedCatalogImporter, ref fabric.EndpointRef, timeout time.Duration) HostedCatalogProjection {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last HostedCatalogProjection
	for time.Now().Before(deadline) {
		p, ok, err := i.LookupProjection(t.Context(), f.networkID, ref)
		if err != nil {
			t.Fatalf("lookup projection: %v", err)
		}
		if ok {
			last = p
			return p
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("projection for %s never appeared (last: %+v)", ref, last)
	return last
}

func (f *hostedGuardFixture) assertNotProjected(t *testing.T, i *HostedCatalogImporter, ref fabric.EndpointRef) {
	t.Helper()
	if _, ok, err := i.LookupProjection(t.Context(), f.networkID, ref); err != nil {
		t.Fatalf("lookup projection: %v", err)
	} else if ok {
		t.Fatalf("projection for %s was retained; the page must have been refused", ref)
	}
}

func (f *hostedGuardFixture) assertCursorUnchanged(t *testing.T, want string) {
	t.Helper()
	usage, ok, err := f.d.state.LoadHostedCatalogUsage(t.Context(), f.networkID)
	if err != nil {
		t.Fatalf("load import usage: %v", err)
	}
	if want == "" {
		if ok {
			t.Fatalf("import row exists with cursor %q (want none): %+v", usage.Cursor, usage)
		}
		return
	}
	if !ok || usage.Cursor != want {
		t.Fatalf("import cursor = %q (ok=%v), want %q", usage.Cursor, ok, want)
	}
}

func newLexicalIndex(t *testing.T) *search.Backend {
	t.Helper()
	b, err := search.New(search.Config{})
	if err != nil {
		t.Fatalf("new lexical backend: %v", err)
	}
	return b
}

// TestHostedCatalogImportProjectsVerifiedRecordsAndFeedsLexicalIndex is the
// canonical two-installation happy path: installation A (the original
// worker's registry, the foreign domain) exports a real signed record
// (Unicode name/description + metadata); a real host-protocol test server
// serves it on the new message pair; a real daemon composed with the
// explicit root = A's registry root imports, verifies, projects (sealed at
// rest) and feeds a real lexical search backend.
func TestHostedCatalogImportProjectsVerifiedRecordsAndFeedsLexicalIndex(t *testing.T) {
	f := newHostedGuardFixture(t)
	ctx := t.Context()
	a, ownerA, rootA := newForeignInstallation(t, ctx, "a")
	genesisA := a.Store.Genesis()

	const name = "UnicodeBridge ünïcodé-α endpoint"
	const description = "Exakt: 日本語説明 — café & naïve"
	metadata := map[string]json.RawMessage{"extensions.example": json.RawMessage(`{"note":"byte-exact"}`)}
	refA, revA := registerForeignEndpoint(t, ctx, a, ownerA, rootA, name, description, metadata)
	recA := exportCurrentRecord(t, ctx, a, ownerA, refA, revA)

	refB, revB := registerForeignEndpoint(t, ctx, a, ownerA, rootA, "SecondAgent", "Second descriptor", nil)
	recB := exportCurrentRecord(t, ctx, a, ownerA, refB, revB)

	f.queueRecordPages(t,
		f.buildCatalogPageRecord(t, recA, genesisA, refA, revA, rootA.PublicKey, false),
		f.buildCatalogPageRecord(t, recB, genesisA, refB, revB, rootA.PublicKey, false),
	)

	idx := newLexicalIndex(t)
	// The feed runs on the importer's goroutine: the captured batches are
	// observed only under this mutex, after the wait below proves both pages
	// were fully processed.
	var (
		feedMu     sync.Mutex
		fedBatches []search.Batch
		feedErr    error
	)
	i := f.newCatalogImporter(t, []registry.GenesisRecord{genesisA}, func(ctx context.Context, networkID string, batch search.Batch) error {
		if networkID != f.networkID {
			feedErr = fmt.Errorf("feed network = %q, want %q", networkID, f.networkID)
			return feedErr
		}
		feedMu.Lock()
		fedBatches = append(fedBatches, batch)
		feedMu.Unlock()
		return idx.Apply(ctx, batch)
	}, 0, 0, time.Second, time.Minute)

	// The node's local registry (installation B) before the import: the
	// fixture's own register leaves exactly the fixture's pending delta.
	pendingBefore, _ := f.installation.Store.PendingIndex(ctx, 32)

	// Drive the real connection-establishment hook (the daemon loop's exact
	// trigger) and wait for the bounded pass to settle.
	f.d.triggerHostedCatalogSync(ctx)
	pA := f.waitForProjection(t, i, refA, 15*time.Second)
	pB := f.waitForProjection(t, i, refB, 15*time.Second)

	// Projected, verified, from the explicit root — not the local registry.
	if pA.Revision != revA || pA.Kind != "endpoint" || pA.Tombstone || pA.RootNamespace != rootA.Namespace {
		t.Fatalf("projection A = %+v, want revision %s from root %s", pA, revA, rootA.Namespace)
	}
	if pB.Revision != revB {
		t.Fatalf("projection B revision = %s, want %s", pB.Revision, revB)
	}

	// SEALED at rest with the network keyring, pinned epoch: the ciphertext
	// must not carry the plaintext descriptor, and the pinned AAD carries
	// the epoch the record was sealed under.
	row, ok, err := f.d.state.LookupHostedCatalogProjection(ctx, f.networkID, refA.String())
	if err != nil || !ok {
		t.Fatalf("projection row: ok=%v err=%v", ok, err)
	}
	if len(row.Ciphertext) == 0 || bytes.Contains(row.Ciphertext, []byte(name)) || bytes.Contains(row.Ciphertext, []byte(description)) {
		t.Fatalf("projection row is not sealed at rest (ciphertext = %q)", row.Ciphertext)
	}
	var rowAAD e2ee.AAD
	if err := json.Unmarshal([]byte(row.AAD), &rowAAD); err != nil || rowAAD.ObjectType != hostedCatalogProjectionObjectType || rowAAD.KeyEpochID != f.keyEpochID || rowAAD.NetworkID != f.networkID {
		t.Fatalf("pinned projection AAD = %+v (err %v), want the pinned network epoch", rowAAD, err)
	}

	// The read port decodes the sealed payload under the pinned epoch: the
	// descriptor round-trips BYTE-EXACT (Unicode name/description, metadata
	// inside the sealed payload) into the published search document.
	doc, ok, err := i.LookupProjectionDocument(ctx, f.networkID, refA)
	if err != nil || !ok {
		t.Fatalf("projection document: ok=%v err=%v", ok, err)
	}
	if doc.Document.Name != name || doc.Document.ShortDescription != description || doc.Document.Kind != "actor.agent" || doc.Document.Revision != revA {
		t.Fatalf("search document differs from the signed descriptor: %+v", doc.Document)
	}
	var sealed struct {
		Metadata map[string]json.RawMessage `json:"metadata"`
	}
	// The sealed payload must equal the retained signed payload byte-for-byte
	// (the read port enforces this; verify the metadata survived the trip).
	var recA2 registry.Record
	if err := json.Unmarshal(row.Record, &recA2); err != nil {
		t.Fatalf("unmarshal retained record: %v", err)
	}
	if err := json.Unmarshal(recA2.Payload, &sealed); err != nil || len(sealed.Metadata["extensions.example"]) == 0 {
		t.Fatalf("metadata did not round-trip through the projection: %v", err)
	}

	// The feed emitted real Batch upserts into the real lexical backend, and
	// a discover-shaped query serves the imported descriptor. The feed runs
	// on the importer's goroutine: wait for both page batches (each
	// ImportPage feeds before it advances the watermark — two batches prove
	// both pages were fully processed), then observe under the mutex.
	deadline := time.Now().Add(15 * time.Second)
	for {
		feedMu.Lock()
		n := len(fedBatches)
		feedMu.Unlock()
		if n == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("feed delivered %d batches, want 2", n)
		}
		time.Sleep(10 * time.Millisecond)
	}
	feedMu.Lock()
	batches := make([]search.Batch, len(fedBatches))
	copy(batches, fedBatches)
	err = feedErr
	feedMu.Unlock()
	if err != nil {
		t.Fatalf("feed: %v", err)
	}
	if len(batches) != 2 || len(batches[0].Upserts) != 1 || len(batches[1].Upserts) != 1 {
		t.Fatalf("fed batches = %+v, want one upsert per page", batches)
	}
	if batches[0].UpstreamCursor != "1" {
		t.Fatalf("feed cursor = %q, want the projection watermark %q", batches[0].UpstreamCursor, "1")
	}
	res, err := idx.Search(ctx, fabric.DiscoverRequest{Query: "unicodebridge", Limit: 10})
	if err != nil {
		t.Fatalf("discover-shaped search: %v", err)
	}
	found := false
	for _, c := range res.Candidates {
		if c.Document.Ref == refA && c.Document.Name == name {
			found = true
		}
	}
	if !found {
		t.Fatalf("lexical index does not serve the imported descriptor: %+v", res.Candidates)
	}
	if d, ok, err := idx.Document(ctx, refA, revA); err != nil || !ok || d.ShortDescription != description {
		t.Fatalf("indexed document = %+v ok=%v err=%v, want the byte-exact descriptor", d, ok, err)
	}

	// The import watermark is the projection's own cursor (page 2 is
	// terminal: the committed watermark is the last advanced one).
	usage, ok, err := f.d.state.LoadHostedCatalogUsage(ctx, f.networkID)
	if err != nil || !ok || usage.Cursor != "1" || usage.RowsUsed != 2 {
		t.Fatalf("import usage = %+v ok=%v err=%v, want cursor 1 with 2 rows", usage, ok, err)
	}

	// The node's LOCAL registry was never touched: it cannot resolve the
	// foreign ref, and its outbox is exactly as before the import.
	if _, err := f.installation.Store.GetEndpoint(ctx, refA, revA); err == nil {
		t.Fatalf("local registry resolved the foreign ref; the import must stay in the separate projection")
	}
	pendingAfter, _ := f.installation.Store.PendingIndex(ctx, 32)
	if len(pendingBefore.Upserts) != len(pendingAfter.Upserts) {
		t.Fatalf("local registry outbox changed by the import: before=%+v after=%+v", pendingBefore, pendingAfter)
	}
}

// TestHostedCatalogImportRefusesUntrustedAndTamperedRecords covers the
// fail-closed trust gate and the tamper matrix: each variant is refused with
// an honest error, nothing is retained, the cursor does not move.
func TestHostedCatalogImportRefusesUntrustedAndTamperedRecords(t *testing.T) {
	f := newHostedGuardFixture(t)
	ctx := t.Context()
	a, ownerA, rootA := newForeignInstallation(t, ctx, "a")
	c, ownerC, rootC := newForeignInstallation(t, ctx, "c")
	genesisA := a.Store.Genesis()
	genesisB := f.installation.Store.Genesis()

	refA, revA := registerForeignEndpoint(t, ctx, a, ownerA, rootA, "TamperCheck", "tamper check", nil)
	recA := exportCurrentRecord(t, ctx, a, ownerA, refA, revA)
	refC, revC := registerForeignEndpoint(t, ctx, c, ownerC, rootC, "ForeignC", "untrusted domain", nil)
	recC := exportCurrentRecord(t, ctx, c, ownerC, refC, revC)

	// nil feed: the page would be retained but not indexed — the refusals
	// below must not retain it anyway.
	i := f.newCatalogImporter(t, []registry.GenesisRecord{genesisA}, nil, 0, 0, time.Second, time.Minute)

	mutateSignature := func(rec registry.Record) registry.Record {
		r := rec
		r.Signature = append([]byte(nil), r.Signature...) // no aliasing
		r.Signature[0] ^= 1
		return r
	}
	tamperCiphertext := func(r transport.FabricHostedCatalogRecord) transport.FabricHostedCatalogRecord {
		raw, err := base64.StdEncoding.DecodeString(r.Envelope.Ciphertext)
		if err != nil {
			t.Fatalf("decode ciphertext: %v", err)
		}
		raw[len(raw)-1] ^= 1
		r.Envelope.Ciphertext = base64.StdEncoding.EncodeToString(raw)
		return r
	}

	cases := []struct {
		name    string
		record  func() transport.FabricHostedCatalogRecord
		ref     fabric.EndpointRef
		wantErr string
	}{
		{
			name: "altered signature",
			record: func() transport.FabricHostedCatalogRecord {
				return f.buildCatalogPageRecord(t, mutateSignature(recA), genesisA, refA, revA, rootA.PublicKey, false)
			},
			ref:     refA,
			wantErr: "signed record authority or exact payload commitment mismatch",
		},
		{
			name: "forged domain public key",
			record: func() transport.FabricHostedCatalogRecord {
				return f.buildCatalogPageRecord(t, recA, genesisA, refA, revA, rootC.PublicKey, false)
			},
			ref:     refA,
			wantErr: "Invalid hosted catalog record routing",
		},
		{
			name: "untrusted domain",
			record: func() transport.FabricHostedCatalogRecord {
				return f.buildCatalogPageRecord(t, recC, c.Store.Genesis(), refC, revC, rootC.PublicKey, false)
			},
			ref:     refC,
			wantErr: "not explicitly trusted",
		},
		{
			name: "AAD network mismatch",
			record: func() transport.FabricHostedCatalogRecord {
				r := f.buildCatalogPageRecord(t, recA, genesisA, refA, revA, rootA.PublicKey, false)
				r.AAD.NetworkID = domain.NewID().String()
				return r
			},
			ref:     refA,
			wantErr: "Invalid protected hosted catalog record",
		},
		{
			name: "AAD epoch mismatch",
			record: func() transport.FabricHostedCatalogRecord {
				r := f.buildCatalogPageRecord(t, recA, genesisA, refA, revA, rootA.PublicKey, false)
				r.AAD.KeyEpochID = "epoch-unknown"
				return r
			},
			ref:     refA,
			wantErr: "Invalid protected hosted catalog record",
		},
		{
			name: "ciphertext tampered",
			record: func() transport.FabricHostedCatalogRecord {
				return tamperCiphertext(f.buildCatalogPageRecord(t, recA, genesisA, refA, revA, rootA.PublicKey, false))
			},
			ref:     refA,
			wantErr: "does not authenticate under the pinned network epoch",
		},
		{
			name: "relayed genesis differs from trusted root",
			record: func() transport.FabricHostedCatalogRecord {
				// A's record, but the sealed body carries B's (valid,
				// self-certifying) genesis: the relayed genesis is
				// information, never authority.
				return f.buildCatalogPageRecord(t, recA, genesisB, refA, revA, rootA.PublicKey, false)
			},
			ref:     refA,
			wantErr: "genesis differs from the explicitly trusted root",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f.queueRecordPages(t, tc.record())
			err := i.SyncNetwork(ctx, f.ownerConn, f.networkID)
			if err == nil {
				t.Fatalf("page accepted; want the honest refusal %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %q, want it to contain %q", err, tc.wantErr)
			}
			f.assertNotProjected(t, i, tc.ref)
			f.assertCursorUnchanged(t, "")
		})
	}
}

// TestHostedCatalogImportMonotonicRevisionsTombstonesAndFeedDeletes covers
// the per-ref monotonicity + tombstone discipline end to end: duplicate
// exact record = idempotent no-op; older sequence after newer = refused;
// tombstone imports and the feed emits the exact Delete; a revived older
// profile after a tombstone = refused.
func TestHostedCatalogImportMonotonicRevisionsTombstonesAndFeedDeletes(t *testing.T) {
	f := newHostedGuardFixture(t)
	ctx := t.Context()
	a, ownerA, rootA := newForeignInstallation(t, ctx, "a")
	genesisA := a.Store.Genesis()

	refA, rev1 := registerForeignEndpoint(t, ctx, a, ownerA, rootA, "Mono", "v1", nil)
	recV1 := exportCurrentRecord(t, ctx, a, ownerA, refA, rev1) // exported while v1 is current
	rev2 := updateForeignEndpoint(t, ctx, a, ownerA, refA, rev1, "v2")
	recV2 := exportCurrentRecord(t, ctx, a, ownerA, refA, rev2)

	idx := newLexicalIndex(t)
	var fedBatches []search.Batch
	i := f.newCatalogImporter(t, []registry.GenesisRecord{genesisA}, func(ctx context.Context, networkID string, batch search.Batch) error {
		fedBatches = append(fedBatches, batch)
		return idx.Apply(ctx, batch)
	}, 0, 0, time.Second, time.Minute)

	// 1. The newer revision imports and feeds.
	f.queueRecordPages(t, f.buildCatalogPageRecord(t, recV2, genesisA, refA, rev2, rootA.PublicKey, false))
	if err := i.SyncNetwork(ctx, f.ownerConn, f.networkID); err != nil {
		t.Fatalf("import v2: %v", err)
	}
	if d, ok, _ := idx.Document(ctx, refA, rev2); !ok || d.ShortDescription != "v2" {
		t.Fatalf("index after v2 = ok=%v doc=%+v", ok, d)
	}

	// 2. The OLDER sequence after the newer one is refused (stale page);
	// the projection keeps v2.
	f.queueRecordPages(t, f.buildCatalogPageRecord(t, recV1, genesisA, refA, rev1, rootA.PublicKey, false))
	if err := i.SyncNetwork(ctx, f.ownerConn, f.networkID); err == nil {
		t.Fatalf("older sequence after newer accepted; want the monotonicity refusal")
	}
	p, ok, err := i.LookupProjection(ctx, f.networkID, refA)
	if err != nil || !ok || p.Revision != rev2 {
		t.Fatalf("projection after stale page = %+v ok=%v err=%v, want revision %s retained", p, ok, err, rev2)
	}
	if d, ok, _ := idx.Document(ctx, refA, rev2); !ok || d.ShortDescription != "v2" {
		t.Fatalf("index changed by a refused page: ok=%v doc=%+v", ok, d)
	}

	// 3. The duplicate exact record is an idempotent no-op (the row, its
	// timestamps and the capacity ledger stay untouched).
	rowBefore, _, _ := f.d.state.LookupHostedCatalogProjection(ctx, f.networkID, refA.String())
	usageBefore, _, _ := f.d.state.LoadHostedCatalogUsage(ctx, f.networkID)
	f.queueRecordPages(t, f.buildCatalogPageRecord(t, recV2, genesisA, refA, rev2, rootA.PublicKey, false))
	if err := i.SyncNetwork(ctx, f.ownerConn, f.networkID); err != nil {
		t.Fatalf("duplicate exact record refused: %v", err)
	}
	rowAfter, _, _ := f.d.state.LookupHostedCatalogProjection(ctx, f.networkID, refA.String())
	usageAfter, _, _ := f.d.state.LoadHostedCatalogUsage(ctx, f.networkID)
	if rowBefore.LastSeen != rowAfter.LastSeen || rowBefore.DataBytes != rowAfter.DataBytes {
		t.Fatalf("duplicate record touched the retained row: before=%+v after=%+v", rowBefore, rowAfter)
	}
	if usageBefore.RowsUsed != usageAfter.RowsUsed || usageBefore.BytesUsed != usageAfter.BytesUsed {
		t.Fatalf("duplicate record touched the capacity ledger: before=%+v after=%+v", usageBefore, usageAfter)
	}

	// 4. Retire on the export side: the tombstone record imports, the feed
	// emits the exact Delete with ExpectedRevision, the index stops serving.
	revT, err := a.Store.Retire(ctx, ownerA, refA, rev2)
	if err != nil {
		t.Fatalf("retire foreign endpoint: %v", err)
	}
	recT := exportCurrentRecord(t, ctx, a, ownerA, refA, revT)
	fedBatches = nil
	f.queueRecordPages(t, f.buildCatalogPageRecord(t, recT, genesisA, refA, revT, rootA.PublicKey, true))
	if err := i.SyncNetwork(ctx, f.ownerConn, f.networkID); err != nil {
		t.Fatalf("import tombstone: %v", err)
	}
	if len(fedBatches) != 1 {
		t.Fatalf("tombstone fed batches = %d, want 1", len(fedBatches))
	}
	batch := fedBatches[0]
	if len(batch.Upserts) != 0 || len(batch.Deletes) != 1 || batch.Deletes[0].Ref != refA || batch.Deletes[0].ExpectedRevision != rev2 {
		t.Fatalf("tombstone batch = %+v, want exactly one delete for %s @ %s", batch, refA, rev2)
	}
	if _, ok, _ := idx.Document(ctx, refA, ""); ok {
		t.Fatalf("index still serves the retired ref after the feed delete")
	}
	p, ok, err = i.LookupProjection(ctx, f.networkID, refA)
	if err != nil || !ok || !p.Tombstone || p.Revision != revT {
		t.Fatalf("projection after tombstone = %+v ok=%v err=%v, want the tombstone retained", p, ok, err)
	}

	// 5. A REVIVED OLDER PROFILE after the tombstone is refused: the old
	// live record (v1) cannot reuse the retired ref.
	f.queueRecordPages(t, f.buildCatalogPageRecord(t, recV1, genesisA, refA, rev1, rootA.PublicKey, false))
	if err := i.SyncNetwork(ctx, f.ownerConn, f.networkID); err == nil {
		t.Fatalf("revived old profile after tombstone accepted; want the refusal")
	}
	p, ok, err = i.LookupProjection(ctx, f.networkID, refA)
	if err != nil || !ok || !p.Tombstone || p.Revision != revT {
		t.Fatalf("projection changed by a refused revival: %+v ok=%v err=%v", p, ok, err)
	}
}

// TestHostedCatalogImportCapacityRefusesWholePage covers the bounded
// capacity row: an over-limit page is refused before retention (the
// capacity row stays intact, no partial acceptance).
func TestHostedCatalogImportCapacityRefusesWholePage(t *testing.T) {
	f := newHostedGuardFixture(t)
	ctx := t.Context()
	a, ownerA, rootA := newForeignInstallation(t, ctx, "a")
	genesisA := a.Store.Genesis()

	ref1, rev1 := registerForeignEndpoint(t, ctx, a, ownerA, rootA, "Cap1", "one", nil)
	ref2, rev2 := registerForeignEndpoint(t, ctx, a, ownerA, rootA, "Cap2", "two", nil)
	ref3, rev3 := registerForeignEndpoint(t, ctx, a, ownerA, rootA, "Cap3", "three", nil)
	rec1 := exportCurrentRecord(t, ctx, a, ownerA, ref1, rev1)
	rec2 := exportCurrentRecord(t, ctx, a, ownerA, ref2, rev2)
	rec3 := exportCurrentRecord(t, ctx, a, ownerA, ref3, rev3)

	// Row bound: max 2 rows; one imports, then a page holding TWO more is
	// refused whole (1+2 > 2) before any retention of that page.
	i := f.newCatalogImporter(t, []registry.GenesisRecord{genesisA}, nil, 2, 0, time.Second, time.Minute)
	f.queueRecordPages(t, f.buildCatalogPageRecord(t, rec1, genesisA, ref1, rev1, rootA.PublicKey, false))
	if err := i.SyncNetwork(ctx, f.ownerConn, f.networkID); err != nil {
		t.Fatalf("import under capacity: %v", err)
	}
	f.queuePagesFor(t, transport.FabricHostedCatalogPage{
		NetworkID: f.networkID,
		Records: []transport.FabricHostedCatalogRecord{
			f.buildCatalogPageRecord(t, rec2, genesisA, ref2, rev2, rootA.PublicKey, false),
			f.buildCatalogPageRecord(t, rec3, genesisA, ref3, rev3, rootA.PublicKey, false),
		},
		Terminal: true,
	})
	err := i.SyncNetwork(ctx, f.ownerConn, f.networkID)
	if err != ErrHostedCatalogCapacity {
		t.Fatalf("over-limit page error = %v, want %v", err, ErrHostedCatalogCapacity)
	}
	f.assertNotProjected(t, i, ref2)
	f.assertNotProjected(t, i, ref3)
	usage, ok, err := f.d.state.LoadHostedCatalogUsage(ctx, f.networkID)
	if err != nil || !ok || usage.RowsUsed != 1 {
		t.Fatalf("capacity row changed by the refusal: %+v ok=%v err=%v, want rows_used 1", usage, ok, err)
	}

	// Byte bound: the next page would push the byte ledger over its cap;
	// the refusal leaves the row intact (same refuse-before-retention
	// order, byte ledger).
	i2 := f.newCatalogImporter(t, []registry.GenesisRecord{genesisA}, nil, 4096, usage.BytesUsed+1, time.Second, time.Minute)
	f.queueRecordPages(t, f.buildCatalogPageRecord(t, rec2, genesisA, ref2, rev2, rootA.PublicKey, false))
	if err := i2.SyncNetwork(ctx, f.ownerConn, f.networkID); err != ErrHostedCatalogCapacity {
		t.Fatalf("over-byte-cap page error = %v, want %v", err, ErrHostedCatalogCapacity)
	}
	f.assertNotProjected(t, i2, ref2)
	usage2, ok, err := f.d.state.LoadHostedCatalogUsage(ctx, f.networkID)
	if err != nil || !ok || usage2.RowsUsed != 1 || usage2.BytesUsed != usage.BytesUsed {
		t.Fatalf("byte-cap refusal touched the ledger: %+v (before %+v) ok=%v err=%v", usage2, usage, ok, err)
	}
}

// TestHostedCatalogImportEnforcesDeclaredPageBounds covers boundedness at
// the exchange: the daemon declares the byte/record bound in the request,
// and an over-bound SERVED page is a protocol violation (refused, nothing
// retained).
func TestHostedCatalogImportEnforcesDeclaredPageBounds(t *testing.T) {
	f := newHostedGuardFixture(t)
	ctx := t.Context()
	a, ownerA, rootA := newForeignInstallation(t, ctx, "a")
	genesisA := a.Store.Genesis()

	ref1, rev1 := registerForeignEndpoint(t, ctx, a, ownerA, rootA, "Bound1", "one", nil)
	ref2, rev2 := registerForeignEndpoint(t, ctx, a, ownerA, rootA, "Bound2", "two", nil)
	ref3, rev3 := registerForeignEndpoint(t, ctx, a, ownerA, rootA, "Bound3", "three", nil)
	rec1 := exportCurrentRecord(t, ctx, a, ownerA, ref1, rev1)
	rec2 := exportCurrentRecord(t, ctx, a, ownerA, ref2, rev2)
	rec3 := exportCurrentRecord(t, ctx, a, ownerA, ref3, rev3)

	i := f.newCatalogImporter(t, []registry.GenesisRecord{genesisA}, nil, 0, 0, time.Second, time.Minute)

	// Record bound: the request declares 2, the (misbehaving) server serves
	// 3 in one page — the exchange refuses the page.
	r1 := f.buildCatalogPageRecord(t, rec1, genesisA, ref1, rev1, rootA.PublicKey, false)
	r2 := f.buildCatalogPageRecord(t, rec2, genesisA, ref2, rev2, rootA.PublicKey, false)
	r3 := f.buildCatalogPageRecord(t, rec3, genesisA, ref3, rev3, rootA.PublicKey, false)
	f.queuePagesFor(t, transport.FabricHostedCatalogPage{NetworkID: f.networkID, Records: []transport.FabricHostedCatalogRecord{r1, r2, r3}, Terminal: true})
	_, err := f.ownerConn.RequestHostedFabricCatalog(ctx, transport.FabricHostedCatalogRequest{
		RequestID: domain.NewID().String(), NetworkID: f.networkID,
		MaxBytes: transport.FabricHostedCatalogPageMaxBytes, MaxRecords: 2,
	})
	if err != ErrNativeObservationConflict {
		t.Fatalf("over-record-bound page error = %v, want the exchange conflict", err)
	}
	f.assertNotProjected(t, i, ref1)

	// Byte bound: the served page's records exceed the declared bytes.
	f.queuePagesFor(t, transport.FabricHostedCatalogPage{NetworkID: f.networkID, Records: []transport.FabricHostedCatalogRecord{r1}, Terminal: true})
	_, err = f.ownerConn.RequestHostedFabricCatalog(ctx, transport.FabricHostedCatalogRequest{
		RequestID: domain.NewID().String(), NetworkID: f.networkID,
		MaxBytes: 1, MaxRecords: transport.FabricHostedCatalogPageMaxRecords,
	})
	if err != ErrNativeObservationConflict {
		t.Fatalf("over-byte-bound page error = %v, want the exchange conflict", err)
	}
	f.assertNotProjected(t, i, ref1)
}

// TestHostedCatalogImportTriggerBackoffAndRefresh covers the daemon-scoped
// bounded sync trigger: the connection-establishment hook launches a
// non-blocking pass; a failing pass backs off (the immediate re-trigger is
// skipped); after the backoff the pass retries; once the served page is
// valid the pass succeeds and the projection lands.
func TestHostedCatalogImportTriggerBackoffAndRefresh(t *testing.T) {
	f := newHostedGuardFixture(t)
	ctx := t.Context()
	a, ownerA, rootA := newForeignInstallation(t, ctx, "a")
	genesisA := a.Store.Genesis()

	refA, revA := registerForeignEndpoint(t, ctx, a, ownerA, rootA, "Backoff", "backoff", nil)
	recA := exportCurrentRecord(t, ctx, a, ownerA, refA, revA)

	// A tampered page: the sealed body carries an altered signature, so
	// every pass against it fails verification.
	tampered := f.buildCatalogPageRecord(t, recA, genesisA, refA, revA, rootA.PublicKey, false)
	tamperedRec := recA
	tamperedRec.Signature = append([]byte(nil), recA.Signature...) // no aliasing
	tamperedRec.Signature[0] ^= 1
	badBody, err := json.Marshal(HostedCatalogBody{hostedCatalogProtocol, genesisA, tamperedRec})
	if err != nil {
		t.Fatalf("marshal tampered body: %v", err)
	}
	tamperedEnvelope, err := e2ee.Encrypt(badBody, f.key, tampered.AAD)
	if err != nil {
		t.Fatalf("encrypt tampered body: %v", err)
	}
	tampered.Envelope = tamperedEnvelope
	f.queueRecordPages(t, tampered)
	cs := f.catalogServer.Load() // stable for every served-count poll below

	i := f.newCatalogImporter(t, []registry.GenesisRecord{genesisA}, nil, 0, 0, 500*time.Millisecond, time.Second)

	// First trigger: the pass runs and fails (verification).
	f.d.triggerHostedCatalogSync(ctx)
	deadline := time.Now().Add(10 * time.Second)
	for atomic.LoadInt64(&cs.served) < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if atomic.LoadInt64(&cs.served) < 1 {
		t.Fatalf("triggered pass never reached the server")
	}

	// Immediate re-trigger inside the backoff window: skipped.
	f.d.triggerHostedCatalogSync(ctx)
	time.Sleep(150 * time.Millisecond)
	if got := atomic.LoadInt64(&cs.served); got != 1 {
		t.Fatalf("pass retried inside the backoff window: served=%d", got)
	}

	// After the backoff elapses: the pass retries (and fails again on the
	// same tampered page).
	time.Sleep(600 * time.Millisecond)
	f.d.triggerHostedCatalogSync(ctx)
	deadline = time.Now().Add(10 * time.Second)
	for atomic.LoadInt64(&cs.served) < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := atomic.LoadInt64(&cs.served); got != 2 {
		t.Fatalf("pass did not retry after the backoff: served=%d", got)
	}
	f.assertNotProjected(t, i, refA)

	// Once the served page is genuine: the next ELIGIBLE pass succeeds.
	// The second failure set a fresh backoff window, so trigger in a
	// bounded loop until the window elapses and a pass lands.
	f.queueRecordPages(t, f.buildCatalogPageRecord(t, recA, genesisA, refA, revA, rootA.PublicKey, false))
	deadline = time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		f.d.triggerHostedCatalogSync(ctx)
		if _, ok, err := i.LookupProjection(ctx, f.networkID, refA); err == nil && ok {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	f.waitForProjection(t, i, refA, 15*time.Second)
}

// TestHostedCatalogProjectionMonotonicCorners pins the state-layer rule
// table directly (the signed end-to-end flow covers the natural cases;
// these corners — a newer re-publication after a tombstone, a newer
// tombstone after a tombstone — are not producible by a single local
// registry's exporter because a retired ref cannot be re-published
// locally).
func TestHostedCatalogProjectionMonotonicCorners(t *testing.T) {
	d := newTestDaemon(t)
	ctx := t.Context()
	const net = "net-mono"

	mk := func(seq uint64, rev string, retired bool, content string) HostedCatalogRetainedRecord {
		b, _ := json.Marshal(map[string]any{"seq": seq, "content": content})
		return HostedCatalogRetainedRecord{
			Ref: "ref-x", Kind: "endpoint", Revision: fabric.Revision(rev), Sequence: seq,
			Retired: retired, RootNamespace: "ns", RecordJSON: b, DataBytes: len(b),
		}
	}
	retain := func(rec HostedCatalogRetainedRecord) ([]HostedCatalogAcceptedChange, error) {
		return d.state.RetainHostedCatalogPage(ctx, net, 4096, 8<<20, []HostedCatalogRetainedRecord{rec})
	}

	// 1. New live seq1: accepted.
	changes, err := retain(mk(1, "rev1", false, "live-1"))
	if err != nil || !changes[0].Changed || changes[0].ReplacedRevision != "" {
		t.Fatalf("first live: %+v err=%v", changes, err)
	}
	row1, _, _ := d.state.LookupHostedCatalogProjection(ctx, net, "ref-x")

	// 2. Duplicate exact record: idempotent no-op (timestamps untouched).
	changes, err = retain(mk(1, "rev1", false, "live-1"))
	if err != nil || changes[0].Changed {
		t.Fatalf("duplicate exact record: %+v err=%v, want a no-op", changes, err)
	}
	row1b, _, _ := d.state.LookupHostedCatalogProjection(ctx, net, "ref-x")
	if row1.LastSeen != row1b.LastSeen || row1.FirstSeen != row1b.FirstSeen {
		t.Fatalf("duplicate touched the row: %+v vs %+v", row1, row1b)
	}

	// 3. Same sequence, different content: conflict.
	if _, err = retain(mk(1, "rev1x", false, "other")); err != ErrHostedCatalogConflict {
		t.Fatalf("same-sequence different content err = %v, want conflict", err)
	}

	// 4. Older sequence: conflict.
	if _, err = retain(mk(0, "rev0", false, "older")); err != ErrHostedCatalogConflict {
		t.Fatalf("older sequence err = %v, want conflict", err)
	}

	// 5. Tombstone seq2 replacing the live seq1: accepted, carries the
	// replaced revision (the feed delete's ExpectedRevision).
	changes, err = retain(mk(2, "revT", true, "tomb-2"))
	if err != nil || !changes[0].Changed || !changes[0].Retired || changes[0].ReplacedRevision != "rev1" {
		t.Fatalf("tombstone over live: %+v err=%v, want replaced rev1", changes, err)
	}

	// 6. Duplicate tombstone: no-op.
	changes, err = retain(mk(2, "revT", true, "tomb-2"))
	if err != nil || changes[0].Changed {
		t.Fatalf("duplicate tombstone: %+v err=%v, want a no-op", changes, err)
	}

	// 7. A REVIVED OLDER PROFILE after the tombstone (seq1 live): refused.
	if _, err = retain(mk(1, "rev1", false, "live-1")); err != ErrHostedCatalogConflict {
		t.Fatalf("revived old profile after tombstone err = %v, want conflict", err)
	}

	// 8. A NEWER live re-publication after the tombstone (seq3): accepted
	// (the export-side registry is the authority; its sequence proves
	// novelty).
	changes, err = retain(mk(3, "rev3", false, "live-3"))
	if err != nil || !changes[0].Changed || changes[0].Retired || changes[0].ReplacedRevision != "" {
		t.Fatalf("re-publication after tombstone: %+v err=%v", changes, err)
	}

	// 9. Tombstone seq4 over the re-published live seq3: carries rev3.
	changes, err = retain(mk(4, "revT4", true, "tomb-4"))
	if err != nil || !changes[0].Changed || changes[0].ReplacedRevision != "rev3" {
		t.Fatalf("tombstone over re-publication: %+v err=%v, want replaced rev3", changes, err)
	}

	// 10. Tombstone seq5 after tombstone seq4: accepted, the original
	// replaced revision is preserved.
	changes, err = retain(mk(5, "revT5", true, "tomb-5"))
	if err != nil || !changes[0].Changed || changes[0].ReplacedRevision != "rev3" {
		t.Fatalf("tombstone over tombstone: %+v err=%v, want replaced rev3 preserved", changes, err)
	}

	usage, ok, err := d.state.LoadHostedCatalogUsage(ctx, net)
	if err != nil || !ok || usage.RowsUsed != 1 {
		t.Fatalf("capacity ledger = %+v ok=%v err=%v, want exactly one row", usage, ok, err)
	}
}
