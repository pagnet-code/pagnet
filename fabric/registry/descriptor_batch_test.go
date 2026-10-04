package registry

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/search"
)

func batchFixture(t *testing.T) (*Store, fabric.ExecutionContext, string, DescriptorBatchScope, DescriptorBatchLimits) {
	t.Helper()
	s, owner, dir := fixture(t)
	d := endpoint(t, s)
	rev, err := s.Register(t.Context(), owner, fabric.RegistryUpdate{Descriptor: d})
	if err != nil {
		t.Fatal(err)
	}
	scope := DescriptorBatchScope{Endpoint: d.Ref, ExpectedEndpointRevision: rev, BindingID: "local"}
	limits := DefaultDescriptorBatchLimits()
	if _, err = s.InitializeBindingProjection(t.Context(), owner, scope, limits, []byte("owned-protected-config-fixture")); err != nil {
		t.Fatal(err)
	}
	scope.ExpectedProjectionRevision = 1
	return s, owner, dir, scope, limits
}
func batchID(s string) string { sum := sha256.Sum256([]byte(s)); return hex.EncodeToString(sum[:]) }
func batchOffer(t *testing.T, scope DescriptorBatchScope, seed string) (fabric.OfferDescriptor, BindingProjectionRow) {
	t.Helper()
	sum := sha256.Sum256([]byte(seed))
	ref, err := scope.Endpoint.WithOfferID(sum[:])
	if err != nil {
		t.Fatal(err)
	}
	d := fabric.OfferDescriptor{Ref: ref, BindingID: scope.BindingID, Name: seed, Description: "genuine provider offer", InputSchema: json.RawMessage(`{"type":"object","properties":{"n":{"const":9007199254740993123456789}}}`)}
	return d, BindingProjectionRow{Ref: ref, Selector: batchID(seed), Value: []byte("private-selector-proof-" + seed)}
}
func TestDescriptorBatchAtomicSignedReopenAndExactRetry(t *testing.T) {
	s, owner, dir, scope, limits := batchFixture(t)
	d, row := batchOffer(t, scope, "one")
	batch := DescriptorBatch{RequestID: batchID("original"), Limits: limits, PrivateConfig: []byte("owned-protected-config-fixture"), Upserts: []OfferChange{{Descriptor: d}}, Projection: []BindingProjectionRow{row}}
	result, err := s.ApplyDescriptorBatch(t.Context(), owner, scope, batch)
	if err != nil {
		t.Fatal(err)
	}
	if result.ProjectionRevision != 2 || len(result.Rows) != 1 || result.Rows[0].OfferRevision == "" {
		t.Fatal("batch lacks genuine committed offer revision")
	}
	retry, err := s.ApplyDescriptorBatch(t.Context(), owner, scope, batch)
	if err != nil || retry.ProjectionRevision != result.ProjectionRevision || retry.Rows[0].OfferRevision != result.Rows[0].OfferRevision {
		t.Fatal("exact ambiguous retry changed admission", err)
	}
	batch.Projection[0].Value = []byte("substituted")
	if _, err = s.ApplyDescriptorBatch(t.Context(), owner, scope, batch); err == nil {
		t.Fatal("request ID replay content substituted")
	}
	public, err := s.GetOffer(t.Context(), d.Ref, result.Rows[0].OfferRevision)
	if err != nil || !bytes.Contains(public.InputSchema, []byte("9007199254740993123456789")) {
		t.Fatal("genuine signed schema precision lost", err)
	}
	// Search publication and descriptor/map share the same actual transaction.
	var outbox int
	if err = s.db.QueryRow("SELECT count(*) FROM search_outbox WHERE ref=?", d.Ref.String()).Scan(&outbox); err != nil || outbox != 1 {
		t.Fatal("search outbox not atomically published")
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(t.Context(), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	page, err := reopened.ReadBindingProjection(t.Context(), owner, scope, "", 100)
	if err != nil || page.Generation != 2 || len(page.Rows) != 1 || !bytes.Equal(page.PrivateConfig, []byte("owned-protected-config-fixture")) {
		t.Fatal("original projection did not reopen", err)
	}
	if _, _, err = reopened.LookupBindingProjectionByRef(t.Context(), owner, scope, d.Ref); err != nil {
		t.Fatal(err)
	}
}
func TestDescriptorBatchRollbackNoPartialMapLedgerOrOutbox(t *testing.T) {
	s, owner, _, scope, limits := batchFixture(t)
	a, ar := batchOffer(t, scope, "a")
	b, br := batchOffer(t, scope, "b")
	br.Selector = ar.Selector // genuine SQL uniqueness failure after first mutation
	batch := DescriptorBatch{RequestID: batchID("collision"), Limits: limits, PrivateConfig: []byte("owned-protected-config-fixture"), Upserts: []OfferChange{{Descriptor: a}, {Descriptor: b}}, Projection: []BindingProjectionRow{ar, br}}
	beforeSequence, _, _ := head(t.Context(), s.db, s.Namespace())
	var beforeBudget int64
	_ = s.db.QueryRow("SELECT records FROM ledger_budget").Scan(&beforeBudget)
	if _, err := s.ApplyDescriptorBatch(t.Context(), owner, scope, batch); err == nil {
		t.Fatal("selector collision accepted")
	}
	afterSequence, _, _ := head(t.Context(), s.db, s.Namespace())
	if afterSequence != beforeSequence {
		t.Fatal("partial signed mutations survived rollback")
	}
	var afterBudget, count int64
	_ = s.db.QueryRow("SELECT records FROM ledger_budget").Scan(&afterBudget)
	_ = s.db.QueryRow("SELECT count(*) FROM descriptor_projection_rows").Scan(&count)
	if afterBudget != beforeBudget || count != 0 {
		t.Fatal("partial quota/map state survived rollback")
	}
	if _, err := s.GetOffer(t.Context(), a.Ref, ""); err == nil {
		t.Fatal("first partial offer visible")
	}
	var outbox int
	_ = s.db.QueryRow("SELECT count(*) FROM search_outbox WHERE ref IN (?,?)", a.Ref.String(), b.Ref.String()).Scan(&outbox)
	if outbox != 0 {
		t.Fatal("partial search publication")
	}
}
func TestDescriptorProjectionTombstoneIdentityCASAndBudget(t *testing.T) {
	s, owner, dir, scope, limits := batchFixture(t)
	d, row := batchOffer(t, scope, "old")
	config := []byte("owned-protected-config-fixture")
	result, err := s.ApplyDescriptorBatch(t.Context(), owner, scope, DescriptorBatch{RequestID: batchID("create"), Limits: limits, PrivateConfig: config, Upserts: []OfferChange{{Descriptor: d}}, Projection: []BindingProjectionRow{row}})
	if err != nil {
		t.Fatal(err)
	}
	old := result.Rows[0]
	scope.ExpectedProjectionRevision = 2
	retired := old
	retired.OfferRevision = ""
	retired.Retired = true
	if _, err = s.ApplyDescriptorBatch(t.Context(), owner, scope, DescriptorBatch{RequestID: batchID("retire"), Limits: limits, PrivateConfig: config, Retirements: []OfferRetirement{{Ref: old.Ref, ExpectedRevision: old.OfferRevision}}, Projection: []BindingProjectionRow{retired}}); err != nil {
		t.Fatal(err)
	}
	scope.ExpectedProjectionRevision = 3
	if _, _, err = s.LookupBindingProjectionByRef(t.Context(), owner, scope, old.Ref); err == nil {
		t.Fatal("retired projection callable")
	}
	if _, err = s.ApplyDescriptorBatch(t.Context(), owner, scope, DescriptorBatch{RequestID: batchID("resurrect"), Limits: limits, PrivateConfig: config, Upserts: []OfferChange{{Descriptor: d, ExpectedRevision: old.OfferRevision}}, Projection: []BindingProjectionRow{row}}); err == nil {
		t.Fatal("retired reference reactivated")
	}
	fresh, fr := batchOffer(t, scope, "fresh-id")
	fresh.Name = "old"
	fr.Selector = old.Selector
	if _, err = s.ApplyDescriptorBatch(t.Context(), owner, scope, DescriptorBatch{RequestID: batchID("new-incarnation"), Limits: limits, PrivateConfig: config, Upserts: []OfferChange{{Descriptor: fresh}}, Projection: []BindingProjectionRow{fr}}); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	reopened, err := Open(t.Context(), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	var count, total, claimedCount, claimedTotal int64
	_ = reopened.db.QueryRow("SELECT (SELECT count(*) FROM ledger)+(SELECT count(*) FROM descriptor_projection_log),(SELECT COALESCE(sum(length(record)),0) FROM ledger)+(SELECT COALESCE(sum(length(record)),0) FROM descriptor_projection_log)").Scan(&count, &total)
	_ = reopened.db.QueryRow("SELECT records,bytes FROM ledger_budget").Scan(&claimedCount, &claimedTotal)
	if count != claimedCount || total != claimedTotal {
		t.Fatal("private history omitted from shared quota")
	}
}
func TestDescriptorProjectionTamperMissingMarkerAndWrongAuthorityRejected(t *testing.T) {
	for _, mutation := range []string{"UPDATE descriptor_projection_heads SET generation=generation+1", "UPDATE descriptor_projection_rows SET row=x'7b7d'", "UPDATE descriptor_projection_log SET record=x'7b7d'", "DROP TABLE descriptor_projection_format", "UPDATE ledger_budget SET records=records-1"} {
		t.Run(mutation, func(t *testing.T) {
			s, owner, dir, scope, limits := batchFixture(t)
			d, row := batchOffer(t, scope, "original")
			if _, err := s.ApplyDescriptorBatch(t.Context(), owner, scope, DescriptorBatch{RequestID: batchID("signed"), Limits: limits, PrivateConfig: []byte("owned-protected-config-fixture"), Upserts: []OfferChange{{Descriptor: d}}, Projection: []BindingProjectionRow{row}}); err != nil {
				t.Fatal(err)
			}
			if _, err := s.db.Exec(mutation); err != nil {
				t.Fatal(err)
			}
			_ = s.Close()
			if reopened, err := Open(t.Context(), dir); err == nil {
				reopened.Close()
				t.Fatal("unsigned/missing/corrupted projection trusted")
			}
		})
	}
	s, owner, _, scope, limits := batchFixture(t)
	foreign, err := fabric.NewAuthenticatedContext(owner.PrincipalView(), "other-domain", []byte("genuine foreign assertion"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.InitializeBindingProjection(t.Context(), foreign, scope, limits, []byte("config")); err == nil {
		t.Fatal("foreign audience initialized local mapping")
	}
}

func TestDescriptorProjectionPagingFencesConcurrentGenerationAndFiniteRows(t *testing.T) {
	s, owner, _, scope, limits := batchFixture(t)
	config := []byte("owned-protected-config-fixture")
	a, ar := batchOffer(t, scope, "page-a")
	b, br := batchOffer(t, scope, "page-b")
	result, err := s.ApplyDescriptorBatch(t.Context(), owner, scope, DescriptorBatch{RequestID: batchID("pages"), Limits: limits, PrivateConfig: config, Upserts: []OfferChange{{Descriptor: a}, {Descriptor: b}}, Projection: []BindingProjectionRow{ar, br}})
	if err != nil {
		t.Fatal(err)
	}
	first, err := s.ReadBindingProjection(t.Context(), owner, scope, "", 1)
	if err != nil || len(first.Rows) != 1 || first.NextCursor == "" {
		t.Fatal("missing bounded first page", err)
	}
	second, err := s.ReadBindingProjection(t.Context(), owner, scope, first.NextCursor, 1)
	if err != nil || len(second.Rows) != 1 || second.NextCursor != "" || second.Rows[0].Ref == first.Rows[0].Ref {
		t.Fatal("page lost or duplicated mapping", err)
	}
	scope.ExpectedProjectionRevision = result.ProjectionRevision
	updated := result.Rows[0]
	updated.OfferRevision = ""
	updated.Value = []byte("changed protected metadata")
	descriptor, err := s.GetOffer(t.Context(), updated.Ref, result.Rows[0].OfferRevision)
	if err != nil {
		t.Fatal(err)
	}
	descriptor.Revision = ""
	descriptor.Description = "updated genuine provider description"
	if _, err = s.ApplyDescriptorBatch(t.Context(), owner, scope, DescriptorBatch{RequestID: batchID("change-page"), Limits: limits, PrivateConfig: config, Upserts: []OfferChange{{Descriptor: descriptor, ExpectedRevision: result.Rows[0].OfferRevision}}, Projection: []BindingProjectionRow{updated}}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ReadBindingProjection(t.Context(), owner, scope, first.NextCursor, 1); err == nil {
		t.Fatal("stale cursor mixed signed generations")
	}
	if _, err = s.ReadBindingProjection(t.Context(), owner, scope, "", 101); err == nil {
		t.Fatal("unbounded page accepted")
	}
	// Limits are immutable after signed initialization, not silently enlarged.
	limits.MaxRows++
	if _, err = s.ApplyDescriptorBatch(t.Context(), owner, scope, DescriptorBatch{RequestID: batchID("changed-limits"), Limits: limits, PrivateConfig: config}); err == nil {
		t.Fatal("binding budget changed without migration")
	}
}

func TestDescriptorProjectionCoexistsWithNativeAuthorityAndSearchCheckpoint(t *testing.T) {
	s, owner, dir, scope, limits := batchFixture(t)
	key := AuthorityKey{Kind: AuthorityBinding, Endpoint: scope.Endpoint, ID: "coexisting"}
	authorityScope := AuthorityScope{Endpoint: scope.Endpoint, ExpectedRevision: scope.ExpectedEndpointRevision, BindingID: scope.BindingID}
	if err := s.WithNativeAuthority(t.Context(), owner, authorityScope, func(tx *AuthorityTx) error {
		_, err := tx.CAS(key, 0, []byte(`{"native":"original"}`), false)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	d, row := batchOffer(t, scope, "checkpoint")
	if _, err := s.ApplyDescriptorBatch(t.Context(), owner, scope, DescriptorBatch{RequestID: batchID("native-and-catalog"), Limits: limits, PrivateConfig: []byte("owned-protected-config-fixture"), Upserts: []OfferChange{{Descriptor: d}}, Projection: []BindingProjectionRow{row}}); err != nil {
		t.Fatal(err)
	}
	backend, err := search.New(search.Config{})
	if err != nil {
		t.Fatal(err)
	}
	publishPending(t, s, backend)
	checkpoint, err := backend.Checkpoint(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err = s.SaveCheckpoint(t.Context(), checkpoint); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(t.Context(), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if nativeVersion(t, reopened) != 2 {
		t.Fatal("native authority schema downgraded")
	}
	if _, err = reopened.LoadIndex(t.Context(), search.Config{}); err != nil {
		t.Fatal("checkpoint/shared ledger accounting rejected genuine history", err)
	}
	if _, _, err = reopened.LookupBindingProjectionByRef(t.Context(), owner, scope, d.Ref); err != nil {
		t.Fatal(err)
	}
	if err = reopened.WithNativeAuthority(t.Context(), owner, authorityScope, func(tx *AuthorityTx) error {
		record, err := tx.Get(key)
		if err == nil && !bytes.Equal(record.Value, []byte(`{"native":"original"}`)) {
			t.Fatal("native authority changed")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestDescriptorBatchFiniteProjectionCapacityRejectsWholeSnapshot(t *testing.T) {
	s, owner, _ := fixture(t)
	endpointDescriptor := endpoint(t, s)
	rev, err := s.Register(t.Context(), owner, fabric.RegistryUpdate{Descriptor: endpointDescriptor})
	if err != nil {
		t.Fatal(err)
	}
	scope := DescriptorBatchScope{Endpoint: endpointDescriptor.Ref, ExpectedEndpointRevision: rev, BindingID: "local"}
	limits := DefaultDescriptorBatchLimits()
	limits.MaxRows = 1
	config := []byte("protected-finite-config")
	if _, err = s.InitializeBindingProjection(t.Context(), owner, scope, limits, config); err != nil {
		t.Fatal(err)
	}
	scope.ExpectedProjectionRevision = 1
	a, ar := batchOffer(t, scope, "finite-a")
	b, br := batchOffer(t, scope, "finite-b")
	before, _, _ := head(t.Context(), s.db, s.Namespace())
	if _, err = s.ApplyDescriptorBatch(t.Context(), owner, scope, DescriptorBatch{RequestID: batchID("over-capacity"), Limits: limits, PrivateConfig: config, Upserts: []OfferChange{{Descriptor: a}, {Descriptor: b}}, Projection: []BindingProjectionRow{ar, br}}); err == nil {
		t.Fatal("finite row capacity ignored")
	}
	after, _, _ := head(t.Context(), s.db, s.Namespace())
	if before != after {
		t.Fatal("capacity failure partially published snapshot")
	}
	page, err := s.ReadBindingProjection(t.Context(), owner, scope, "", 1)
	if err != nil || len(page.Rows) != 0 || page.Generation != 1 {
		t.Fatal("capacity failure changed private checkpoint", err)
	}
}
