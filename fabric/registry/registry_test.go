package registry

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/search"
)

var testOwner = fabric.Principal{Ref: "spiffe://local/owner", Kind: "local.owner", Issuer: "local.test"}

func fixture(t *testing.T) (*Store, fabric.ExecutionContext, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "domain")
	s, e := Bootstrap(context.Background(), dir, testOwner)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	c, e := fabric.NewAuthenticatedContext(testOwner, s.Namespace(), []byte("trusted original request"))
	if e != nil {
		t.Fatal(e)
	}
	return s, c, dir
}
func endpoint(t *testing.T, s *Store) fabric.EndpointDescriptor {
	t.Helper()
	ref, e := fabric.NewEndpointRef(s.identity.PublicKey)
	if e != nil {
		t.Fatal(e)
	}
	return fabric.EndpointDescriptor{Ref: ref, Kind: "agent.local", Name: "Research", Description: "Private team research", Bindings: []fabric.BindingSummary{{ID: "local", Protocol: "local.native", Version: "1"}}}
}
func code(t *testing.T, e error, want fabric.ErrorCode) {
	t.Helper()
	var typed *fabric.Error
	if !errors.As(e, &typed) || typed.Code != want {
		t.Fatalf("expected %s, got %v", want, e)
	}
}
func TestBootstrapPrivateReadbackNoReplacement(t *testing.T) {
	s, _, dir := fixture(t)
	gen := s.Genesis()
	namespace := s.Namespace()
	if _, e := Open(context.Background(), dir); e == nil {
		t.Fatal("second live writer")
	}
	if _, e := Bootstrap(context.Background(), dir, testOwner); e == nil {
		t.Fatal("second bootstrap")
	}
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	opened, e := Open(context.Background(), dir)
	if e != nil {
		t.Fatal(e)
	}
	if opened.Namespace() != namespace || string(opened.Genesis().Body) != string(gen.Body) {
		t.Fatal("identity changed")
	}
	opened.Close()
	if e = os.Remove(filepath.Join(dir, "genesis.key")); e != nil {
		t.Fatal(e)
	}
	if _, e = Open(context.Background(), dir); e == nil {
		t.Fatal("missing key replaced")
	}
	if _, e = Bootstrap(context.Background(), dir, testOwner); e == nil {
		t.Fatal("partial existing identity regenerated")
	}
	if _, e = os.Stat(filepath.Join(dir, "genesis.key")); !os.IsNotExist(e) {
		t.Fatal("replacement file created")
	}
}
func TestRegistryCASOwnershipRenameAndPermanentTombstone(t *testing.T) {
	s, c, dir := fixture(t)
	ctx := context.Background()
	d := endpoint(t, s)
	var zero fabric.ExecutionContext
	if _, e := s.Register(ctx, zero, fabric.RegistryUpdate{Descriptor: d}); e == nil {
		t.Fatal("forged empty context")
	}
	foreign := testOwner
	foreign.Issuer = "different-issuer"
	forged, _ := fabric.NewAuthenticatedContext(foreign, s.Namespace(), []byte("trusted"))
	if _, e := s.Register(ctx, forged, fabric.RegistryUpdate{Descriptor: d}); e == nil {
		t.Fatal("foreign issuer")
	}
	wrongAudience, _ := fabric.NewAuthenticatedContext(testOwner, "another-domain", []byte("trusted"))
	if _, e := s.Register(ctx, wrongAudience, fabric.RegistryUpdate{Descriptor: d}); e == nil {
		t.Fatal("wrong audience")
	}
	rev, e := s.Register(ctx, c, fabric.RegistryUpdate{Descriptor: d})
	if e != nil {
		t.Fatal(e)
	}
	retry, e := s.Register(ctx, c, fabric.RegistryUpdate{Descriptor: d})
	if e != nil || retry != rev {
		t.Fatal("exact ambiguous retry", e)
	}
	read, e := s.GetEndpoint(ctx, d.Ref, rev)
	if e != nil || read.Name != d.Name {
		t.Fatal(e)
	}
	d.Name = "Renamed"
	next, e := s.Update(ctx, c, fabric.RegistryUpdate{Descriptor: d, ExpectedRevision: rev})
	if e != nil || next == rev {
		t.Fatal(e)
	}
	if _, e = s.GetEndpoint(ctx, d.Ref, rev); e == nil {
		t.Fatal("stale read accepted")
	}
	if _, e = s.Update(ctx, c, fabric.RegistryUpdate{Descriptor: d, ExpectedRevision: rev}); e != nil {
		t.Fatal("exact update retry", e)
	}
	changed := d
	changed.Name = "Fork"
	_, e = s.Update(ctx, c, fabric.RegistryUpdate{Descriptor: changed, ExpectedRevision: rev})
	code(t, e, fabric.CodeStaleReference)
	tomb, e := s.Retire(ctx, c, d.Ref, next)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.GetEndpoint(ctx, d.Ref, ""); e == nil {
		t.Fatal("retired read")
	}
	if _, e = s.Register(ctx, c, fabric.RegistryUpdate{Descriptor: d}); e == nil {
		t.Fatal("retired identity resurrected")
	}
	if retry, e = s.Retire(ctx, c, d.Ref, next); e != nil || retry != tomb {
		t.Fatal("retire retry", e)
	}
	s.Close()
	s, e = Open(ctx, dir)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if _, e = s.GetEndpoint(ctx, d.Ref, ""); e == nil {
		t.Fatal("restart revived tombstone")
	}
}
func TestConcurrentCASCommitsExactlyOne(t *testing.T) {
	s, c, _ := fixture(t)
	ctx := context.Background()
	d := endpoint(t, s)
	rev, e := s.Register(ctx, c, fabric.RegistryUpdate{Descriptor: d})
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	success := 0
	for i := range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			copy := d
			copy.Description = string(rune('a' + i))
			_, e := s.Update(ctx, c, fabric.RegistryUpdate{Descriptor: copy, ExpectedRevision: rev})
			if e == nil {
				mu.Lock()
				success++
				mu.Unlock()
			} else {
				code(t, e, fabric.CodeStaleReference)
			}
		}()
	}
	wg.Wait()
	if success != 1 {
		t.Fatalf("CAS winners %d", success)
	}
	records, e := s.Records(ctx, s.Namespace(), 0, 100)
	if e != nil || len(records) != 2 {
		t.Fatal("partial or duplicate history", e)
	}
}
func TestOffersSeparateSchemasRevisionBoundPagination(t *testing.T) {
	s, c, _ := fixture(t)
	ctx := context.Background()
	d := endpoint(t, s)
	rev, e := s.Register(ctx, c, fabric.RegistryUpdate{Descriptor: d})
	if e != nil {
		t.Fatal(e)
	}
	offers := make([]fabric.OfferDescriptor, 3)
	for i := range offers {
		raw := make([]byte, 32)
		raw[0] = byte(i + 1)
		ref, e := d.Ref.WithOfferID(raw)
		if e != nil {
			t.Fatal(e)
		}
		offers[i] = fabric.OfferDescriptor{Ref: ref, Name: "Question", Description: "Typed inquiry", InputSchema: json.RawMessage(`{"type":"object"}`), BindingID: "local"}
		if _, e = s.PutOffer(ctx, c, offers[i], ""); e != nil {
			t.Fatal(e)
		}
	}
	page, cursor, e := s.ListOffers(ctx, d.Ref, rev, "", 2)
	if e != nil || len(page) != 2 || cursor == "" {
		t.Fatal("first page", e)
	}
	page2, cursor2, e := s.ListOffers(ctx, d.Ref, rev, cursor, 2)
	if e != nil || len(page2) != 1 || cursor2 != "" {
		t.Fatal("second page", e)
	}
	detail, e := s.GetOffer(ctx, page2[0].Ref, page2[0].Revision)
	if e != nil || string(detail.InputSchema) != `{"type":"object"}` {
		t.Fatal("exact offer detail", e)
	}
	offers[0].Name = "Changed"
	current, e := s.GetOffer(ctx, offers[0].Ref, "")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.PutOffer(ctx, c, offers[0], current.Revision); e != nil {
		t.Fatal(e)
	}
	_, _, e = s.ListOffers(ctx, d.Ref, rev, cursor, 2)
	code(t, e, fabric.CodeStaleReference)
	if _, e = s.Retire(ctx, c, d.Ref, rev); e != nil {
		t.Fatal(e)
	}
	if _, e = s.GetOffer(ctx, offers[1].Ref, ""); e == nil {
		t.Fatal("orphan offer callable after parent retirement")
	}
}
func TestImportExplicitPinExactSignatureAtomicForkAndTombstone(t *testing.T) {
	source, sc, _ := fixture(t)
	dest, dc, dir := fixture(t)
	ctx := context.Background()
	d := endpoint(t, source)
	rev, e := source.Register(ctx, sc, fabric.RegistryUpdate{Descriptor: d})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = source.Retire(ctx, sc, d.Ref, rev); e != nil {
		t.Fatal(e)
	}
	records, e := source.Records(ctx, source.Namespace(), 0, 100)
	if e != nil {
		t.Fatal(e)
	}
	if e = dest.Import(ctx, dc, records); e == nil {
		t.Fatal("untrusted self-signed root imported")
	}
	if e = dest.PinForeign(ctx, dc, source.Namespace(), source.Genesis()); e != nil {
		t.Fatal(e)
	}
	tampered := append([]Record(nil), records...)
	tampered[1].Signature = append([]byte(nil), tampered[1].Signature...)
	tampered[1].Signature[0] ^= 1
	if e = dest.Import(ctx, dc, tampered); e == nil {
		t.Fatal("bad signature")
	}
	if _, e = dest.GetEndpoint(ctx, d.Ref, ""); e == nil {
		t.Fatal("partial imported transaction")
	}
	if e = dest.Import(ctx, dc, records); e != nil {
		t.Fatal(e)
	}
	if e = dest.Import(ctx, dc, records); e != nil {
		t.Fatal("exact import retry", e)
	}
	if _, e = dest.Register(ctx, dc, fabric.RegistryUpdate{Descriptor: d}); e == nil {
		t.Fatal("foreign authority made writable")
	}
	if _, e = dest.GetEndpoint(ctx, d.Ref, ""); e == nil {
		t.Fatal("foreign tombstone revived")
	}
	dest.Close()
	dest, e = Open(ctx, dir)
	if e != nil {
		t.Fatal(e)
	}
	defer dest.Close()
	if e = dest.Import(ctx, dc, records[:1]); e != nil {
		t.Fatal("old exact history receipt", e)
	}
	if _, e = dest.GetEndpoint(ctx, d.Ref, ""); e == nil {
		t.Fatal("historical import resurrected tombstone")
	}
}
func TestRealSignedForkRejected(t *testing.T) {
	source, sc, _ := fixture(t)
	dest, dc, _ := fixture(t)
	ctx := context.Background()
	d := endpoint(t, source)
	if _, e := source.Register(ctx, sc, fabric.RegistryUpdate{Descriptor: d}); e != nil {
		t.Fatal(e)
	}
	records, _ := source.Records(ctx, source.Namespace(), 0, 1)
	if e := dest.PinForeign(ctx, dc, source.Namespace(), source.Genesis()); e != nil {
		t.Fatal(e)
	}
	if e := dest.Import(ctx, dc, records); e != nil {
		t.Fatal(e)
	}
	r := records[0]
	different := d
	different.Name = "Fork"
	unsigned, _ := json.Marshal(different)
	m := mutationDigest(r.Frame.ActionKind, d.Ref, "", unsigned)
	r.Frame.NewRevision = newRevision(1, [32]byte{}, m)
	different.Revision = r.Frame.NewRevision
	r.Payload, _ = json.Marshal(different)
	r.Frame.PayloadDigest = sha256ForTest(r.Payload)
	wire, _ := r.Frame.SigningBytes()
	r.Signature = ed25519.Sign(source.key, wire)
	if e := dest.Import(ctx, dc, []Record{r}); e == nil {
		t.Fatal("validly signed fork accepted")
	}
}
func sha256ForTest(b []byte) [32]byte { return digestForTest(b) }
func TestTransactionFailureLeavesNoHeadProjectionOrQuota(t *testing.T) {
	s, c, _ := fixture(t)
	ctx := context.Background()
	d := endpoint(t, s)
	if _, e := s.db.Exec(`CREATE TRIGGER reject_outbox BEFORE INSERT ON search_outbox BEGIN SELECT RAISE(ABORT,'fixture rejects commit'); END;`); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Register(ctx, c, fabric.RegistryUpdate{Descriptor: d}); e == nil {
		t.Fatal("expected abort")
	}
	var records, bytes int
	if e := s.db.QueryRow("SELECT records,bytes FROM ledger_budget").Scan(&records, &bytes); e != nil || records != 0 || bytes != 0 {
		t.Fatal("quota leaked", e)
	}
	var n int
	if e := s.db.QueryRow("SELECT COUNT(*) FROM objects").Scan(&n); e != nil || n != 0 {
		t.Fatal("projection leaked", e)
	}
	if _, e := s.db.Exec("DROP TRIGGER reject_outbox"); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Register(ctx, c, fabric.RegistryUpdate{Descriptor: d}); e != nil {
		t.Fatal("retry after rollback", e)
	}
}
func TestIndexPublicationCrashGapAndExactWatermark(t *testing.T) {
	s, c, dir := fixture(t)
	ctx := context.Background()
	d := endpoint(t, s)
	if _, e := s.Register(ctx, c, fabric.RegistryUpdate{Descriptor: d}); e != nil {
		t.Fatal(e)
	}
	backend, e := search.New(search.Config{})
	if e != nil {
		t.Fatal(e)
	}
	batch, e := s.PendingIndex(ctx, 32)
	if e != nil {
		t.Fatal(e)
	}
	prepared, e := backend.Prepare(ctx, batch)
	if e != nil {
		t.Fatal(e)
	}
	record := prepared.Record()
	forged := record
	forged.Batch.Upserts = append([]fabric.SearchDocument(nil), record.Batch.Upserts...)
	forged.Batch.Upserts[0].Name = "Injected"
	forged.SHA256 = indexHashForTest(forged)
	if e = s.CommitIndex(ctx, forged); e == nil {
		t.Fatal("forged search delta")
	}
	if e = s.CommitIndex(ctx, record); e != nil {
		t.Fatal(e)
	}
	if e = s.CommitIndex(ctx, record); e != nil {
		t.Fatal("index commit exact retry", e)
	}
	s.Close()
	s, e = Open(ctx, dir)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	commits, e := s.IndexRecords(ctx, 0, 32)
	if e != nil || len(commits) != 1 {
		t.Fatal(e)
	}
	restored, e := search.New(search.Config{})
	if e != nil {
		t.Fatal(e)
	}
	if e = restored.Restore(ctx, commits[0]); e != nil {
		t.Fatal(e)
	}
	result, e := restored.Search(ctx, fabric.DiscoverRequest{Query: "research", Limit: 10})
	if e != nil || len(result.Candidates) != 1 || result.Candidates[0].Document.Ref != d.Ref {
		t.Fatal("crash gap recovery", e)
	}
	current, e := s.GetEndpoint(ctx, d.Ref, "")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Retire(ctx, c, d.Ref, current.Revision); e != nil {
		t.Fatal(e)
	}
	batch, e = s.PendingIndex(ctx, 32)
	if e != nil {
		t.Fatal(e)
	}
	prepared, e = restored.Prepare(ctx, batch)
	if e != nil {
		t.Fatal(e)
	}
	if e = restored.Publish(ctx, prepared, s.CommitIndex); e != nil {
		t.Fatal(e)
	}
	result, e = restored.Search(ctx, fabric.DiscoverRequest{Query: "research", Limit: 10})
	if e != nil || len(result.Candidates) != 0 {
		t.Fatal("retired index entry", e)
	}
}
func TestMalformedKeyLedgerAndGenesisFailClosed(t *testing.T) {
	for _, mutation := range []string{"key", "genesis", "projection", "budget", "head"} {
		t.Run(mutation, func(t *testing.T) {
			s, c, dir := fixture(t)
			d := endpoint(t, s)
			if _, e := s.Register(context.Background(), c, fabric.RegistryUpdate{Descriptor: d}); e != nil {
				t.Fatal(e)
			}
			switch mutation {
			case "key":
				_, key, _ := ed25519.GenerateKey(rand.Reader)
				if e := os.WriteFile(filepath.Join(dir, "genesis.key"), key, 0600); e != nil {
					t.Fatal(e)
				}
			case "genesis":
				s.db.Exec("UPDATE identity SET genesis='{}'")
			case "projection":
				s.db.Exec("UPDATE objects SET revision='forged'")
			case "budget":
				s.db.Exec("UPDATE ledger_budget SET records=0")
			case "head":
				s.db.Exec("UPDATE ledger SET head=zeroblob(32)")
			}
			s.Close()
			if opened, e := Open(context.Background(), dir); e == nil {
				opened.Close()
				t.Fatal("corruption accepted")
			}
		})
	}
}

func TestOfferRetirementAndBindingRemovalAreExplicit(t *testing.T) {
	s, c, _ := fixture(t)
	ctx := context.Background()
	d := endpoint(t, s)
	rev, e := s.Register(ctx, c, fabric.RegistryUpdate{Descriptor: d})
	if e != nil {
		t.Fatal(e)
	}
	id := make([]byte, 32)
	id[0] = 1
	ref, _ := d.Ref.WithOfferID(id)
	offer := fabric.OfferDescriptor{Ref: ref, Name: "Ask", BindingID: "local"}
	offerRev, e := s.PutOffer(ctx, c, offer, "")
	if e != nil {
		t.Fatal(e)
	}
	changed := d
	changed.Bindings = nil
	if _, e = s.Update(ctx, c, fabric.RegistryUpdate{Descriptor: changed, ExpectedRevision: rev}); e == nil {
		t.Fatal("dependent binding silently removed")
	}
	if _, e = s.RetireOffer(ctx, c, ref, offerRev); e != nil {
		t.Fatal(e)
	}
	if _, e = s.PutOffer(ctx, c, offer, ""); e == nil {
		t.Fatal("tombstoned offer revived")
	}
	if _, e = s.Update(ctx, c, fabric.RegistryUpdate{Descriptor: changed, ExpectedRevision: rev}); e != nil {
		t.Fatal("explicit retired offer blocks binding update", e)
	}
}
func TestQuotaRejectDoesNotAllocateRevisionOrOutbox(t *testing.T) {
	s, c, _ := fixture(t)
	ctx := context.Background()
	d := endpoint(t, s)
	if _, e := s.db.Exec("UPDATE ledger_budget SET records=?", maxRecords); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Register(ctx, c, fabric.RegistryUpdate{Descriptor: d}); e == nil {
		t.Fatal("full identity ledger accepted")
	}
	var n int
	if e := s.db.QueryRow("SELECT COUNT(*) FROM ledger").Scan(&n); e != nil || n != 0 {
		t.Fatal("ledger leaked", e)
	}
	if e := s.db.QueryRow("SELECT COUNT(*) FROM search_outbox").Scan(&n); e != nil || n != 0 {
		t.Fatal("outbox leaked", e)
	}
	if _, e := s.db.Exec("UPDATE ledger_budget SET records=0"); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Register(ctx, c, fabric.RegistryUpdate{Descriptor: d}); e != nil {
		t.Fatal("quota fixture clean retry", e)
	}
}

func TestAcceptedRegistrySourceAlwaysFitsCompactIndexBudget(t *testing.T) {
	s, c, _ := fixture(t)
	ctx := context.Background()
	d := endpoint(t, s)
	if _, e := s.Register(ctx, c, fabric.RegistryUpdate{Descriptor: d}); e != nil {
		t.Fatal(e)
	}
	ref, _ := d.Ref.WithOfferID(make([]byte, 32))
	offer := fabric.OfferDescriptor{Ref: ref, Name: "Encoded tags", BindingID: "local"}
	for range 32 {
		offer.Tags = append(offer.Tags, strings.Repeat("<", 256))
	}
	if _, e := s.PutOffer(ctx, c, offer, ""); e == nil {
		t.Fatal("accepted source strands its discovery outbox")
	}
	records, e := s.Records(ctx, s.Namespace(), 0, 100)
	if e != nil || len(records) != 1 {
		t.Fatal("oversize index source committed signed history", e)
	}
	offer.Tags = []string{"typed"}
	if _, e = s.PutOffer(ctx, c, offer, ""); e != nil {
		t.Fatal("failed admission leaked identity", e)
	}
	b, _ := search.New(search.Config{})
	publishPending(t, s, b)
}
func TestSignedInvalidForeignScopeAndDuplicateKeysRejectBeforeMutation(t *testing.T) {
	source, sc, _ := fixture(t)
	dest, dc, _ := fixture(t)
	ctx := context.Background()
	d := endpoint(t, source)
	if _, e := source.Register(ctx, sc, fabric.RegistryUpdate{Descriptor: d}); e != nil {
		t.Fatal(e)
	}
	records, _ := source.Records(ctx, source.Namespace(), 0, 1)
	if e := dest.PinForeign(ctx, dc, source.Namespace(), source.Genesis()); e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*Record){func(r *Record) { r.Frame.IssuerKeyRevision = 2 }, func(r *Record) { r.Frame.AudienceDomain = dest.Namespace() }, func(r *Record) {
		r.Payload = json.RawMessage(`{"name":"a","name":"b"}`)
		r.Frame.PayloadDigest = digestForTest(r.Payload)
	}} {
		r := records[0]
		change(&r)
		wire, e := r.Frame.SigningBytes()
		if e != nil {
			t.Fatal(e)
		}
		r.Signature = ed25519.Sign(source.key, wire)
		if e = dest.Import(ctx, dc, []Record{r}); e == nil {
			t.Fatal("authentic signer bypassed current source scope/grammar")
		}
		if _, e = dest.GetEndpoint(ctx, d.Ref, ""); e == nil {
			t.Fatal("rejected source mutated registry")
		}
	}
}
