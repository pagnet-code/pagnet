//go:build linux || darwin

package daemon

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/fabric/search"
	"github.com/pagnet-code/pagnet/transport"
)

// TestPrepareHostedCatalogDerivesTombstoneFromSignedRecord pins the flag
// derivation at the publisher: an endpoint.retire record sets the tombstone
// flag; an endpoint.publish record leaves it false. The caller's packet does
// not carry the flag - the daemon always takes it from the signed record it
// binds to the publication.
func TestPrepareHostedCatalogDerivesTombstoneFromSignedRecord(t *testing.T) {
	f := newHostedGuardFixture(t)
	ctx := t.Context()
	a, ownerA, rootA := newForeignInstallation(t, ctx, "a")
	genesisA := a.Store.Genesis()

	refA, revA := registerForeignEndpoint(t, ctx, a, ownerA, rootA, "TombstoneFlag", "flag derivation", nil)
	recLive := exportCurrentRecord(t, ctx, a, ownerA, refA, revA)

	packet := func(revision fabric.Revision) transport.FabricHostedPublication {
		return transport.FabricHostedPublication{
			RequestID:           domain.NewID().String(),
			Ref:                 refA,
			Revision:            revision,
			DomainPublicKey:     rootA.PublicKey,
			NetworkID:           f.networkID,
			InstanceID:          f.profile.Scope.InstanceID,
			OwnershipID:         f.profile.OwnershipID,
			OwnershipGeneration: f.profile.Scope.Generation,
		}
	}

	live, err := f.d.PrepareHostedCatalog(ctx, f.profile, packet(revA), genesisA, recLive)
	if err != nil {
		t.Fatalf("prepare live record: %v", err)
	}
	if live.Tombstone {
		t.Fatal("endpoint.publish record set the tombstone flag")
	}

	revT, err := a.Store.Retire(ctx, ownerA, refA, revA)
	if err != nil {
		t.Fatalf("retire foreign endpoint: %v", err)
	}
	recRetire := exportCurrentRecord(t, ctx, a, ownerA, refA, revT)
	retired, err := f.d.PrepareHostedCatalog(ctx, f.profile, packet(revT), genesisA, recRetire)
	if err != nil {
		t.Fatalf("prepare retire record: %v", err)
	}
	if !retired.Tombstone {
		t.Fatal("endpoint.retire record did not set the tombstone flag")
	}
}

// TestHostedCatalogPublishTombstoneFlagFlowsThroughPublishStoreReadImport is
// the end-to-end pin of the publish wire flag: the REAL publisher
// (PrepareHostedCatalog + PublishHostedCatalog over the real authenticated
// connection) publishes into the fake host, which stores exactly what the
// publish message carried and ECHOES the stored flag into the READ page,
// the behavior the real server will have in Phase C. The importer accepts
// each page and the feed emits the upsert for the live publish and the exact
// delete (not an upsert) for the retire of the same ref.
func TestHostedCatalogPublishTombstoneFlagFlowsThroughPublishStoreReadImport(t *testing.T) {
	f := newHostedGuardFixture(t)
	ctx := t.Context()
	a, ownerA, rootA := newForeignInstallation(t, ctx, "a")
	genesisA := a.Store.Genesis()
	refA, revA := registerForeignEndpoint(t, ctx, a, ownerA, rootA, "FlagFlow", "flag flow", nil)

	idx := newLexicalIndex(t)
	// The feed runs on the importer's goroutine: the captured batches are
	// observed only under this mutex, after the sync below proves the page
	// was fully processed.
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

	publishRecord := func(rec registry.Record, revision fabric.Revision) transport.FabricHostedPublication {
		t.Helper()
		pub := transport.FabricHostedPublication{
			RequestID:           domain.NewID().String(),
			Ref:                 refA,
			Revision:            revision,
			DomainPublicKey:     rootA.PublicKey,
			NetworkID:           f.networkID,
			InstanceID:          f.profile.Scope.InstanceID,
			OwnershipID:         f.profile.OwnershipID,
			OwnershipGeneration: f.profile.Scope.Generation,
		}
		prepared, err := f.d.PrepareHostedCatalog(ctx, f.profile, pub, genesisA, rec)
		if err != nil {
			t.Fatalf("prepare %s: %v", rec.Frame.ActionKind, err)
		}
		if err := f.d.PublishHostedCatalog(ctx, f.profile, prepared); err != nil {
			t.Fatalf("publish %s: %v", rec.Frame.ActionKind, err)
		}
		return prepared
	}

	f.queueEchoPublishPages(t)

	// 1. The live publish through the real publisher: the fake stores the
	// packet and echoes the stored flag (false) into the READ page; the
	// importer accepts the page and the feed emits the upsert.
	live := publishRecord(exportCurrentRecord(t, ctx, a, ownerA, refA, revA), revA)
	if live.Tombstone {
		t.Fatal("the live publish carried the tombstone flag")
	}
	if err := i.SyncNetwork(ctx, f.ownerConn, f.networkID); err != nil {
		t.Fatalf("import live publish: %v", err)
	}
	f.waitForProjection(t, i, refA, 15*time.Second)
	feedMu.Lock()
	batches := append([]search.Batch(nil), fedBatches...)
	batchErr := feedErr
	feedMu.Unlock()
	if batchErr != nil {
		t.Fatalf("feed: %v", batchErr)
	}
	if len(batches) != 1 || len(batches[0].Upserts) != 1 || len(batches[0].Deletes) != 0 {
		t.Fatalf("live fed batches = %+v, want exactly one upsert", batches)
	}
	if d, ok, _ := idx.Document(ctx, refA, revA); !ok || d.Name != "FlagFlow" {
		t.Fatalf("index after live publish = ok=%v doc=%+v, want the imported descriptor", ok, d)
	}

	// 2. The retire publish of the same ref through the same real
	// publisher: the stored flag (true) rides the READ page; the importer
	// accepts the page and the feed emits the exact delete (not an
	// upsert); the projection retains the tombstone.
	revT, err := a.Store.Retire(ctx, ownerA, refA, revA)
	if err != nil {
		t.Fatalf("retire foreign endpoint: %v", err)
	}
	retired := publishRecord(exportCurrentRecord(t, ctx, a, ownerA, refA, revT), revT)
	if !retired.Tombstone {
		t.Fatal("the retire publish did not carry the tombstone flag")
	}
	feedMu.Lock()
	fedBatches = nil
	feedMu.Unlock()
	if err := i.SyncNetwork(ctx, f.ownerConn, f.networkID); err != nil {
		t.Fatalf("import retire publish: %v", err)
	}
	feedMu.Lock()
	batches = append([]search.Batch(nil), fedBatches...)
	batchErr = feedErr
	feedMu.Unlock()
	if batchErr != nil {
		t.Fatalf("feed: %v", batchErr)
	}
	if len(batches) != 1 || len(batches[0].Upserts) != 0 || len(batches[0].Deletes) != 1 || batches[0].Deletes[0].Ref != refA || batches[0].Deletes[0].ExpectedRevision != revA {
		t.Fatalf("retire fed batches = %+v, want exactly one delete for %s @ %s", batches, refA, revA)
	}
	if _, ok, _ := idx.Document(ctx, refA, revA); ok {
		t.Fatal("index still serves the retired ref after the feed delete")
	}
	p, ok, err := i.LookupProjection(ctx, f.networkID, refA)
	if err != nil || !ok || !p.Tombstone || p.Revision != revT {
		t.Fatalf("projection after retire = %+v ok=%v err=%v, want the tombstone retained", p, ok, err)
	}
}
