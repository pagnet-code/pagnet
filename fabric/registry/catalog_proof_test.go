package registry

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/pagnet-code/pagnet/fabric"
)

func TestCatalogExactSelectiveProofAndIndexedLookup(t *testing.T) {
	ctx := context.Background()
	s, owner, dir := fixture(t)
	d := endpoint(t, s)
	rev, err := s.Register(ctx, owner, fabric.RegistryUpdate{Descriptor: d})
	if err != nil {
		t.Fatal(err)
	}
	secret := endpoint(t, s)
	secret.Description = "Other network's secret payroll"
	if _, err = s.Register(ctx, owner, fabric.RegistryUpdate{Descriptor: secret}); err != nil {
		t.Fatal(err)
	}
	var forged fabric.ExecutionContext
	if _, err = NewCatalogExporter(ctx, s, forged); err == nil {
		t.Fatal("unauthenticated index installation")
	}
	x, err := NewCatalogExporter(ctx, s, owner)
	if err != nil {
		t.Fatal(err)
	}
	r, err := x.Exact(ctx, d.Ref, rev)
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifyCatalogRecord(s.Genesis(), r, d.Ref, rev); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(r)
	if strings.Contains(string(raw), secret.Description) || strings.Contains(string(raw), secret.Ref.String()) {
		t.Fatal("selective export leaked another descriptor")
	}
	rows, err := s.db.QueryContext(ctx, "EXPLAIN QUERY PLAN "+catalogProofQuery, s.Namespace(), d.Ref.String(), string(rev))
	if err != nil {
		t.Fatal(err)
	}
	used := false
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err = rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(detail, "SCAN") {
			t.Fatal("catalog lookup scans history", detail)
		}
		used = used || strings.Contains(detail, "SEARCH ledger USING INDEX catalog_exact_record")
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	rows.Close()
	if !used {
		t.Fatal("catalog lookup does not use its exact indexed key")
	}
	bad := r
	bad.Payload = append([]byte(nil), r.Payload...)
	bad.Payload[len(bad.Payload)-1] ^= 1
	if VerifyCatalogRecord(s.Genesis(), bad, d.Ref, rev) == nil {
		t.Fatal("forged descriptor accepted")
	}
	if VerifyCatalogRecord(s.Genesis(), r, secret.Ref, rev) == nil {
		t.Fatal("changed outer reference accepted")
	}
	d.Name = "Renamed"
	next, err := s.Update(ctx, owner, fabric.RegistryUpdate{Descriptor: d, ExpectedRevision: rev})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = x.Exact(ctx, d.Ref, rev); err == nil {
		t.Fatal("stale descriptor exported")
	}
	if _, err = x.Exact(ctx, d.Ref, ""); err == nil {
		t.Fatal("implicit latest revision")
	}
	tomb, err := s.Retire(ctx, owner, d.Ref, next)
	if err != nil {
		t.Fatal(err)
	}
	r, err = x.Exact(ctx, d.Ref, tomb)
	if err != nil || r.Frame.ActionKind != "endpoint.retire" {
		t.Fatal("missing exact signed retirement", err)
	}
	if err = VerifyCatalogRecord(s.Genesis(), r, d.Ref, tomb); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = x.Exact(ctx, d.Ref, tomb); err == nil {
		t.Fatal("closed authority export")
	}
	opened, err := Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	// Index survives restart without a hidden install in the read path.
	x = &CatalogExporter{store: opened}
	if _, err = x.Exact(ctx, d.Ref, tomb); err != nil {
		t.Fatal(err)
	}
}
