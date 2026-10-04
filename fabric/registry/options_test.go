package registry

import (
	"context"
	"encoding/json"
	"github.com/pagnet-code/pagnet/fabric"
	"math"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigurableLimitsAreAdmissionNotProtocolCapacity(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "custom")
	options := DefaultOptions()
	options.Limits.MaxRecords = 10000000
	options.Limits.MaxLedgerBytes = 128 << 20
	options.Limits.MaxDatabaseBytes = 512 << 20
	options.Limits.MaxPayloadBytes = 2 << 20
	s, e := BootstrapWithOptions(ctx, dir, testOwner, options)
	if e != nil {
		t.Fatal(e)
	}
	c, _ := fabric.NewAuthenticatedContext(testOwner, s.Namespace(), []byte("trusted"))
	d := endpoint(t, s)
	if _, e = s.Register(ctx, c, fabric.RegistryUpdate{Descriptor: d}); e != nil {
		t.Fatal(e)
	}
	ref, _ := d.Ref.WithOfferID(make([]byte, 32))
	offer := fabric.OfferDescriptor{Ref: ref, Name: "Large schema", BindingID: "local", InputSchema: json.RawMessage(`{"type":"string","description":"` + strings.Repeat("a", 1100000) + `"}`)}
	rev, e := s.PutOffer(ctx, c, offer, "")
	if e != nil {
		t.Fatal("selected bound not used", e)
	}
	s.Close()
	if _, e = Open(ctx, dir); e == nil {
		t.Fatal("smaller default readback silently accepted oversized retained schema")
	}
	s, e = OpenWithOptions(ctx, dir, options)
	if e != nil {
		t.Fatal("selected limits cannot reopen retained record", e)
	}
	defer s.Close()
	got, e := s.GetOffer(ctx, ref, rev)
	if e != nil || len(got.InputSchema) != len(offer.InputSchema) {
		t.Fatal("large exact descriptor readback", e)
	}
}
func TestInvalidOptionsNeverInstallIdentity(t *testing.T) {
	for _, modify := range []func(*Options){func(o *Options) { o.Limits.MaxRecords = 0 }, func(o *Options) { o.Limits.MaxRecords = math.MaxUint64 }, func(o *Options) { o.Limits.MaxLedgerBytes = 0 }, func(o *Options) { o.Limits.MaxPayloadBytes = math.MaxInt }, func(o *Options) { o.Limits.MaxDatabaseBytes = 1024 }} {
		o := DefaultOptions()
		modify(&o)
		dir := filepath.Join(t.TempDir(), "invalid")
		if _, e := BootstrapWithOptions(context.Background(), dir, testOwner, o); e == nil {
			t.Fatal("invalid storage capacity accepted")
		}
	}
}
func TestCustomRecordQuotaBackpressureAndExpandedReopen(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "quota")
	options := DefaultOptions()
	options.Limits.MaxRecords = 1
	s, e := BootstrapWithOptions(ctx, dir, testOwner, options)
	if e != nil {
		t.Fatal(e)
	}
	c, _ := fabric.NewAuthenticatedContext(testOwner, s.Namespace(), []byte("trusted"))
	d := endpoint(t, s)
	rev, e := s.Register(ctx, c, fabric.RegistryUpdate{Descriptor: d})
	if e != nil {
		t.Fatal(e)
	}
	d.Name = "Edited"
	if _, e = s.Update(ctx, c, fabric.RegistryUpdate{Descriptor: d, ExpectedRevision: rev}); e == nil {
		t.Fatal("configured full quota accepted")
	}
	s.Close()
	options.Limits.MaxRecords = 2
	s, e = OpenWithOptions(ctx, dir, options)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if _, e = s.Update(ctx, c, fabric.RegistryUpdate{Descriptor: d, ExpectedRevision: rev}); e != nil {
		t.Fatal("capacity cannot be expanded", e)
	}
}
