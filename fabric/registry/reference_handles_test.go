package registry

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/pagnet-code/pagnet/fabric"
)

func allocateHandle(t *testing.T, s *Store, c fabric.ExecutionContext, ref fabric.EndpointRef, label string) fabric.ReferenceHandleView {
	t.Helper()
	v, e := s.AllocateReferenceHandle(context.Background(), c, ref, label)
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func registerEndpoint(t *testing.T, s *Store, c fabric.ExecutionContext) (fabric.EndpointDescriptor, fabric.Revision) {
	t.Helper()
	d := endpoint(t, s)
	rev, e := s.Register(context.Background(), c, fabric.RegistryUpdate{Descriptor: d})
	if e != nil {
		t.Fatal(e)
	}
	return d, rev
}

// Unique allocation: slots are monotonic, each handle binds exactly one
// canonical reference plus its exact revision, and re-allocating the same
// endpoint is idempotent (one slot per endpoint, permanently).
func TestReferenceHandleUniqueAllocationAndIdempotency(t *testing.T) {
	s, c, _ := fixture(t)
	ctx := context.Background()
	// Before any allocation the handle state is not adopted: explicit unknown.
	_, e := s.ResolveReferenceHandle(ctx, "#1.r1")
	if e == nil {
		t.Fatal("resolved a handle before any allocation")
	}
	code(t, e, fabric.CodeNotFound)
	var refs []fabric.EndpointRef
	var views []fabric.ReferenceHandleView
	for i := 0; i < 3; i++ {
		d, rev := registerEndpoint(t, s, c)
		refs = append(refs, d.Ref)
		v := allocateHandle(t, s, c, d.Ref, fmt.Sprintf("participant-%d", i+1))
		if v.Handle != fmt.Sprintf("#%d.r1", i+1) || v.Revision != rev || v.Ref != d.Ref {
			t.Fatalf("allocation %d = %+v", i, v)
		}
		views = append(views, v)
	}
	// Exactly one canonical target per handle, and vice versa.
	for i, want := range refs {
		got, e := s.ResolveReferenceHandle(ctx, views[i].Handle)
		if e != nil || got.Ref != want || got.Revision != views[i].Revision || got.Label != views[i].Label {
			t.Fatalf("resolve %s = %+v %v", views[i].Handle, got, e)
		}
		if byRef, e := s.ReferenceHandleForRef(ctx, want); e != nil || byRef != views[i] {
			t.Fatalf("by-ref %s = %+v %v", want, byRef, e)
		}
	}
	// Idempotent: the same endpoint returns its existing slot, and the
	// persisted label is the truth, not the new request's.
	again, e := s.AllocateReferenceHandle(ctx, c, refs[0], "forged-label")
	if e != nil || again != views[0] {
		t.Fatalf("re-allocation not idempotent: %+v %v", again, e)
	}
	// An offer or foreign reference never allocates.
	offerRef, e := refs[0].WithOfferID(make([]byte, 32))
	if e != nil {
		t.Fatal(e)
	}
	if _, e := s.AllocateReferenceHandle(ctx, c, offerRef, "offer"); e == nil {
		t.Fatal("offer allocated a handle")
	} else {
		code(t, e, fabric.CodeInvalidInput)
	}
	foreign, e := fabric.NewEndpointRef(make([]byte, 32))
	if e != nil {
		t.Fatal(e)
	}
	if _, e := s.AllocateReferenceHandle(ctx, c, foreign, "foreign"); e == nil {
		t.Fatal("foreign reference allocated a handle")
	} else {
		code(t, e, fabric.CodeInvalidInput)
	}
}

// No slot reuse: a retired endpoint's slot is permanent; later endpoints get
// only fresh slots, and the retired handle fails explicitly.
func TestReferenceHandleNoSlotReuseAfterRetirement(t *testing.T) {
	s, c, _ := fixture(t)
	ctx := context.Background()
	d, rev := registerEndpoint(t, s, c)
	v := allocateHandle(t, s, c, d.Ref, "p1")
	if v.Handle != "#1.r1" {
		t.Fatal(v)
	}
	if _, e := s.Retire(ctx, c, d.Ref, rev); e != nil {
		t.Fatal(e)
	}
	if _, e := s.ResolveReferenceHandle(ctx, "#1.r1"); e == nil {
		t.Fatal("retired slot resolved")
	} else {
		code(t, e, fabric.CodeNotFound)
	}
	if _, e := s.ReferenceHandleForRef(ctx, d.Ref); e == nil {
		t.Fatal("retired endpoint returned a handle")
	} else {
		code(t, e, fabric.CodeNotFound)
	}
	// The next endpoint takes slot 2, never slot 1.
	d2, _ := registerEndpoint(t, s, c)
	v2 := allocateHandle(t, s, c, d2.Ref, "p2")
	if v2.Handle != "#2.r1" {
		t.Fatalf("slot reused: %+v", v2)
	}
	d3, _ := registerEndpoint(t, s, c)
	v3 := allocateHandle(t, s, c, d3.Ref, "p3")
	if v3.Handle != "#3.r1" {
		t.Fatalf("slot sequence broken: %+v", v3)
	}
}

// Stale detection: a descriptor update advances the slot's handle revision in
// the same transaction. The old text resolves as CodeStaleReference with the
// current handle; the endpoint identity never changes; an idempotent mutation
// retry does not advance the handle twice.
func TestReferenceHandleStaleDetection(t *testing.T) {
	s, c, _ := fixture(t)
	ctx := context.Background()
	d, rev1 := registerEndpoint(t, s, c)
	v := allocateHandle(t, s, c, d.Ref, "Maria")
	if v.Revision != rev1 {
		t.Fatal(v)
	}
	d2 := d
	d2.Name = "Renamed"
	rev2, e := s.Update(ctx, c, fabric.RegistryUpdate{Descriptor: d2, ExpectedRevision: rev1})
	if e != nil {
		t.Fatal(e)
	}
	// The old handle is stale and actionable; the current handle is returned.
	got, e := s.ResolveReferenceHandle(ctx, "#1.r1")
	code(t, e, fabric.CodeStaleReference)
	if !strings.Contains(e.Error(), "#1.r1") || !strings.Contains(e.Error(), "#1.r2") {
		t.Fatalf("stale error not actionable: %v", e)
	}
	if got.Handle != "#1.r2" || got.Ref != d.Ref || got.Revision != rev2 || got.Label != "Maria" {
		t.Fatalf("stale current = %+v", got)
	}
	// The new handle resolves cleanly to the same canonical identity.
	cur, e := s.ResolveReferenceHandle(ctx, "#1.r2")
	if e != nil || cur.Handle != "#1.r2" || cur.Ref != d.Ref || cur.Revision != rev2 {
		t.Fatalf("current = %+v %v", cur, e)
	}
	// An exact idempotent retry of the same mutation does not advance again.
	retry, e := s.Update(ctx, c, fabric.RegistryUpdate{Descriptor: d2, ExpectedRevision: rev1})
	if e != nil || retry != rev2 {
		t.Fatalf("retry = %s %v", retry, e)
	}
	if _, e := s.ResolveReferenceHandle(ctx, "#1.r2"); e != nil {
		t.Fatalf("idempotent retry advanced the handle: %v", e)
	}
	// A second update advances again; every superseded text stays stale.
	d3 := d2
	d3.Name = "Again"
	rev3, e := s.Update(ctx, c, fabric.RegistryUpdate{Descriptor: d3, ExpectedRevision: rev2})
	if e != nil {
		t.Fatal(e)
	}
	_, e = s.ResolveReferenceHandle(ctx, "#1.r2")
	if e == nil {
		t.Fatal("second generation resolved")
	}
	code(t, e, fabric.CodeStaleReference)
	if got, e := s.ResolveReferenceHandle(ctx, "#1.r3"); e != nil || got.Revision != rev3 || got.Ref != d.Ref {
		t.Fatalf("third = %+v %v", got, e)
	}
	// A skipped generation is stale too, pointing at the current handle.
	if _, e := s.ResolveReferenceHandle(ctx, "#1.r1"); e == nil || !strings.Contains(e.Error(), "#1.r3") {
		t.Fatalf("skipped generation: %v", e)
	}
}

// Cross-root / cross-principal confusion: a handle from another private root
// is explicitly unknown here, and rows grafted with a foreign scope are inert
// while the root is live and fail the restart gate when it reopens.
func TestReferenceHandleCrossRootAndPrincipalRejection(t *testing.T) {
	ctx := context.Background()
	sA, cA, dirA := fixture(t)
	sB, _, _ := fixture(t)
	d, _ := registerEndpoint(t, sA, cA)
	v := allocateHandle(t, sA, cA, d.Ref, "p1")
	if v.Handle != "#1.r1" {
		t.Fatal(v)
	}
	// The same slot number in another root resolves nothing.
	if _, e := sB.ResolveReferenceHandle(ctx, "#1.r1"); e == nil {
		t.Fatal("cross-root handle resolved")
	} else {
		code(t, e, fabric.CodeNotFound)
	}
	// A row grafted under a foreign principal scope is inert in this root.
	foreignScope := "foreign-store\x00" + sA.Namespace() + "\x00spiffe://local/other"
	if _, e := sA.db.Exec("INSERT INTO reference_handles VALUES(?,?,?,?,?,?,?)", foreignScope, 1, d.Ref.String(), 1, v.Revision, "forged", 0); e != nil {
		t.Fatal(e)
	}
	got, e := sA.ResolveReferenceHandle(ctx, "#1.r1")
	if e != nil || got.Ref != d.Ref || got.Label != "p1" {
		t.Fatalf("grafted row changed resolution: %+v %v", got, e)
	}
	// Reopening fails closed: foreign-scope rows are retained-state corruption.
	if e := sA.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e := Open(ctx, dirA); e == nil {
		t.Fatal("foreign-scope handle state accepted on restart")
	}
}

// Bounded quota: allocation fails explicitly at the finite per-scope bound,
// the bound survives restart, and reopening with a smaller limit rejects the
// retained state instead of purging it.
func TestReferenceHandleQuotaExhaustion(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "domain")
	opts := DefaultOptions()
	opts.Limits.MaxReferenceHandles = 2
	s, e := BootstrapWithOptions(ctx, dir, testOwner, opts)
	if e != nil {
		t.Fatal(e)
	}
	c, e := fabric.NewAuthenticatedContext(testOwner, s.Namespace(), []byte("trusted original request"))
	if e != nil {
		t.Fatal(e)
	}
	var refs [3]fabric.EndpointRef
	for i := range refs {
		d, _ := registerEndpoint(t, s, c)
		refs[i] = d.Ref
	}
	if v, e := s.AllocateReferenceHandle(ctx, c, refs[0], "one"); e != nil || v.Handle != "#1.r1" {
		t.Fatalf("one: %+v %v", v, e)
	}
	if v, e := s.AllocateReferenceHandle(ctx, c, refs[1], "two"); e != nil || v.Handle != "#2.r1" {
		t.Fatalf("two: %+v %v", v, e)
	}
	_, e = s.AllocateReferenceHandle(ctx, c, refs[2], "three")
	if e == nil {
		t.Fatal("quota exhausted silently")
	}
	code(t, e, fabric.CodeInvalidInput)
	// The bound and the counter survive restart.
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	s, e = OpenWithOptions(ctx, dir, opts)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	_, e = s.AllocateReferenceHandle(ctx, c, refs[2], "three")
	if e == nil {
		t.Fatal("quota reset across restart")
	}
	code(t, e, fabric.CodeInvalidInput)
	// Reopening with a smaller limit rejects retained state.
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	smaller := DefaultOptions()
	smaller.Limits.MaxReferenceHandles = 1
	if _, e := OpenWithOptions(ctx, dir, smaller); e == nil {
		t.Fatal("smaller quota accepted retained slots")
	}
}

// Restart survival: the mapping, the persisted label, the stale generations
// and the slot counter all survive a full close/open cycle.
func TestReferenceHandleRestartSurvival(t *testing.T) {
	ctx := context.Background()
	s, c, dir := fixture(t)
	d, rev1 := registerEndpoint(t, s, c)
	v := allocateHandle(t, s, c, d.Ref, "Maria")
	d2 := d
	d2.Name = "Renamed"
	rev2, e := s.Update(ctx, c, fabric.RegistryUpdate{Descriptor: d2, ExpectedRevision: rev1})
	if e != nil {
		t.Fatal(e)
	}
	if _, e := s.SetReferenceHandleLabel(ctx, c, d.Ref, "Maria (research)"); e != nil {
		t.Fatal(e)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	s, e = Open(ctx, dir)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	cur, e := s.ResolveReferenceHandle(ctx, "#1.r2")
	if e != nil || cur.Handle != "#1.r2" || cur.Ref != d.Ref || cur.Revision != rev2 || cur.Label != "Maria (research)" {
		t.Fatalf("survived = %+v %v", cur, e)
	}
	_, e = s.ResolveReferenceHandle(ctx, "#1.r1")
	if e == nil {
		t.Fatal("stale generation survived restart as live")
	}
	code(t, e, fabric.CodeStaleReference)
	if byRef, e := s.ReferenceHandleForRef(ctx, d.Ref); e != nil || byRef != cur {
		t.Fatalf("by-ref = %+v %v", byRef, e)
	}
	// The counter survived too: the next slot is 2.
	d3, _ := registerEndpoint(t, s, c)
	if v3 := allocateHandle(t, s, c, d3.Ref, "p3"); v3.Handle != "#2.r1" {
		t.Fatalf("counter lost across restart: %+v", v3)
	}
	_ = v
}

// Concurrent allocation: distinct endpoints take distinct slots without gaps,
// and concurrent allocation of the same endpoint converges on one slot.
func TestReferenceHandleConcurrentAllocation(t *testing.T) {
	s, c, _ := fixture(t)
	ctx := context.Background()
	const n = 8
	refs := make([]fabric.EndpointRef, n)
	for i := range refs {
		d, _ := registerEndpoint(t, s, c)
		refs[i] = d.Ref
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	failed := 0
	views := make([]fabric.ReferenceHandleView, n)
	for i := range refs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			v, e := s.AllocateReferenceHandle(ctx, c, refs[i], fmt.Sprintf("p%d", i+1))
			if e != nil {
				mu.Lock()
				failed++
				mu.Unlock()
				return
			}
			mu.Lock()
			views[i] = v
			mu.Unlock()
		}(i)
	}
	wg.Wait()
	if failed != 0 {
		t.Fatalf("%d concurrent allocations failed", failed)
	}
	slots := make([]int, n)
	for i, v := range views {
		slot, _, e := fabric.ParseReferenceHandle(v.Handle)
		if e != nil || v.Revision == "" || v.Ref != refs[i] {
			t.Fatalf("view %d = %+v %v", i, v, e)
		}
		slots[i] = int(slot)
	}
	sort.Ints(slots)
	for i, want := range slots {
		if want != i+1 {
			t.Fatalf("slot sequence %v not contiguous 1..%d", slots, n)
		}
	}
	// Concurrent allocation of one endpoint is idempotent: every caller gets
	// the single slot, never a divergent second one.
	d, _ := registerEndpoint(t, s, c)
	var first fabric.ReferenceHandleView
	var haveFirst, diverged int
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, e := s.AllocateReferenceHandle(ctx, c, d.Ref, "same")
			if e != nil {
				t.Error(e)
				return
			}
			mu.Lock()
			if haveFirst == 0 {
				first, haveFirst = v, 1
			} else if v != first {
				diverged++
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	if haveFirst == 0 {
		t.Fatal("no concurrent allocation succeeded")
	}
	if diverged != 0 {
		t.Fatalf("%d concurrent allocations diverged on one endpoint", diverged)
	}
	if slot, _, e := fabric.ParseReferenceHandle(first.Handle); e != nil || slot == 0 || first.Ref != d.Ref {
		t.Fatalf("shared slot = %+v %v", first, e)
	}
}

// Adoption ordering: an original v1 root that adopts handle state first must
// still adopt the native authority schema in strict version order (1 -> 2 ->
// 3), so later native authority use and the restart gate both work.
func TestReferenceHandleAdoptionOrderingWithNativeAuthority(t *testing.T) {
	s, c, dir := fixture(t)
	ctx := context.Background()
	if v := nativeVersion(t, s); v != 1 {
		t.Fatalf("fresh fixture at version %d", v)
	}
	d, rev := registerEndpoint(t, s, c)
	v := allocateHandle(t, s, c, d.Ref, "p1")
	if nativeVersion(t, s) != 3 {
		t.Fatalf("handle adoption skipped the native authority version: %d", nativeVersion(t, s))
	}
	// Native authority must work on the now v3 root and survive the restart.
	scope := AuthorityScope{Endpoint: d.Ref, ExpectedRevision: rev, BindingID: "local"}
	key := AuthorityKey{Kind: AuthorityBinding, Endpoint: d.Ref, ID: "binding"}
	if e := s.WithNativeAuthority(ctx, c, scope, func(a *AuthorityTx) error {
		_, e := a.CAS(key, 0, []byte(`{"generation":"one"}`), false)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	reopened, e := Open(ctx, dir)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	if cur, e := reopened.ResolveReferenceHandle(ctx, v.Handle); e != nil || cur.Ref != d.Ref {
		t.Fatalf("handle lost across mixed adoption: %+v %v", cur, e)
	}
}

// The compact handle text is strict: only "#<slot>.r<revision>" with positive
// finite values parses, and it round-trips through the formatter.
func TestReferenceHandleParseAndFormat(t *testing.T) {
	slot, rev, e := fabric.ParseReferenceHandle("#7.r3")
	if e != nil || slot != 7 || rev != 3 || fabric.FormatReferenceHandle(slot, rev) != "#7.r3" {
		t.Fatalf("parse: %d %d %v", slot, rev, e)
	}
	for _, bad := range []string{"", "#", "#1", "#1.r", "#1.r1x", "#01.r1", "#0.r1", "#1.r0", "1.r1", "#A.r1", "#1.R1", "#1000000001.r1", "#1.r1000000001", "#1.r1 ", " #1.r1", "#1.r1\n"} {
		_, _, e := fabric.ParseReferenceHandle(bad)
		if e == nil {
			t.Fatalf("accepted %q", bad)
		}
		if fe, ok := e.(*fabric.Error); !ok || fe.Code != fabric.CodeInvalidInput {
			t.Fatalf("code for %q: %v", bad, e)
		}
	}
}
