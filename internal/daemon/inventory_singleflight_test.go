package daemon

import (
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/transport"
)

// TestInventorySingleFlight (external audit F-016): when an inventory scan
// is already in flight, a concurrent caller must WAIT for it and REUSE its
// result — not run a second (expensive) scan. Without the guard, a
// reconnect + a host.request_inventory + an UpdateRoots arriving close
// together would each fan out their own workspace walk + runtime version
// probes, multiplying the helper-process storm.
func TestInventorySingleFlight(t *testing.T) {
	d := newTestDaemon(t)

	// Simulate an in-flight scan: a flight that is not yet done.
	f := &inventoryFlight{done: make(chan struct{})}
	d.invMu.Lock()
	d.invFlight = f
	d.invMu.Unlock()

	got := make(chan transport.InventoryPayload, 1)
	go func() { got <- d.buildInventoryPayload() }()

	// The concurrent caller must block until the in-flight scan settles —
	// it must not return a freshly-scanned payload immediately.
	select {
	case <-got:
		t.Fatal("concurrent caller returned before the in-flight scan settled (no single-flight)")
	case <-time.After(100 * time.Millisecond):
	}
	// Settle the in-flight scan exactly as the scanning caller would: set
	// the payload, close done, clear the flight.
	f.payload = transport.InventoryPayload{HostID: "shared-result"}
	close(f.done)
	d.invMu.Lock()
	d.invFlight = nil
	d.invMu.Unlock()

	select {
	case p := <-got:
		if p.HostID != "shared-result" {
			t.Fatalf("concurrent caller reused a different payload: %+v (want the in-flight scan's result)", p)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("concurrent caller did not return after the in-flight scan settled")
	}
}
