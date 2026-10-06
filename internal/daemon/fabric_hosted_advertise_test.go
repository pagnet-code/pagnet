//go:build linux || darwin

package daemon

import (
	"context"
	"net/url"
	"testing"

	"github.com/pagnet-code/pagnet/transport"
)

// TestWsURLHostedAdvertiseGate proves the per-connect advertisement gate: the
// fabric-hosted-native capability is on the connect query ONLY when the
// composition-supplied gate passes on the connect context. A nil gate never
// advertises (no implicit enabling, no enabling by the presence of a SID).
func TestWsURLHostedAdvertiseGate(t *testing.T) {
	const base = "https://app.pagnet.dev"
	ctx := context.Background()

	d0 := newTestDaemon(t)
	d0.ServerURL = base
	u0, err := url.Parse(d0.wsURL(ctx))
	if err != nil {
		t.Fatalf("parse wsURL: %v", err)
	}
	if got := u0.Query().Get("fabric_hosted_native"); got != "" {
		t.Fatalf("nil gate must not advertise; got %q", got)
	}

	d1 := newTestDaemon(t)
	d1.ServerURL = base
	d1.HostedAdvertise = func(context.Context) bool { return false }
	u1, err := url.Parse(d1.wsURL(ctx))
	if err != nil {
		t.Fatalf("parse wsURL: %v", err)
	}
	if got := u1.Query().Get("fabric_hosted_native"); got != "" {
		t.Fatalf("failing gate must not advertise; got %q", got)
	}

	d2 := newTestDaemon(t)
	d2.ServerURL = base
	d2.HostedAdvertise = func(context.Context) bool { return true }
	u2, err := url.Parse(d2.wsURL(ctx))
	if err != nil {
		t.Fatalf("parse wsURL: %v", err)
	}
	if got := u2.Query().Get("fabric_hosted_native"); got != transport.FabricHostedProtocol {
		t.Fatalf("passing gate must advertise the exact hosted protocol; got %q want %q", got, transport.FabricHostedProtocol)
	}
}
