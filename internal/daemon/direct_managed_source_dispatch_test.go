package daemon

import (
	"encoding/json"
	"net/url"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
)

func TestDirectManagedSourceDispatchVersions(t *testing.T) {
	for i, typ := range []string{transport.MsgDirectManagedSourcePrepare, transport.MsgDirectManagedSourcePoP, transport.MsgDirectManagedSourceCredential} {
		for _, version := range append(append([]string{}, directManagedSourceProtocolsV1[:]...), directManagedSourceProtocolsV2[:]...) {
			var got int
			d := &directManagedSourceDispatch{}
			for j := range 3 {
				index := j
				d.v1 = append(d.v1, func(transport.Envelope) bool { got = 10 + index; return true })
				d.v2 = append(d.v2, func(transport.Envelope) bool { got = 20 + index; return true })
			}
			raw, _ := json.Marshal(map[string]string{"protocolVersion": version})
			if !d.handle(transport.Envelope{Type: typ, Payload: raw}) {
				t.Fatal("reserved command escaped")
			}
			want := 0
			if version == directManagedSourceProtocolsV1[i] {
				want = 10 + i
			}
			if version == directManagedSourceProtocolsV2[i] {
				want = 20 + i
			}
			if got != want {
				t.Fatalf("%s / %s routed to %d; want %d", typ, version, got, want)
			}
		}
	}
}

func TestDirectManagedSourceDispatchMalformedConsumed(t *testing.T) {
	for _, raw := range []string{`{}`, `null`, `[]`, `{"protocolVersion":"direct_managed_source_prepare_v2"}`, `{"protocolVersion":2}`, `{"protocol\u0056ersion":"direct_managed_source_prepare_v1"}`, `{"ProtocolVersion":"direct_managed_source_prepare_v1"}`, `{"protocolVersion":"direct_managed_source_prepare_v2","protocolVersion":"direct_managed_source_prepare_v1"}`, `{"protocolVersion":"direct_managed_source_prepare_v2"} {}`, `{"protocolVersion":"direct_managed_source_prepare_v9"}`, `{"subject":{"protocolVersion":"direct_managed_source_prepare_v2"}}`} {
		d := &directManagedSourceDispatch{v1: []func(transport.Envelope) bool{func(transport.Envelope) bool { t.Fatal("malformed reached V1"); return true }, nil, nil}}
		if !d.handle(transport.Envelope{Type: transport.MsgDirectManagedSourcePrepare, Payload: []byte(raw)}) {
			t.Fatal("malformed escaped dispatcher")
		}
	}
	d := &directManagedSourceDispatch{}
	if d.handle(transport.Envelope{Type: "unrelated"}) {
		t.Fatal("unrelated command consumed")
	}
}

func TestDirectManagedSourceV2AuthenticatedSelection(t *testing.T) {
	host, boot, runner := domain.NewID().String(), domain.NewID().String(), domain.NewID().String()
	base := transport.HostSessionPayload{HostID: host, BootID: boot, TenantID: host, AccountID: host, NativeAdmissionID: runner, RunnerID: runner, OwnershipScope: "personal", RunnerEpoch: time.Now().UTC()}
	for _, reason := range []string{"exact", "unoffered", "duplicate", "mixed", "partial", "duplicate-offer", "unknown"} {
		t.Run(reason, func(t *testing.T) {
			c := NewNativeObservationConnection("https://example.test", host, boot, nil)
			query := url.Values{}
			for i, key := range directManagedSourceQueryKeys {
				query.Set(key, directManagedSourceProtocolsV2[i])
			}
			if reason == "unoffered" {
				query.Del(directManagedSourceQueryKeys[0])
			}
			if reason == "duplicate-offer" {
				query.Add(directManagedSourceQueryKeys[0], directManagedSourceProtocolsV2[0])
			}
			c.captureDirectManagedSourceOffers(query)
			p := base
			p.ProtocolFeatures = append([]string{transport.NativeObservationReceiptProtocol}, directManagedSourceProtocolsV2[:]...)
			switch reason {
			case "duplicate":
				p.ProtocolFeatures = append(p.ProtocolFeatures, directManagedSourceProtocolsV2[0])
			case "mixed":
				p.ProtocolFeatures = append(p.ProtocolFeatures, directManagedSourceProtocolsV1[1])
			case "unknown":
				p.ProtocolFeatures = append(p.ProtocolFeatures, "direct_managed_source_prepare_v9")
			case "partial":
				p.ProtocolFeatures = p.ProtocolFeatures[:3]
			}
			err := c.Admit(p)
			if (err == nil) != (reason == "exact") {
				t.Fatalf("selection %s: %v", reason, err)
			}
		})
	}
}
