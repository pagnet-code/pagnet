package sdk

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/pagnet-code/pagnet/transport"
)

func TestDirectReservedCountingRoundTrip(t *testing.T) {
	d, _, s, p, now := directFixture(t)
	legacy := d
	d.Budget.CountingVersion = transport.DirectChannelCountingVersionReservedV2
	raw, err := d.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	sm, wire, err := directPrepare(raw, d, s, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := directAccept(wire, legacy, p, now); err == nil {
		t.Fatal("accepted different counting contract as expected descriptor")
	}
	pm, err := directAccept(wire, d, p, now)
	if err != nil {
		t.Fatal(err)
	}
	ask, err := sm.seal("ASK", "reserved-ask", "root", nil, []byte("question"), now)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := pm.seal("REPLY", "reserved-reply", "root", ask, []byte("answer"), now)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := sm.open("REPLY", "reserved-reply", "root", ask, reply, now)
	if err != nil || !bytes.Equal(plaintext, []byte("answer")) {
		t.Fatalf("reply round trip: %v", err)
	}
	for _, grant := range []bool{false, true} {
		invalid := d
		if grant {
			invalid.Budget.GrantLimits.MaxMessagesPerMinute = 1
		} else {
			invalid.Limits.MaxMessagesPerMinute = 1
		}
		rawBad, err := json.Marshal(invalid)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := directValidate(rawBad, invalid, now); err == nil {
			t.Fatal("accepted invalid expected reserved limits")
		}
	}
}
