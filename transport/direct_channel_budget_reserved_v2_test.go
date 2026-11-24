package transport

import (
	"bytes"
	"reflect"
	"testing"
)

func TestDirectChannelReservedCountingCanonicalCompatibility(t *testing.T) {
	p, _, _, _, _ := directV2TestFixture(t)
	legacy, err := p.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if DirectChannelCountingVersionV2 != "canonical_encrypted_wire_bytes_utc_minute_day_ask_reply_each_v1" {
		t.Fatal("original counting default changed")
	}
	original := p.Descriptor
	p.Descriptor.Budget.CountingVersion = DirectChannelCountingVersionReservedV2
	raw, err := p.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	want := bytes.Replace(legacy, []byte(DirectChannelCountingVersionV2), []byte(DirectChannelCountingVersionReservedV2), 1)
	if !bytes.Equal(raw, want) {
		t.Fatal("counting selection changed other canonical bytes")
	}
	decoded, err := DecodeDirectChannelPublicationV2(raw)
	if err != nil || !reflect.DeepEqual(decoded, p) {
		t.Fatalf("publication round trip: %v", err)
	}
	descriptor, _ := p.Descriptor.CanonicalBytes()
	if _, err := DecodeDirectChannelDescriptorV2(descriptor); err != nil {
		t.Fatal(err)
	}
	oldHash, _ := DescriptorHashV2(original)
	newHash, _ := DescriptorHashV2(p.Descriptor)
	oldID, _ := DirectChannelIDV2(original)
	newID, _ := DirectChannelIDV2(p.Descriptor)
	if oldHash == newHash || oldID != newID {
		t.Fatal("counting version must bind descriptor hash, preserving channel identity")
	}
	for _, field := range []string{"limits", "grantLimits"} {
		bad := bytes.Replace(raw, []byte(`"`+field+`":{`), []byte(`"`+field+`":{"replyReservationSeconds":60,`), 1)
		if _, err := DecodeDirectChannelPublicationV2(bad); err == nil {
			t.Fatalf("accepted seventh %s field", field)
		}
	}
}

func TestDirectChannelReservedCountingLimits(t *testing.T) {
	p, _, _, _, now := directV2TestFixture(t)
	minimum := DirectChannelLimitsV2{1024, 2, 2, 2048, 1, 1}
	maximum := DirectChannelLimitsV2{65536, 10, 200, 8388608, 2, 16}
	for _, limits := range []DirectChannelLimitsV2{minimum, maximum, {65536, 2, 2, 131072, 1, 1}} {
		d := p.Descriptor
		d.Budget.CountingVersion = DirectChannelCountingVersionReservedV2
		d.Limits, d.Budget.GrantLimits = limits, limits
		if err := ValidateDirectChannelDescriptorV2(d, now); err != nil {
			t.Fatalf("valid boundary %+v: %v", limits, err)
		}
	}
	mutations := map[string]func(*DirectChannelLimitsV2){
		"minute":   func(l *DirectChannelLimitsV2) { l.MaxMessagesPerMinute = 1 },
		"day":      func(l *DirectChannelLimitsV2) { l.MaxMessagesPerDay = 1 },
		"bytes":    func(l *DirectChannelLimitsV2) { l.MaxWireBytesPerDay = 2047 },
		"overflow": func(l *DirectChannelLimitsV2) { l.MaxMessageWireBytes = int(^uint(0) >> 1) },
	}
	for name, mutate := range mutations {
		for _, grant := range []bool{false, true} {
			t.Run(name+map[bool]string{false: "/pair", true: "/grant"}[grant], func(t *testing.T) {
				d := p.Descriptor
				d.Budget.CountingVersion = DirectChannelCountingVersionReservedV2
				d.Limits, d.Budget.GrantLimits = minimum, minimum
				if grant {
					mutate(&d.Budget.GrantLimits)
				} else {
					mutate(&d.Limits)
				}
				if err := ValidateDirectChannelDescriptorV2(d, now); err == nil {
					t.Fatal("accepted invalid reserved limits")
				}
			})
		}
	}
	for field := 0; field < 6; field++ {
		d := p.Descriptor
		d.Budget.CountingVersion = DirectChannelCountingVersionReservedV2
		d.Limits, d.Budget.GrantLimits = minimum, minimum
		v := reflect.ValueOf(&d.Limits).Elem().Field(field)
		v.SetInt(v.Int() + 1)
		// Keep pair byte capacity valid while exceeding the grant message size.
		if field == 0 {
			d.Limits.MaxWireBytesPerDay += 2
			d.Budget.GrantLimits.MaxWireBytesPerDay += 2
		}
		if err := ValidateDirectChannelDescriptorV2(d, now); err == nil {
			t.Errorf("pair field %d exceeded grant", field)
		}
	}
	// The original counting contract retains its single-message lower bounds.
	d := p.Descriptor
	d.Limits, d.Budget.GrantLimits = DirectChannelLimitsV2{1024, 1, 1, 1024, 1, 1}, DirectChannelLimitsV2{1024, 1, 1, 1024, 1, 1}
	if err := ValidateDirectChannelDescriptorV2(d, now); err != nil {
		t.Fatal("original lower bounds changed", err)
	}
}
