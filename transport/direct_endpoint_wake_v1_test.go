package transport

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func wakeTestOfferV1() DirectEndpointWakeOfferV1 {
	return DirectEndpointWakeOfferV1{DirectEndpointWakeProtocolV1, directV2TestID(1), directV2TestID(2), directV2TestID(3), "1", directV2TestID(4), "9223372036854775807"}
}

func TestDirectEndpointWakeV1Wire(t *testing.T) {
	offer := wakeTestOfferV1()
	subscribe := DirectEndpointWakeSubscribeV1{DirectEndpointWakeProtocolV1, offer.SubscriptionID, directV2TestID(5), DirectEndpointWakeRoleSourceV2, directV2TestID(6)}
	cases := []struct {
		kind   string
		value  interface{ CanonicalBytes() ([]byte, error) }
		decode func([]byte) (any, error)
	}{
		{MsgDirectEndpointWakeSubscribe, subscribe, func(b []byte) (any, error) { return DecodeDirectEndpointWakeSubscribeV1(b) }},
		{MsgDirectEndpointWakeOffer, offer, func(b []byte) (any, error) { return DecodeDirectEndpointWakeOfferV1(b) }},
		{MsgDirectEndpointWakeACK, DirectEndpointWakeACKV1(offer), func(b []byte) (any, error) { return DecodeDirectEndpointWakeACKV1(b) }},
		{MsgDirectEndpointWakeUnsubscribe, DirectEndpointWakeUnsubscribeV1{DirectEndpointWakeProtocolV1, offer.SubscriptionID}, func(b []byte) (any, error) { return DecodeDirectEndpointWakeUnsubscribeV1(b) }},
		{MsgDirectEndpointWakeClosed, DirectEndpointWakeClosedV1{DirectEndpointWakeProtocolV1, offer.SubscriptionID, DirectEndpointWakeClosedUnavailable}, func(b []byte) (any, error) { return DecodeDirectEndpointWakeClosedV1(b) }},
	}
	for _, tc := range cases {
		t.Run(tc.kind, func(t *testing.T) {
			raw, err := tc.value.CanonicalBytes()
			if err != nil {
				t.Fatal(err)
			}
			got, err := tc.decode(raw)
			if err != nil || !reflect.DeepEqual(got, tc.value) {
				t.Fatalf("roundtrip: %v, %v", got, err)
			}
			env, err := NewEnvelope(tc.kind, tc.value)
			if err != nil || env.ProtocolVersion != 2 || env.Type != tc.kind || !bytes.Equal(env.Payload, raw) {
				t.Fatalf("envelope: %+v, %v", env, err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(raw, &fields); err != nil {
				t.Fatal(err)
			}
			bad := map[string][]byte{
				"empty": nil, "null": []byte("null"), "array": []byte("[]"),
				"unknown":         append([]byte(`{"future":1,`), raw[1:]...),
				"trailing":        append(append([]byte{}, raw...), []byte("{}")...),
				"oversize":        bytes.Repeat([]byte(" "), DirectEndpointWakeMaxPayloadBytesV1+1),
				"future protocol": bytes.Replace(raw, []byte(DirectEndpointWakeProtocolV1), []byte("direct-endpoint-wake-v2"), 1),
				"invalid utf8":    append([]byte{'{', '"', 0xff, '"', ':', '0', ','}, raw[1:]...),
			}
			for key, value := range fields {
				duplicate := []byte(`{"` + key + `":` + string(value) + `,`)
				bad["duplicate "+key] = append(duplicate, raw[1:]...)
				missing := make(map[string]json.RawMessage)
				for k, v := range fields {
					if k != key {
						missing[k] = v
					}
				}
				bad["missing "+key], _ = json.Marshal(missing)
				bad["null "+key] = bytes.Replace(raw, append([]byte(`"`+key+`":`), value...), []byte(`"`+key+`":null`), 1)
				alias := strings.ToUpper(key[:1]) + key[1:]
				bad["case alias "+key] = bytes.Replace(raw, []byte(`"`+key+`":`), []byte(`"`+alias+`":`), 1)
			}
			for name, b := range bad {
				t.Run(name, func(t *testing.T) {
					if _, err := tc.decode(b); err == nil {
						t.Fatalf("accepted %s", b)
					}
				})
			}
		})
	}
}

func TestDirectEndpointWakeV1Validation(t *testing.T) {
	offer := wakeTestOfferV1()
	for _, field := range []string{"Generation", "Revision"} {
		for _, value := range []string{"", "0", "-1", "01", "+1", "1.0", "1e2", " 1", "9223372036854775808", "18446744073709551615"} {
			p := offer
			reflect.ValueOf(&p).Elem().FieldByName(field).SetString(value)
			if _, err := p.CanonicalBytes(); err == nil {
				t.Errorf("accepted %s %q", field, value)
			}
		}
	}
	for _, field := range []string{"SubscriptionID", "StreamID", "ContinuityID", "OfferID"} {
		for _, value := range []string{"", "00000000-0000-0000-0000-000000000000", "00000000000040008000000000000001", "00000000-0000-4000-8000-00000000000A"} {
			p := offer
			reflect.ValueOf(&p).Elem().FieldByName(field).SetString(value)
			if _, err := p.CanonicalBytes(); err == nil {
				t.Errorf("accepted %s %q", field, value)
			}
		}
	}
	p := DirectEndpointWakeSubscribeV1{DirectEndpointWakeProtocolV1, offer.SubscriptionID, directV2TestID(5), DirectEndpointWakeRoleTargetV1, directV2TestID(6)}
	if _, err := p.CanonicalBytes(); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"DirectIntentID", "CredentialID", "EndpointRole"} {
		bad := p
		reflect.ValueOf(&bad).Elem().FieldByName(field).SetString("future")
		if _, err := bad.CanonicalBytes(); err == nil {
			t.Errorf("accepted %s", field)
		}
	}
	for _, reason := range []string{DirectEndpointWakeClosedUnsubscribed, DirectEndpointWakeClosedUnavailable, DirectEndpointWakeClosedRetryExhausted} {
		if _, err := (DirectEndpointWakeClosedV1{DirectEndpointWakeProtocolV1, offer.SubscriptionID, reason}).CanonicalBytes(); err != nil {
			t.Fatal(err)
		}
	}
	for _, reason := range []string{"", "authority_lost", "listener_discontinuity", "future"} {
		if _, err := (DirectEndpointWakeClosedV1{DirectEndpointWakeProtocolV1, offer.SubscriptionID, reason}).CanonicalBytes(); err == nil {
			t.Errorf("accepted reason %q", reason)
		}
	}
}

func TestDirectEndpointWakeV1ACKExactTuple(t *testing.T) {
	offer := wakeTestOfferV1()
	ack := DirectEndpointWakeACKV1(offer)
	if err := ValidateDirectEndpointWakeACKV1(ack, offer); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"SubscriptionID", "StreamID", "ContinuityID", "Generation", "OfferID", "Revision"} {
		changed := ack
		value := directV2TestID(9)
		if field == "Generation" || field == "Revision" {
			value = "2"
		}
		reflect.ValueOf(&changed).Elem().FieldByName(field).SetString(value)
		if _, err := changed.CanonicalBytes(); err != nil {
			t.Fatal(err)
		}
		if err := ValidateDirectEndpointWakeACKV1(changed, offer); err == nil {
			t.Errorf("accepted changed %s", field)
		}
	}
	invalid := offer
	invalid.Protocol = "direct-endpoint-wake-v2"
	if ValidateDirectEndpointWakeACKV1(ack, invalid) == nil {
		t.Fatal("accepted invalid offer")
	}
}

func TestDirectEndpointWakeV1Constants(t *testing.T) {
	if DirectEndpointWakeProtocolV1 != "direct-endpoint-wake-v1" || DirectEndpointWakeFeatureV1 != DirectEndpointWakeProtocolV1 || DirectEndpointWakeQueryKey != "direct_endpoint_wake" || ProtocolVersion != 2 {
		t.Fatal("protocol constants changed")
	}
	for suffix, kind := range map[string]string{"subscribe": MsgDirectEndpointWakeSubscribe, "offer": MsgDirectEndpointWakeOffer, "ack": MsgDirectEndpointWakeACK, "unsubscribe": MsgDirectEndpointWakeUnsubscribe, "closed": MsgDirectEndpointWakeClosed} {
		if kind != "direct.endpoint.wake."+suffix {
			t.Errorf("unexpected message kind %q", kind)
		}
	}
}
