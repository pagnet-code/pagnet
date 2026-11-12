package transport

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestBrowserAccountReplyReadCanonicalEnvelope(t *testing.T) {
	s, _, proof := accountContractFixtureFile(t, "account_message_source_reply_html_v1.json")
	r, _, _ := accountReplyWireFixture(t)
	proof.AccountMessageSource = &s
	p := BrowserAccountReplyReadBeginPayload{V: 1, MessageID: s.MessageID, Deadline: time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano), Reference: r, Proof: proof}
	e, err := NewEnvelope(MsgAccountReplyRead, p)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalNativeJSON(e)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeBrowserAccountReplyReadFrame(raw)
	if err != nil {
		t.Fatal(err)
	}
	var decoded BrowserAccountReplyReadBeginPayload
	if err = DecodeBrowserAccountReplyReadPayload(got.Payload, &decoded); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.Proof.AccountMessageSource.CanonicalJSON(), s.CanonicalJSON()) {
		t.Fatal("source canonical bytes changed through envelope")
	}
	if bytes.Contains(raw, []byte(`\u003c`)) || bytes.Contains(raw, []byte(`\u0026`)) {
		t.Fatal("canonical account bytes HTML escaped")
	}
}

func TestBrowserAccountReplyReadStrictFrames(t *testing.T) {
	e, err := NewEnvelope(MsgAccountReplyReadCommit, BrowserAccountReplyReadVersionPayload{V: 1})
	if err != nil {
		t.Fatal(err)
	}
	id := e.ID
	e.CorrelationID = &id
	raw, err := MarshalNativeJSON(e)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = DecodeBrowserAccountReplyReadFrame(raw); err != nil {
		t.Fatal(err)
	}
	for name, changed := range map[string][]byte{
		"duplicate":    bytes.Replace(raw, []byte(`"v":1`), []byte(`"v":1,"v":1`), 1),
		"alias":        bytes.Replace(raw, []byte(`"id"`), []byte(`"ID"`), 1),
		"unknown":      bytes.Replace(raw, []byte(`"protocolVersion":2`), []byte(`"extra":0,"protocolVersion":2`), 1),
		"version":      bytes.Replace(raw, []byte(`"protocolVersion":2`), []byte(`"protocolVersion":1`), 1),
		"trailing":     append(append([]byte{}, raw...), []byte(`{}`)...),
		"invalid utf8": append(append([]byte{}, raw...), 0xff),
		"oversize":     bytes.Repeat([]byte(" "), BrowserAccountReplyReadMaxWireBytes+1),
		"surrogate":    bytes.Replace(raw, []byte(`"v":1`), []byte(`"v":"\ud800"`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeBrowserAccountReplyReadFrame(changed); err == nil {
				t.Fatal("accepted ambiguous read frame")
			}
		})
	}
	for _, mutate := range []func(*Envelope){func(e *Envelope) { e.CorrelationID = nil }, func(e *Envelope) { e.CausationID = &id }, func(e *Envelope) { e.ID = strings.ToUpper(e.ID) }, func(e *Envelope) { e.Type = "host.command" }} {
		changed := e
		mutate(&changed)
		raw, _ := json.Marshal(changed)
		if _, err := DecodeBrowserAccountReplyReadFrame(raw); err == nil {
			t.Fatal("accepted invalid frame metadata")
		}
	}
}
