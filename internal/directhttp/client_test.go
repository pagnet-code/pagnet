package directhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/transport"
)

func testClient(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	s := httptest.NewTLSServer(h)
	t.Cleanup(s.Close)
	c, e := New(s.URL)
	if e != nil {
		t.Fatal(e)
	}
	c.http.Transport.(*http.Transport).TLSClientConfig = s.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	return c
}
func TestRoutes(t *testing.T) {
	p, ch, proof, _, _ := directV2TestFixture(t)
	id := p.Descriptor.DirectIntentID
	secret := directV2TestBinary(90, 32)
	cred := p.Descriptor.S.CredentialID + ":" + secret
	wire, e := os.ReadFile("../../transport/testdata/direct_channel_message_v2.golden.json")
	if e != nil {
		t.Fatal(e)
	}
	wire = bytes.TrimSpace(wire)
	m, e := transport.DecodeDirectChannelMessageV2(wire)
	if e != nil {
		t.Fatal(e)
	}
	hash, _ := transport.DirectChannelMessageHashV2(m)
	b := transport.DirectMessageBindingV2{Context: transport.DirectDeliveryContextV2{ChannelID: ch.ChannelID, DescriptorHash: ch.DescriptorHash, PublicationHash: ch.PublicationHash, ParentGrantID: ch.ParentGrantID, GrantGeneration: ch.GrantGeneration}, MessageID: m.Header.MessageID, WireHash: hash, WireBytes: len(wire), Sender: transport.DirectDeliveryPartyV2{Role: "S", PrincipalID: p.Descriptor.S.PrincipalID, EndpointID: p.Descriptor.S.EndpointID, CredentialID: p.Descriptor.S.CredentialID}, Recipient: transport.DirectDeliveryPartyV2{Role: "P", PrincipalID: p.Descriptor.P.PrincipalID, EndpointID: p.Descriptor.P.EndpointID, CredentialID: p.Descriptor.P.CredentialID}}
	admission := transport.DirectMessageAdmissionReceiptV2{Version: 2, Domain: transport.DirectChannelDomainV2 + "/delivery/admission", Binding: b, AdmissionState: "admitted", AdmittedAt: "2030-01-01T00:01:00Z", ExpiresAt: "2030-01-01T00:02:00Z"}
	q := transport.DirectInboxRequestV2{Version: 2, Domain: transport.DirectChannelDomainV2 + "/delivery/inbox-request", Context: b.Context, Recipient: b.Recipient, Limit: 5}
	page := transport.DirectInboxPageV2{Version: 2, Domain: transport.DirectChannelDomainV2 + "/delivery/inbox-page", Context: b.Context, Recipient: b.Recipient, Deliveries: []transport.DirectDeliveryV2{}}
	ack := transport.DirectMessageAckV2{Version: 2, Domain: transport.DirectChannelDomainV2 + "/delivery/ack", Binding: b}
	ackReceipt := transport.DirectMessageAckReceiptV2{Version: 2, Domain: transport.DirectChannelDomainV2 + "/delivery/ack-receipt", Binding: b, DeliveryState: "acknowledged", AcknowledgedAt: "2030-01-01T00:01:01Z"}
	sender := transport.DirectSenderReceiptRequestV2{Version: 2, Domain: transport.DirectChannelDomainV2 + "/delivery/sender-receipt-request", Binding: b}
	receipt := transport.DirectSenderReceiptV2{Version: 2, Domain: transport.DirectChannelDomainV2 + "/delivery/sender-receipt", Status: "not_found", ObservedAt: "2030-01-01T00:01:00Z", ReconcileUntil: "2030-01-02T01:00:00Z"}
	marshal := func(v any) []byte {
		b, e := json.Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	envelope := struct {
		Publication       json.RawMessage `json:"publication"`
		ReadinessVerifier string          `json:"readinessVerifier"`
	}{marshal(p), secret}
	activation := Activation{ch.ChannelID, time.Date(2030, 1, 1, 0, 1, 0, 0, time.UTC), time.Date(2030, 1, 1, 1, 0, 0, 0, time.UTC)}
	peerCred := p.Descriptor.P.CredentialID + ":" + secret
	cases := []struct {
		name, method, path, credential string
		body, response                 []byte
		status                         int
		run                            func(*Client) error
	}{
		{"descriptor", "GET", "/intents/" + id + "/descriptor", cred, nil, marshal(p.Descriptor), 200, func(c *Client) error { _, e := c.Descriptor(t.Context(), cred, id); return e }},
		{"publication", "GET", "/intents/" + id + "/publication", cred, nil, marshal(p), 200, func(c *Client) error { _, e := c.Publication(t.Context(), cred, id); return e }},
		{"publish", "PUT", "/intents/" + id + "/publication", cred, marshal(envelope), marshal(p), 201, func(c *Client) error { _, e := c.Publish(t.Context(), cred, id, p, secret); return e }},
		{"challenge", "POST", "/intents/" + id + "/readiness/challenge", cred, nil, marshal(ch), 201, func(c *Client) error { _, e := c.Challenge(t.Context(), cred, id); return e }},
		{"proof", "PUT", "/intents/" + id + "/readiness/proofs/" + proof.ChallengeID, cred, marshal(proof), marshal(proof), 201, func(c *Client) error { _, e := c.Prove(t.Context(), cred, id, proof); return e }},
		{"activate", "POST", "/intents/" + id + "/activate", cred, nil, marshal(activation), 201, func(c *Client) error { _, e := c.Activate(t.Context(), cred, id); return e }},
		{"send", "POST", "/channels/" + ch.ChannelID + "/messages", cred, wire, marshal(admission), 201, func(c *Client) error { _, e := c.Send(t.Context(), cred, m); return e }},
		{"inbox", "POST", "/channels/" + ch.ChannelID + "/inbox/query", peerCred, marshal(q), marshal(page), 200, func(c *Client) error { _, e := c.Inbox(t.Context(), peerCred, q); return e }},
		{"ack", "POST", "/channels/" + ch.ChannelID + "/messages/" + b.MessageID + "/ack", peerCred, marshal(ack), marshal(ackReceipt), 200, func(c *Client) error { _, e := c.Ack(t.Context(), peerCred, ack); return e }},
		{"sender receipt", "POST", "/channels/" + ch.ChannelID + "/sender-receipt", cred, marshal(sender), marshal(receipt), 200, func(c *Client) error { _, e := c.SenderReceipt(t.Context(), cred, sender); return e }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != tc.method || r.URL.RequestURI() != prefix+tc.path {
					t.Errorf("request %s %s", r.Method, r.URL.RequestURI())
				}
				if r.Header.Get("Authorization") != "Pagnet-Direct-V2 "+tc.credential {
					t.Error("authorization mismatch")
				}
				for _, h := range []string{"Cookie", "Origin", "Forwarded", "Sec-Fetch-Site", "User-Agent"} {
					if r.Header.Get(h) != "" {
						t.Errorf("unexpected %s", h)
					}
				}
				body, _ := io.ReadAll(r.Body)
				if !bytes.Equal(body, tc.body) {
					t.Error("body mismatch")
				}
				if len(body) > 0 && r.Header.Get("Content-Type") != "application/json" {
					t.Error("content type")
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				w.Write(tc.response)
			})
			if e := tc.run(c); e != nil {
				t.Fatal(e)
			}
			bad := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				w.Write(append([]byte(" "), tc.response...))
			})
			err := tc.run(bad)
			var typed *Error
			mutation := tc.name == "publish" || tc.name == "challenge" || tc.name == "proof" || tc.name == "activate" || tc.name == "send" || tc.name == "ack"
			if !errors.As(err, &typed) || typed.Kind != Protocol || typed.UnknownCommit != mutation {
				t.Fatalf("malformed response classification: %v", err)
			}

		})
	}
}

func TestFailures(t *testing.T) {
	cred := directV2TestID(1) + ":" + directV2TestBinary(91, 32)
	for _, status := range []int{400, 401, 404, 409, 413, 503, 302} {
		for _, mutation := range []bool{false, true} {
			t.Run(http.StatusText(status)+map[bool]string{false: "/read", true: "/write"}[mutation], func(t *testing.T) {
				hits := 0
				c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
					hits++
					w.Header().Set("Location", "https://elsewhere.invalid/"+cred)
					w.WriteHeader(status)
					io.WriteString(w, cred)
				})
				_, e := c.call(t.Context(), cred, "POST", "/intents/"+directV2TestID(2)+"/activate", nil, 1024, false, mutation)
				var typed *Error
				if !errors.As(e, &typed) || typed.Status != status || strings.Contains(e.Error(), cred) || typed.UnknownCommit != (mutation && (status == 503 || status == 302)) || hits != 1 {
					t.Fatalf("classification: %v", e)
				}
			})
		}
	}
	for _, body := range []string{strings.Repeat("x", 1025), "{}"} {
		c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, body)
		})
		if _, e := c.Activate(t.Context(), cred, directV2TestID(2)); e == nil {
			t.Fatal("accepted invalid response")
		}
	}
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) { t.Error("invalid request reached server") })
	if _, e := c.Descriptor(context.Background(), cred+"=", directV2TestID(2)); e == nil {
		t.Fatal("accepted padded credential")
	}
	if c.http.Jar != nil || c.http.Transport.(*http.Transport).Proxy != nil {
		t.Fatal("ambient transport state")
	}
}
func TestOrigins(t *testing.T) {
	for _, s := range []string{"http://example.com", "https://user:pass@example.com", "https://example.com/", "https://example.com?", "https://example.com#", "https://EXAMPLE.com", "https://example.com/base"} {
		if _, e := New(s); e == nil {
			t.Errorf("accepted %s", s)
		}
	}
}

func TestAmbiguousMutationAndStreamingLimit(t *testing.T) {
	cred := directV2TestID(1) + ":" + directV2TestBinary(91, 32)
	for _, mode := range []string{"disconnect", "streamed oversize", "truncated"} {
		t.Run(mode, func(t *testing.T) {
			c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				if mode == "disconnect" {
					conn, _, e := w.(http.Hijacker).Hijack()
					if e != nil {
						t.Error(e)
						return
					}
					conn.Close()
					return
				}
				w.Header().Set("Content-Type", "application/json")
				if mode == "truncated" {
					w.Header().Set("Content-Length", "100")
					io.WriteString(w, "{")
					return
				}
				w.(http.Flusher).Flush()
				io.WriteString(w, strings.Repeat("x", 1025))
			})
			_, err := c.Activate(t.Context(), cred, directV2TestID(2))
			var typed *Error
			if !errors.As(err, &typed) || !typed.UnknownCommit || strings.Contains(err.Error(), cred) {
				t.Fatalf("unsafe ambiguous result: %v", err)
			}
		})
	}
}
