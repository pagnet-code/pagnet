package transport

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
)

func readinessTestOffer() AccountMessagingReadinessOfferPayload {
	id := domain.NewID()
	now := time.Now().UTC()
	return AccountMessagingReadinessOfferPayload{V: 1, Protocol: AccountMessagingReadinessProtocol, Route: AccountMessagingReadinessRoute{AccountMessagingReadinessCandidate: AccountMessagingReadinessCandidate{ConnectionID: id, NetworkID: id, TargetPrincipalID: id, HostID: id}, LogicalSenderID: id, Generation: 1, ConsentID: id, ResourceID: "resource", IdentityIncarnationID: domain.NewID().String(), DesiredRevision: 1, TargetDefinitionID: id, TargetInstanceID: id, RunnerID: id, RunnerConnectedAt: now, ServerInstanceID: "server", HostConnectionGeneration: 1, KeyHolderID: id, EpochID: "epoch", OfferID: id, Digest: strings.Repeat("ab", 32), OfferedAt: now, OfferDeadline: now.Add(time.Minute), ExpiresAt: now.Add(time.Hour), Status: "offered"}}
}

func TestAccountMessagingReadinessWire(t *testing.T) {
	good, _ := json.Marshal(readinessTestOffer())
	for name, raw := range map[string][]byte{
		"valid":           good,
		"duplicate":       []byte(strings.Replace(string(good), `"v":1`, `"v":1,"v":1`, 1)),
		"unknown":         []byte(strings.Replace(string(good), `"v":1`, `"v":1,"extra":true`, 1)),
		"missing":         []byte(strings.Replace(string(good), `"messagingAvailable":false`, `"extra":false`, 1)),
		"case":            []byte(strings.Replace(string(good), `"v":1`, `"V":1`, 1)),
		"null":            []byte(strings.Replace(string(good), `"generation":1`, `"generation":null`, 1)),
		"nestedDuplicate": []byte(strings.Replace(string(good), `"generation":1`, `"generation":1,"generation":1`, 1)),
		"trailing":        append(append([]byte{}, good...), []byte(` {}`)...),
		"oversize":        []byte(strings.Repeat(" ", 4097)),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseAccountMessagingReadinessOffer(raw)
			if (err == nil) != (name == "valid") {
				t.Fatalf("accepted=%v", err == nil)
			}
		})
	}
	for name, mutate := range map[string]func(*AccountMessagingReadinessRoute){
		"id":        func(r *AccountMessagingReadinessRoute) { r.HostID = "invalid" },
		"digest":    func(r *AccountMessagingReadinessRoute) { r.Digest = "abc" },
		"counter":   func(r *AccountMessagingReadinessRoute) { r.DesiredRevision = 0 },
		"deadline":  func(r *AccountMessagingReadinessRoute) { r.OfferDeadline = r.OfferedAt },
		"expiry":    func(r *AccountMessagingReadinessRoute) { r.ExpiresAt = r.OfferedAt },
		"acked":     func(r *AccountMessagingReadinessRoute) { r.AckedAt = &r.OfferedAt },
		"status":    func(r *AccountMessagingReadinessRoute) { r.Status = "ready" },
		"messaging": func(r *AccountMessagingReadinessRoute) { r.MessagingAvailable = true },
	} {
		t.Run(name, func(t *testing.T) {
			p := readinessTestOffer()
			mutate(&p.Route)
			raw, _ := json.Marshal(p)
			if _, err := ParseAccountMessagingReadinessOffer(raw); err == nil {
				t.Fatal("accepted invalid route")
			}
		})
	}
}
