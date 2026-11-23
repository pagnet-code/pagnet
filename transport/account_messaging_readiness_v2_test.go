package transport

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
)

func readinessSubscriptionTestFrame() AccountMessagingReadinessSubscriptionFrame {
	return AccountMessagingReadinessSubscriptionFrame{V: 2, Protocol: AccountMessagingReadinessSubscriptionProtocol, SubscriptionID: domain.ID("12345678-abcd-4321-8765-123456789abc"), Version: "1"}
}

func TestAccountMessagingReadinessSubscriptionWire(t *testing.T) {
	frame := readinessSubscriptionTestFrame()
	route := readinessTestOffer().Route
	ready := route
	ackedAt := route.OfferedAt.Add(time.Second)
	ready.Status, ready.AckedAt = "ready", &ackedAt
	for name, test := range map[string]struct {
		payload any
		parse   func([]byte) error
	}{
		"reset": {AccountMessagingReadinessSubscriptionResetPayload{frame, "initial"}, func(raw []byte) error {
			_, err := ParseAccountMessagingReadinessSubscriptionReset(raw)
			return err
		}},
		"offer": {AccountMessagingReadinessSubscriptionOfferPayload{frame, route}, func(raw []byte) error {
			_, err := ParseAccountMessagingReadinessSubscriptionOffer(raw)
			return err
		}},
		"complete": {AccountMessagingReadinessSubscriptionCompletePayload{frame, 1, "complete"}, func(raw []byte) error {
			_, err := ParseAccountMessagingReadinessSubscriptionComplete(raw)
			return err
		}},
		"accepted": {AccountMessagingReadinessSubscriptionAcceptedPayload{frame, ready}, func(raw []byte) error {
			_, err := ParseAccountMessagingReadinessSubscriptionAccepted(raw)
			return err
		}},
	} {
		t.Run(name, func(t *testing.T) {
			good, err := json.Marshal(test.payload)
			if err != nil {
				t.Fatal(err)
			}
			if err := test.parse(good); err != nil {
				t.Fatal(err)
			}
			for label, replacement := range map[string]string{
				"zeroVersion": `"version":"0"`, "leadingZero": `"version":"01"`,
				"signedVersion": `"version":"+1"`, "overflow": `"version":"18446744073709551616"`,
				"numericVersion": `"version":1`, "nullVersion": `"version":null`,
				"missingVersion": `"extra":"1"`, "caseVersion": `"Version":"1"`,
				"duplicateVersion": `"version":"1","version":"1"`,
			} {
				t.Run(label, func(t *testing.T) {
					raw := []byte(strings.Replace(string(good), `"version":"1"`, replacement, 1))
					if test.parse(raw) == nil {
						t.Fatal("accepted invalid frame")
					}
				})
			}
			for label, raw := range map[string][]byte{
				"wrongV":        []byte(strings.Replace(string(good), `"v":2`, `"v":1`, 1)),
				"wrongProtocol": []byte(strings.Replace(string(good), AccountMessagingReadinessSubscriptionProtocol, AccountMessagingReadinessProtocol, 1)),
				"invalidID":     []byte(strings.Replace(string(good), frame.SubscriptionID.String(), "invalid", 1)),
				"uppercaseID":   []byte(strings.Replace(string(good), frame.SubscriptionID.String(), strings.ToUpper(frame.SubscriptionID.String()), 1)),
				"unknown":       []byte(strings.Replace(string(good), `"v":2`, `"v":2,"extra":false`, 1)),
				"trailing":      append(append([]byte{}, good...), []byte(` {}`)...),
				"oversize":      append(append([]byte{}, good...), []byte(strings.Repeat(" ", AccountMessagingReadinessMaxPayload))...),
			} {
				t.Run(label, func(t *testing.T) {
					if test.parse(raw) == nil {
						t.Fatal("accepted invalid frame")
					}
				})
			}
			max := []byte(strings.Replace(string(good), `"version":"1"`, `"version":"18446744073709551615"`, 1))
			if err := test.parse(max); err != nil {
				t.Fatalf("rejected max uint64 version: %v", err)
			}
			padded := append(append([]byte{}, good...), []byte(strings.Repeat(" ", AccountMessagingReadinessMaxPayload-len(good)))...)
			if err := test.parse(padded); err != nil {
				t.Fatalf("rejected 4096-byte payload: %v", err)
			}
		})
	}
}

func TestAccountMessagingReadinessSubscriptionResetReasons(t *testing.T) {
	for _, reason := range []string{"initial", "changed", "client_reset", "expired", "", "other"} {
		raw, _ := json.Marshal(AccountMessagingReadinessSubscriptionResetPayload{readinessSubscriptionTestFrame(), reason})
		_, err := ParseAccountMessagingReadinessSubscriptionReset(raw)
		if (err == nil) != (reason != "" && reason != "other") {
			t.Fatalf("reason %q: %v", reason, err)
		}
	}
}

func TestAccountMessagingReadinessSubscriptionCompleteBounds(t *testing.T) {
	for _, status := range []string{"complete", "capacity_exceeded", "other", ""} {
		for _, count := range []int{-1, 0, 1, 256, 257} {
			raw, _ := json.Marshal(AccountMessagingReadinessSubscriptionCompletePayload{readinessSubscriptionTestFrame(), count, status})
			_, err := ParseAccountMessagingReadinessSubscriptionComplete(raw)
			valid := (status == "complete" && count >= 0 && count <= 256) || (status == "capacity_exceeded" && count == 0)
			if (err == nil) != valid {
				t.Fatalf("status %q count %d: %v", status, count, err)
			}
		}
	}
}

func TestAccountMessagingReadinessSubscriptionRoutes(t *testing.T) {
	for _, accepted := range []bool{false, true} {
		for name, mutate := range map[string]func(*AccountMessagingReadinessRoute){
			"id":       func(r *AccountMessagingReadinessRoute) { r.HostID = "invalid" },
			"digest":   func(r *AccountMessagingReadinessRoute) { r.Digest = "abc" },
			"counter":  func(r *AccountMessagingReadinessRoute) { r.DesiredRevision = 0 },
			"deadline": func(r *AccountMessagingReadinessRoute) { r.OfferDeadline = r.OfferedAt },
			"expiry":   func(r *AccountMessagingReadinessRoute) { r.ExpiresAt = r.OfferedAt },
			"acked": func(r *AccountMessagingReadinessRoute) {
				if accepted {
					r.AckedAt = nil
				} else {
					r.AckedAt = &r.OfferedAt
				}
			},
			"status":    func(r *AccountMessagingReadinessRoute) { r.Status = "other" },
			"messaging": func(r *AccountMessagingReadinessRoute) { r.MessagingAvailable = true },
		} {
			route := readinessTestOffer().Route
			if accepted {
				route.Status, route.AckedAt = "ready", &route.OfferedAt
			}
			mutate(&route)
			var err error
			if accepted {
				raw, _ := json.Marshal(AccountMessagingReadinessSubscriptionAcceptedPayload{readinessSubscriptionTestFrame(), route})
				_, err = ParseAccountMessagingReadinessSubscriptionAccepted(raw)
			} else {
				raw, _ := json.Marshal(AccountMessagingReadinessSubscriptionOfferPayload{readinessSubscriptionTestFrame(), route})
				_, err = ParseAccountMessagingReadinessSubscriptionOffer(raw)
			}
			if err == nil {
				t.Fatalf("accepted=%v mutation=%s accepted invalid route", accepted, name)
			}
		}
	}
	good, _ := json.Marshal(AccountMessagingReadinessSubscriptionOfferPayload{readinessSubscriptionTestFrame(), readinessTestOffer().Route})
	for _, replacement := range []string{`"generation":1,"generation":1`, `"Generation":1`, `"generation":null`, `"extra":1`} {
		raw := []byte(strings.Replace(string(good), `"generation":1`, replacement, 1))
		if _, err := ParseAccountMessagingReadinessSubscriptionOffer(raw); err == nil {
			t.Fatalf("accepted nested %s", replacement)
		}
	}
}
