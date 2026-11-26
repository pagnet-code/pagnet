//go:build linux || darwin

package daemon

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/internal/directhttp"
	"github.com/pagnet-code/pagnet/transport"
)

func TestDirectReconcileEnrollmentReadiness(t *testing.T) {
	for index, role := range []string{"S", "P"} {
		t.Run(role, func(t *testing.T) {
			f := newReconcileMaterialFixture(t, role)
			challenge, err := transport.DecodeDirectChannelReadinessChallengeV2(f.vector.Challenges[index])
			if err != nil {
				t.Fatal(err)
			}
			transcript := sha256.Sum256(f.vector.Challenges[index])
			proofDigest := sha256.Sum256(f.vector.Proofs[index])
			expires, _ := time.Parse(time.RFC3339Nano, challenge.ExpiresAt)
			now := f.now.Add(2 * time.Second)
			fresh := func() directhttp.Enrollment {
				e := publishedEnrollment(f.enrollment, f.vector.Publication)
				e.ObservedAt = now
				e.Challenge = &directhttp.EnrollmentChallenge{Challenge: challenge, TranscriptHash: base64.RawURLEncoding.EncodeToString(transcript[:])}
				e.Proof = &directhttp.EnrollmentProof{Digest: base64.RawURLEncoding.EncodeToString(proofDigest[:]), ReceivedAt: f.now.Add(time.Second)}
				e.Activation = &directhttp.EnrollmentActivation{ActivatedAt: now, ExpiresAt: e.Authority.ExpiresAt}
				return e
			}
			for _, state := range []string{"absent", "challenge", "proof", "activation", "historical proof", "historical challenge"} {
				t.Run(state, func(t *testing.T) {
					e := fresh()
					at := now
					switch state {
					case "absent":
						e.PublicationHash, e.Challenge, e.Proof, e.Activation = nil, nil, nil, nil
					case "challenge":
						e.Proof, e.Activation = nil, nil
					case "proof":
						e.Activation = nil
					case "historical proof", "historical challenge":
						at = expires.Add(time.Second)
						e.ObservedAt = at
						e.Activation = nil
						if state == "historical challenge" {
							e.Proof = nil
						}
					}
					raw, expiry, err := validateDirectReconcileEnrollmentReadiness(f.binding, f.vector.Publication, role, e, at)
					if err != nil {
						t.Fatal(err)
					}
					if state == "absent" {
						if raw != nil || !expiry.IsZero() {
							t.Fatal("absent challenge returned evidence")
						}
					} else if !bytes.Equal(raw, f.vector.Challenges[index]) || !expiry.Equal(expires) {
						t.Fatal("challenge evidence changed")
					}
				})
			}
			changes := map[string]func(*directhttp.Enrollment){
				"descriptor hash":              func(e *directhttp.Enrollment) { e.DescriptorHash += "=" },
				"authority grant":              func(e *directhttp.Enrollment) { e.Authority.ParentGrantID = "invalid" },
				"authority grant generation":   func(e *directhttp.Enrollment) { e.Authority.GrantGeneration = "99" },
				"authority channel":            func(e *directhttp.Enrollment) { e.Authority.ChannelID = "invalid" },
				"authority channel generation": func(e *directhttp.Enrollment) { e.Authority.ChannelGeneration = "99" },
				"authority epoch":              func(e *directhttp.Enrollment) { e.Authority.EpochID = "invalid" },
				"authority expiry":             func(e *directhttp.Enrollment) { e.Authority.ExpiresAt = e.Authority.ExpiresAt.Add(time.Second) },
				"observation zero":             func(e *directhttp.Enrollment) { e.ObservedAt = time.Time{} },
				"observation future":           func(e *directhttp.Enrollment) { e.ObservedAt = now.Add(time.Second) },
				"observation offset":           func(e *directhttp.Enrollment) { e.ObservedAt = now.In(time.FixedZone("offset", 3600)) },
				"observation year zero":        func(e *directhttp.Enrollment) { e.ObservedAt = time.Date(0, 1, 1, 0, 0, 0, 0, time.UTC) },
				"observation expired":          func(e *directhttp.Enrollment) { e.ObservedAt = e.Authority.ExpiresAt },
				"publication absent":           func(e *directhttp.Enrollment) { e.PublicationHash = nil },
				"publication hash":             func(e *directhttp.Enrollment) { h := strings.Repeat("A", 43); e.PublicationHash = &h },
				"publication encoding":         func(e *directhttp.Enrollment) { h := *e.PublicationHash + "="; e.PublicationHash = &h },
				"transcript hash":              func(e *directhttp.Enrollment) { e.Challenge.TranscriptHash = strings.Repeat("A", 43) },
				"transcript encoding":          func(e *directhttp.Enrollment) { e.Challenge.TranscriptHash += "=" },
				"challenge role":               func(e *directhttp.Enrollment) { e.Challenge.Challenge.Role = "invalid" },
				"challenge descriptor":         func(e *directhttp.Enrollment) { e.Challenge.Challenge.DescriptorHash = strings.Repeat("A", 43) },
				"challenge issued future": func(e *directhttp.Enrollment) {
					e.Challenge.Challenge.IssuedAt = now.Add(time.Second).Format(time.RFC3339Nano)
				},
				"challenge time encoding": func(e *directhttp.Enrollment) {
					e.Challenge.Challenge.IssuedAt = f.now.Format("2006-01-02T15:04:05+00:00")
				},
				"proof without challenge":      func(e *directhttp.Enrollment) { e.Challenge = nil; e.Activation = nil },
				"activation without challenge": func(e *directhttp.Enrollment) { e.Challenge, e.Proof = nil, nil },
				"activation without proof":     func(e *directhttp.Enrollment) { e.Proof = nil },
				"digest absent":                func(e *directhttp.Enrollment) { e.Proof.Digest = "" },
				"digest padded":                func(e *directhttp.Enrollment) { e.Proof.Digest += "=" },
				"digest short":                 func(e *directhttp.Enrollment) { e.Proof.Digest = strings.Repeat("A", 42) },
				"digest long":                  func(e *directhttp.Enrollment) { e.Proof.Digest = strings.Repeat("A", 44) },
				"digest pad bits":              func(e *directhttp.Enrollment) { e.Proof.Digest = strings.Repeat("A", 42) + "B" },
				"digest newline":               func(e *directhttp.Enrollment) { e.Proof.Digest += "\n" },
				"receipt zero":                 func(e *directhttp.Enrollment) { e.Proof.ReceivedAt = time.Time{} },
				"receipt before issuance":      func(e *directhttp.Enrollment) { e.Proof.ReceivedAt = f.now.Add(-time.Nanosecond) },
				"receipt expired":              func(e *directhttp.Enrollment) { e.Proof.ReceivedAt = expires },
				"receipt after observation":    func(e *directhttp.Enrollment) { e.Proof.ReceivedAt = now.Add(time.Nanosecond) },
				"receipt offset": func(e *directhttp.Enrollment) {
					e.Proof.ReceivedAt = e.Proof.ReceivedAt.In(time.FixedZone("offset", -3600))
				},
				"receipt year zero":            func(e *directhttp.Enrollment) { e.Proof.ReceivedAt = time.Date(0, 1, 1, 0, 0, 0, 0, time.UTC) },
				"receipt year overflow":        func(e *directhttp.Enrollment) { e.Proof.ReceivedAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) },
				"activation zero":              func(e *directhttp.Enrollment) { e.Activation.ActivatedAt = time.Time{} },
				"activation before receipt":    func(e *directhttp.Enrollment) { e.Activation.ActivatedAt = f.now },
				"activation after observation": func(e *directhttp.Enrollment) { e.Activation.ActivatedAt = now.Add(time.Nanosecond) },
				"activation offset":            func(e *directhttp.Enrollment) { e.Activation.ActivatedAt = now.In(time.FixedZone("offset", 3600)) },
				"activation expiry zero":       func(e *directhttp.Enrollment) { e.Activation.ExpiresAt = time.Time{} },
				"activation expiry offset": func(e *directhttp.Enrollment) {
					e.Activation.ExpiresAt = e.Authority.ExpiresAt.In(time.FixedZone("offset", 3600))
				},
				"activation expiry mismatch": func(e *directhttp.Enrollment) { e.Activation.ExpiresAt = e.Authority.ExpiresAt.Add(-time.Second) },
				"activation expiry elapsed":  func(e *directhttp.Enrollment) { e.Activation.ExpiresAt = e.Activation.ActivatedAt },
			}
			for name, change := range changes {
				t.Run(name, func(t *testing.T) {
					e := fresh()
					change(&e)
					raw, expiry, err := validateDirectReconcileEnrollmentReadiness(f.binding, f.vector.Publication, role, e, now)
					if err != errDirectEndpointReconcileBinding || raw != nil || !expiry.IsZero() {
						t.Fatalf("invalid enrollment accepted: %v", err)
					}
				})
			}
		})
	}
}
