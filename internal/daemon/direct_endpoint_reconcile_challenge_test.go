//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/directchannelcrypto"
	"github.com/pagnet-code/pagnet/internal/directhttp"
	"github.com/pagnet-code/pagnet/transport"
)

func TestDirectReconcileChallengeBinding(t *testing.T) {
	for _, role := range []string{"S", "P"} {
		t.Run(role, func(t *testing.T) {
			f := newReconcileMaterialFixture(t, role)
			challenge := passReadinessChallenge(f.binding, f.vector.Publication, role, f.now)
			if _, _, err := validateDirectReconcileChallengeBinding(f.binding, f.vector.Publication, role, challenge, f.now); err != nil {
				t.Fatal(err)
			}
			changes := map[string]func(*transport.DirectChannelReadinessChallengeV2){
				"domain": func(c *transport.DirectChannelReadinessChallengeV2) { c.Domain = "invalid" },
				"role": func(c *transport.DirectChannelReadinessChallengeV2) {
					if role == "S" {
						c.Role = "P"
					} else {
						c.Role = "S"
					}
				},
				"principal":  func(c *transport.DirectChannelReadinessChallengeV2) { c.PrincipalID = string(domain.NewID()) },
				"endpoint":   func(c *transport.DirectChannelReadinessChallengeV2) { c.EndpointID = string(domain.NewID()) },
				"credential": func(c *transport.DirectChannelReadinessChallengeV2) { c.CredentialID = string(domain.NewID()) },
				"intent":     func(c *transport.DirectChannelReadinessChallengeV2) { c.DirectIntentID = string(domain.NewID()) },
				"channel": func(c *transport.DirectChannelReadinessChallengeV2) {
					c.ChannelID = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
				},
				"grant":              func(c *transport.DirectChannelReadinessChallengeV2) { c.ParentGrantID = string(domain.NewID()) },
				"grant generation":   func(c *transport.DirectChannelReadinessChallengeV2) { c.GrantGeneration = "99" },
				"channel generation": func(c *transport.DirectChannelReadinessChallengeV2) { c.ChannelGeneration = "99" },
				"epoch": func(c *transport.DirectChannelReadinessChallengeV2) {
					c.EpochID = "01900000-0000-7000-8000-000000000098"
				},
				"descriptor hash": func(c *transport.DirectChannelReadinessChallengeV2) {
					c.DescriptorHash = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
				},
				"publication hash": func(c *transport.DirectChannelReadinessChallengeV2) {
					c.PublicationHash = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
				},
				"nonce": func(c *transport.DirectChannelReadinessChallengeV2) { c.Nonce = "invalid" },
				"future issued": func(c *transport.DirectChannelReadinessChallengeV2) {
					c.IssuedAt = f.now.Add(time.Second).UTC().Format(time.RFC3339Nano)
				},
				"expiry overflow": func(c *transport.DirectChannelReadinessChallengeV2) {
					expiry, _ := time.Parse(time.RFC3339Nano, f.binding.Descriptor.ExpiresAt)
					c.IssuedAt = expiry.Add(-time.Minute).Format(time.RFC3339Nano)
					c.ExpiresAt = expiry.Add(time.Second).Format(time.RFC3339Nano)
				},
			}
			for name, change := range changes {
				t.Run(name, func(t *testing.T) {
					c := challenge
					change(&c)
					if _, _, err := validateDirectReconcileChallengeBinding(f.binding, f.vector.Publication, role, c, f.now); err != errDirectEndpointReconcileBinding {
						t.Fatal("invalid challenge binding accepted")
					}
				})
			}
			if _, _, err := validateDirectReconcileChallengeBinding(f.binding, f.vector.Publication, role, challenge, f.now.Add(time.Minute)); err != nil {
				t.Fatal("historical expired challenge cannot be retained")
			}
		})
	}
}
func newReadinessPassFixture(t *testing.T, role string) *reconcilePassFixture {
	t.Helper()
	f := newReconcilePassFixture(t, role)
	if role == "S" {
		if state, err := f.run(t.Context()); err != nil || state != directReconcilePublicationPublished {
			t.Fatal("source publication setup failed")
		}
	} else {
		raw, err := os.ReadFile("../directchannelcrypto/testdata/sdk-v2.json")
		if err != nil {
			t.Fatal(err)
		}
		var vector struct{ SourcePrivate []byte }
		if json.Unmarshal(raw, &vector) != nil {
			t.Fatal("vector")
		}
		material, wire, err := directchannelcrypto.Prepare(f.binding.DescriptorBytes, f.binding.Descriptor, vector.SourcePrivate, time.Now())
		clear(vector.SourcePrivate)
		if err != nil {
			t.Fatal(err)
		}
		material.Clear()
		f.client.publication, err = transport.DecodeDirectChannelPublicationV2(wire)
		if err != nil {
			t.Fatal(err)
		}
		f.client.enrollment = publishedEnrollment(f.client.enrollment, wire)
	}
	f.client.calls = nil
	return f
}
func setReadinessGET(t *testing.T, f *reconcilePassFixture, challenge transport.DirectChannelReadinessChallengeV2) {
	t.Helper()
	raw, err := challenge.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(raw)
	f.client.enrollment.Challenge = &directhttp.EnrollmentChallenge{Challenge: challenge, TranscriptHash: base64.RawURLEncoding.EncodeToString(hash[:])}
	f.client.enrollment.ObservedAt = time.Now()
}
func TestDirectReconcileChallengeRequestAndObserve(t *testing.T) {
	for _, role := range []string{"S", "P"} {
		t.Run(role, func(t *testing.T) {
			f := newReadinessPassFixture(t, role)
			publishes := len(f.client.publications)
			state, err := f.run(t.Context())
			if err != nil || state != directReconcileChallengeRequested || len(f.client.challenges) != 1 || len(f.client.publications) != publishes {
				t.Fatalf("challenge request: %s %v", state, err)
			}
			row, err := readPassJournal(f.f.d.nativeRegistry)
			if err != nil {
				t.Fatal(err)
			}
			clear(row.Root)
			if len(row.Challenge) != 0 || len(row.Proof) != 0 || len(row.Activation) != 0 {
				t.Fatal("POST response was ingested or proof advanced")
			}
			state, err = f.run(t.Context())
			if err != nil || state != directReconcileChallengeObserved || len(f.client.challenges) != 1 {
				t.Fatalf("challenge observation: %s %v", state, err)
			}
			row, err = readPassJournal(f.f.d.nativeRegistry)
			if err != nil {
				t.Fatal(err)
			}
			clear(row.Root)
			if !bytes.Equal(row.Challenge, f.client.challenges[0]) || len(row.Proof) != 0 || len(row.Activation) != 0 {
				t.Fatal("challenge observation changed bytes or advanced proof")
			}
		})
	}
}
func TestDirectReconcileChallengeGETValidation(t *testing.T) {
	for _, role := range []string{"S", "P"} {
		t.Run(role, func(t *testing.T) {
			for _, kind := range []string{"transcript", "party", "future", "nil proof", "nil activation", "404"} {
				t.Run(kind, func(t *testing.T) {
					f := newReadinessPassFixture(t, role)
					wire, _ := f.client.publication.CanonicalBytes()
					challenge := passReadinessChallenge(f.binding, wire, role, time.Now().Add(-time.Second))
					setReadinessGET(t, f, challenge)
					switch kind {
					case "transcript":
						f.client.enrollment.Challenge.TranscriptHash = "invalid"
					case "party":
						challenge.EndpointID = string(domain.NewID())
						setReadinessGET(t, f, challenge)
					case "future":
						challenge.IssuedAt = time.Now().Add(time.Second).UTC().Format(time.RFC3339Nano)
						setReadinessGET(t, f, challenge)
					case "nil proof":
						f.client.enrollment.Challenge = nil
						f.client.enrollment.Proof = &directhttp.EnrollmentProof{}
					case "nil activation":
						f.client.enrollment.Challenge = nil
						f.client.enrollment.Activation = &directhttp.EnrollmentActivation{}
					case "404":
						f.client.fail = "enrollment"
						f.client.reconcileObservationReader.failure = &directhttp.Error{Kind: directhttp.Unavailable, Status: 404}
					}
					state, err := f.run(t.Context())
					if err == nil || state != "" || len(f.client.challenges) != 0 {
						t.Fatal("invalid GET evidence authorized a challenge")
					}
				})
			}
		})
	}
}
func TestDirectReconcileChallengeImmutableAndExpired(t *testing.T) {
	for _, role := range []string{"S", "P"} {
		t.Run(role, func(t *testing.T) {
			for _, kind := range []string{"changed", "disappeared", "expired"} {
				t.Run(kind, func(t *testing.T) {
					f := newReadinessPassFixture(t, role)
					wire, _ := f.client.publication.CanonicalBytes()
					challenge := passReadinessChallenge(f.binding, wire, role, time.Now().Add(-time.Second))
					if kind == "expired" {
						challenge.IssuedAt = time.Now().Add(-2 * time.Second).UTC().Format(time.RFC3339Nano)
						challenge.ExpiresAt = time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano)
					}
					setReadinessGET(t, f, challenge)
					original, _ := challenge.CanonicalBytes()
					state, err := f.run(t.Context())
					if kind == "expired" {
						if err != errDirectEndpointReconcileChallengeExpired || state != "" {
							t.Fatal("expired GET challenge was accepted")
						}
					} else if err != nil || state != directReconcileChallengeObserved {
						t.Fatal("challenge setup not observed")
					}
					if kind == "changed" {
						challenge.ChallengeID = string(domain.NewID())
						setReadinessGET(t, f, challenge)
					} else {
						f.client.enrollment.Challenge = nil
					}
					state, err = f.run(t.Context())
					if err == nil || state != "" || len(f.client.challenges) != 0 {
						t.Fatal("immutable challenge changed or renewed")
					}
					row, err := readPassJournal(f.f.d.nativeRegistry)
					if err != nil {
						t.Fatal(err)
					}
					clear(row.Root)
					if !bytes.Equal(row.Challenge, original) {
						t.Fatal("failed recovery changed immutable challenge")
					}
				})
			}
		})
	}
}
func TestDirectReconcileChallengeUnknownHTTP(t *testing.T) {
	for _, role := range []string{"S", "P"} {
		t.Run(role, func(t *testing.T) {
			for _, accepted := range []bool{false, true} {
				t.Run(map[bool]string{false: "not accepted", true: "accepted"}[accepted], func(t *testing.T) {
					f := newReadinessPassFixture(t, role)
					f.client.rejectChallenge = !accepted
					f.client.challengeErr = &directhttp.Error{Kind: directhttp.Transport, UnknownCommit: true}
					state, err := f.run(t.Context())
					var mutation *directhttp.Error
					if state != "" || !errors.As(err, &mutation) || !mutation.UnknownCommit || len(f.client.challenges) != 1 {
						t.Fatal("challenge uncertainty lost")
					}
					f.client.rejectChallenge = false
					f.client.challengeErr = nil
					state, err = f.run(t.Context())
					if err != nil {
						t.Fatal(err)
					}
					if accepted {
						if state != directReconcileChallengeObserved || len(f.client.challenges) != 1 {
							t.Fatal("existing challenge renewed after lost response")
						}
					} else if state != directReconcileChallengeRequested || len(f.client.challenges) != 2 {
						t.Fatal("confirmed absence did not recover request fence")
					}
				})
			}
		})
	}
}
func TestDirectReconcileChallengeUnknownCommit(t *testing.T) {
	for _, role := range []string{"S", "P"} {
		t.Run(role, func(t *testing.T) {
			for _, committed := range []bool{false, true} {
				t.Run(map[bool]string{false: "rollback", true: "commit"}[committed], func(t *testing.T) {
					f := newReadinessPassFixture(t, role)
					journal, err := newDirectEnrollmentJournal(f.f.d.nativeRegistry)
					if err != nil {
						t.Fatal(err)
					}
					connector := enrollmentContextWrap(t, journal)
					pending, injected := false, false
					connector.exec = func(ctx context.Context, query string, args []driver.NamedValue, next driver.ExecerContext) (driver.Result, error) {
						if strings.HasPrefix(query, "INSERT INTO native_direct_enrollment_v1 VALUES") {
							var row directEnrollmentRecord
							if json.Unmarshal(args[3].Value.([]byte), &row) == nil {
								pending = row.Attempts["challenge"].Count > row.Attempts["challenge"].Recovered
							}
							clear(row.Root)
						}
						if query == "COMMIT" && pending && !injected {
							injected = true
							if committed {
								if _, err := next.ExecContext(ctx, query, args); err != nil {
									return nil, err
								}
							}
							return nil, errors.New("lost challenge dispatch acknowledgement")
						}
						return next.ExecContext(ctx, query, args)
					}
					state, err := f.run(t.Context())
					connector.exec = nil
					if err == nil || state != "" || !injected || len(f.client.challenges) != 0 {
						t.Fatal("uncertain challenge COMMIT reached HTTP")
					}
					state, err = f.run(t.Context())
					if err != nil || state != directReconcileChallengeRequested || len(f.client.challenges) != 1 {
						t.Fatal("fresh GET did not recover challenge fence")
					}
				})
			}
		})
	}
}
func TestDirectReconcileChallengeMutationAcceptance(t *testing.T) {
	for _, role := range []string{"S", "P"} {
		t.Run(role, func(t *testing.T) {
			for _, kind := range []string{"response mismatch", "expired response", "known rollback", "cancel", "abort"} {
				t.Run(kind, func(t *testing.T) {
					f := newReadinessPassFixture(t, role)
					ctx, cancel := context.WithCancel(t.Context())
					defer cancel()
					f.client.rejectChallenge = true
					switch kind {
					case "response mismatch":
						f.client.challengeResponse = func(c transport.DirectChannelReadinessChallengeV2) transport.DirectChannelReadinessChallengeV2 {
							c.CredentialID = string(domain.NewID())
							return c
						}
					case "expired response":
						f.client.challengeResponse = func(c transport.DirectChannelReadinessChallengeV2) transport.DirectChannelReadinessChallengeV2 {
							c.IssuedAt = time.Now().Add(-2 * time.Second).UTC().Format(time.RFC3339Nano)
							c.ExpiresAt = time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano)
							return c
						}
					case "known rollback":
						f.client.challengeErr = &directhttp.Error{Kind: directhttp.Conflict, Status: 409, UnknownCommit: false}
					case "cancel":
						f.client.onChallenge = func(context.Context) { cancel() }
						f.client.challengeErr = &directhttp.Error{Kind: directhttp.Conflict, Status: 409}
					case "abort":
						f.client.onChallenge = func(context.Context) { f.f.token.proxy.abort() }
						f.client.challengeErr = &directhttp.Error{Kind: directhttp.Conflict, Status: 409}
					}
					state, err := f.run(ctx)
					if state != "" || len(f.client.challenges) != 1 {
						t.Fatal("challenge mutation did not end pass")
					}
					var mutation *directhttp.Error
					switch kind {
					case "response mismatch", "expired response":
						if !errors.As(err, &mutation) || mutation.Kind != directhttp.Protocol || !mutation.UnknownCommit {
							t.Fatal("invalid POST challenge was accepted")
						}
					case "known rollback":
						if !errors.As(err, &mutation) || mutation.UnknownCommit {
							t.Fatal("known rollback classification changed")
						}
					default:
						if err != errDirectEndpointOperationUnknown || errors.As(err, &mutation) {
							t.Fatal("lease uncertainty exposed known rollback")
						}
					}
				})
			}
		})
	}
}

func TestDirectReconcileChallengeExpiryDuringCommit(t *testing.T) {
	for _, role := range []string{"S", "P"} {
		t.Run(role, func(t *testing.T) {
			f := newReadinessPassFixture(t, role)
			expires, _ := time.Parse(time.RFC3339Nano, f.binding.Descriptor.ExpiresAt)
			var expired atomic.Bool
			now := func() time.Time {
				if expired.Load() {
					return expires.Add(time.Nanosecond)
				}
				return time.Now()
			}
			var err error
			if role == "S" {
				f.run, err = newDirectSourceReconcilePassWithClient(f.f.d, f.f.captured, f.f.s, f.f.source, f.client, now)
			} else {
				f.run, err = newDirectTargetReconcilePassWithClient(f.f.d, f.f.captured, f.f.s, f.f.target, f.client, now)
			}
			if err != nil {
				t.Fatal(err)
			}
			journal, err := newDirectEnrollmentJournal(f.f.d.nativeRegistry)
			if err != nil {
				t.Fatal(err)
			}
			connector := enrollmentContextWrap(t, journal)
			entered, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			defer unblock()
			pending, blocked := false, false
			connector.exec = func(ctx context.Context, query string, args []driver.NamedValue, next driver.ExecerContext) (driver.Result, error) {
				if strings.HasPrefix(query, "INSERT INTO native_direct_enrollment_v1 VALUES") {
					var row directEnrollmentRecord
					if json.Unmarshal(args[3].Value.([]byte), &row) == nil {
						pending = row.Attempts["challenge"].Count > row.Attempts["challenge"].Recovered
					}
					clear(row.Root)
				}
				if query == "COMMIT" && pending && !blocked {
					blocked = true
					close(entered)
					<-release
				}
				return next.ExecContext(ctx, query, args)
			}
			type passResult struct {
				state directEndpointReconcilePassState
				err   error
			}
			finished := make(chan passResult, 1)
			go func() { state, err := f.run(t.Context()); finished <- passResult{state, err} }()
			select {
			case <-entered:
			case result := <-finished:
				connector.exec = nil
				t.Fatalf("dispatch fence missing: %s %v", result.state, result.err)
			case <-time.After(10 * time.Second):
				t.Fatal("challenge dispatch fence not reached")
			}
			expired.Store(true)
			unblock()
			result := <-finished
			connector.exec = nil
			if result.err == nil || result.state != "" || len(f.client.challenges) != 0 {
				t.Fatal("expired descriptor reached challenge POST")
			}
			row, err := readPassJournal(f.f.d.nativeRegistry)
			if err != nil {
				t.Fatal(err)
			}
			clear(row.Root)
			if row.Attempts["challenge"].Count != 1 || len(row.Challenge) != 0 || len(row.Proof) != 0 {
				t.Fatal("expired dispatch attempt not retained for fresh GET")
			}
		})
	}
}
func TestDirectReconcileChallengeConcurrency(t *testing.T) {
	for _, role := range []string{"S", "P"} {
		t.Run(role, func(t *testing.T) {
			f := newReadinessPassFixture(t, role)
			entered, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			defer unblock()
			var reentrant error
			f.client.onChallenge = func(ctx context.Context) { _, reentrant = f.run(ctx); close(entered); <-release }
			type passResult struct {
				state directEndpointReconcilePassState
				err   error
			}
			finished := make(chan passResult, 1)
			go func() { state, err := f.run(t.Context()); finished <- passResult{state, err} }()
			select {
			case <-entered:
			case result := <-finished:
				t.Fatalf("challenge missing: %s %v", result.state, result.err)
			case <-time.After(10 * time.Second):
				t.Fatal("challenge POST not reached")
			}
			if state, err := f.run(t.Context()); state != "" || err != errDirectEndpointLocalBusy {
				t.Error("concurrent challenge pass bypassed gate")
			}
			unblock()
			result := <-finished
			if result.err != nil || result.state != directReconcileChallengeRequested || reentrant != errDirectEndpointLocalBusy || len(f.client.challenges) != 1 {
				t.Fatal("challenge gate or single-mutation boundary failed")
			}
		})
	}
}
