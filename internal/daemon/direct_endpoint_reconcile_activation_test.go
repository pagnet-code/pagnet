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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/internal/directhttp"
)

func newActivationPassFixture(t *testing.T, role string) *reconcilePassFixture {
	t.Helper()
	f := newProofPassFixture(t, role)
	if state, err := f.run(t.Context()); err != nil || state != directReconcileProofSubmitted {
		t.Fatal("activation proof setup failed")
	}
	f.client.calls = nil
	return f
}
func setActivationGET(f *reconcilePassFixture, value directhttp.Activation) {
	f.client.enrollment.Activation = &directhttp.EnrollmentActivation{ActivatedAt: value.ActivatedAt, ExpiresAt: value.ExpiresAt}
	f.client.enrollment.ObservedAt = time.Now().UTC()
}
func TestDirectReconcileActivationRequestAndObserve(t *testing.T) {
	for _, role := range []string{"S", "P"} {
		t.Run(role, func(t *testing.T) {
			f := newActivationPassFixture(t, role)
			state, err := f.run(t.Context())
			if err != nil || state != directReconcileActivationRequested || len(f.client.activations) != 1 || len(f.client.proofs) != 1 {
				t.Fatalf("activation request: %s %v", state, err)
			}
			if !reflectActivationCalls(f.client.calls, []string{"descriptor", "enrollment", "publication", "activate"}) {
				t.Fatal("activation did not end pass after one POST")
			}
			row, err := readPassJournal(f.f.d.nativeRegistry)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(row.Root)
			if row.ProofReceivedAt == "" || len(row.Activation) != 0 {
				t.Fatal("POST response was observed or proof receipt not committed")
			}
			state, err = f.run(t.Context())
			if err != nil || state != directReconcileActivationObserved || len(f.client.activations) != 1 || len(f.client.proofs) != 1 {
				t.Fatalf("activation observation: %s %v", state, err)
			}
			observed, err := readPassJournal(f.f.d.nativeRegistry)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(observed.Root)
			var activation directEnrollmentActivation
			if json.Unmarshal(observed.Activation, &activation) != nil || activation.ChannelID != f.client.activations[0].ChannelID || activation.ActivatedAt != f.client.activations[0].ActivatedAt.UTC().Format(time.RFC3339Nano) || activation.ExpiresAt != f.client.activations[0].ExpiresAt.UTC().Format(time.RFC3339Nano) || !bytes.Equal(row.Root, observed.Root) || !bytes.Equal(row.Proof, observed.Proof) {
				t.Fatal("activation observation changed exact retained evidence")
			}
		})
	}
}
func reflectActivationCalls(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func TestDirectReconcileActivationHistoricalReceipt(t *testing.T) {
	for _, role := range []string{"S", "P"} {
		t.Run(role, func(t *testing.T) {
			for _, receipt := range []bool{false, true} {
				t.Run(map[bool]string{false: "without receipt", true: "with receipt"}[receipt], func(t *testing.T) {
					f := newProofPassFixture(t, role)
					publication, _ := f.client.publication.CanonicalBytes()
					issued := f.f.source.IssuedAt
					if role == "P" {
						issued = f.f.target.IssuedAt
					}
					challenge := passReadinessChallenge(f.binding, publication, role, issued.Add(time.Nanosecond))
					received := issued.Add(2 * time.Nanosecond)
					challenge.ExpiresAt = issued.Add(3 * time.Nanosecond).UTC().Format(time.RFC3339Nano)
					proof := seedRetainedProof(t, f, challenge, received)
					if receipt {
						digest := sha256.Sum256(proof)
						f.client.enrollment.Proof = &directhttp.EnrollmentProof{Digest: base64.RawURLEncoding.EncodeToString(digest[:]), ReceivedAt: received}
					}
					f.client.enrollment.ObservedAt = time.Now().UTC()
					state, err := f.run(t.Context())
					if receipt {
						if err != nil || state != directReconcileActivationRequested || len(f.client.activations) != 1 {
							t.Fatalf("historical receipt activation: %s %v", state, err)
						}
					} else if err != errDirectEndpointReconcileChallengeExpired || state != "" || len(f.client.activations) != 0 {
						t.Fatal("expired challenge without receipt activated")
					}
					if len(f.client.proofs) != 0 || len(f.client.challenges) != 0 {
						t.Fatal("activation regenerated expired readiness evidence")
					}
				})
			}
		})
	}
}
func TestDirectReconcileActivationGETValidation(t *testing.T) {
	for _, role := range []string{"S", "P"} {
		t.Run(role, func(t *testing.T) {
			for _, kind := range []string{"valid", "channel", "before receipt", "future", "expiry", "receipt", "missing proof", "missing challenge", "offset"} {
				t.Run(kind, func(t *testing.T) {
					f := newActivationPassFixture(t, role)
					value := directhttp.Activation{ChannelID: f.client.enrollment.Authority.ChannelID, ActivatedAt: f.client.enrollment.Proof.ReceivedAt, ExpiresAt: f.client.enrollment.Authority.ExpiresAt}
					switch kind {
					case "channel":
						f.client.enrollment.Authority.ChannelID = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32))
					case "before receipt":
						value.ActivatedAt = value.ActivatedAt.Add(-time.Nanosecond)
					case "future":
						value.ActivatedAt = time.Now().UTC().Add(time.Hour)
					case "expiry":
						value.ExpiresAt = value.ExpiresAt.Add(time.Second)
					case "receipt":
						f.client.enrollment.Proof.Digest = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32))
					case "missing proof":
						f.client.enrollment.Proof = nil
					case "missing challenge":
						f.client.enrollment.Challenge = nil
					case "offset":
						value.ActivatedAt = value.ActivatedAt.In(time.FixedZone("offset", 3600))
					}
					setActivationGET(f, value)
					state, err := f.run(t.Context())
					if kind == "valid" {
						if err != nil || state != directReconcileActivationObserved {
							t.Fatal("valid authenticated activation rejected")
						}
					} else if err == nil || state != "" {
						t.Fatal("invalid authenticated activation accepted")
					}
					if len(f.client.activations) != 0 {
						t.Fatal("GET activation validation sent POST")
					}
				})
			}
		})
	}
}
func TestDirectReconcileActivationImmutable(t *testing.T) {
	for _, role := range []string{"S", "P"} {
		t.Run(role, func(t *testing.T) {
			for _, kind := range []string{"changed", "disappeared"} {
				t.Run(kind, func(t *testing.T) {
					f := newActivationPassFixture(t, role)
					if state, err := f.run(t.Context()); err != nil || state != directReconcileActivationRequested {
						t.Fatal("activation setup failed")
					}
					if state, err := f.run(t.Context()); err != nil || state != directReconcileActivationObserved {
						t.Fatal("activation observation setup failed")
					}
					before, err := readPassJournal(f.f.d.nativeRegistry)
					if err != nil {
						t.Fatal(err)
					}
					clear(before.Root)
					if kind == "changed" {
						f.client.enrollment.Activation.ActivatedAt = f.client.enrollment.Activation.ActivatedAt.Add(time.Nanosecond)
					} else {
						f.client.enrollment.Activation = nil
					}
					f.client.enrollment.ObservedAt = time.Now().UTC()
					state, err := f.run(t.Context())
					if err == nil || state != "" || len(f.client.activations) != 1 {
						t.Fatal("changed or disappeared activation was renewed")
					}
					after, err := readPassJournal(f.f.d.nativeRegistry)
					if err != nil {
						t.Fatal(err)
					}
					clear(after.Root)
					if !bytes.Equal(before.Activation, after.Activation) {
						t.Fatal("immutable activation changed")
					}
				})
			}
		})
	}
}
func TestDirectReconcileActivationHTTPStatuses(t *testing.T) {
	for _, role := range []string{"S", "P"} {
		t.Run(role, func(t *testing.T) {
			for _, status := range []int{404, 409, 503} {
				t.Run(strconv.Itoa(status), func(t *testing.T) {
					for _, read := range []bool{false, true} {
						t.Run(map[bool]string{false: "POST", true: "GET"}[read], func(t *testing.T) {
							f := newActivationPassFixture(t, role)
							kind := directhttp.Unavailable
							if status == 409 {
								kind = directhttp.Conflict
							}
							if status == 503 {
								kind = directhttp.ServiceUnavailable
							}
							unknown := !read && status == 503
							failure := &directhttp.Error{Kind: kind, Status: status, UnknownCommit: unknown}
							if read {
								f.client.fail = "enrollment"
								f.client.reconcileObservationReader.failure = failure
							} else {
								f.client.activationErr = failure
								f.client.rejectActivation = true
							}
							state, err := f.run(t.Context())
							var wire *directhttp.Error
							if state != "" || !errors.As(err, &wire) || wire.Kind != kind || wire.Status != status || wire.UnknownCommit != unknown {
								t.Fatal("HTTP status was inferred as absence or awaiting peer")
							}
							want := 1
							if read {
								want = 0
							}
							if len(f.client.activations) != want {
								t.Fatal("HTTP status caused extra mutation")
							}
						})
					}
				})
			}
		})
	}
}
func TestDirectReconcileActivationUnknownHTTP(t *testing.T) {
	for _, role := range []string{"S", "P"} {
		t.Run(role, func(t *testing.T) {
			for _, accepted := range []bool{false, true} {
				t.Run(map[bool]string{false: "not accepted", true: "accepted"}[accepted], func(t *testing.T) {
					f := newActivationPassFixture(t, role)
					f.client.rejectActivation = !accepted
					f.client.activationErr = &directhttp.Error{Kind: directhttp.ServiceUnavailable, Status: 503, UnknownCommit: true}
					state, err := f.run(t.Context())
					var wire *directhttp.Error
					if state != "" || !errors.As(err, &wire) || !wire.UnknownCommit || len(f.client.activations) != 1 {
						t.Fatal("activation uncertainty lost")
					}
					f.client.activationErr = nil
					f.client.rejectActivation = false
					state, err = f.run(t.Context())
					if err != nil {
						t.Fatal(err)
					}
					if accepted {
						if state != directReconcileActivationObserved || len(f.client.activations) != 1 {
							t.Fatal("accepted activation resent")
						}
					} else if state != directReconcileActivationRequested || len(f.client.activations) != 2 {
						t.Fatal("confirmed absence did not recover activation fence")
					}
					if len(f.client.proofs) != 1 {
						t.Fatal("activation recovery resent proof")
					}
				})
			}
		})
	}
}
func TestDirectReconcileActivationUnknownCommit(t *testing.T) {
	for _, role := range []string{"S", "P"} {
		t.Run(role, func(t *testing.T) {
			for _, stage := range []string{"absence", "dispatch", "observed"} {
				t.Run(stage, func(t *testing.T) {
					for _, committed := range []bool{false, true} {
						t.Run(map[bool]string{false: "rollback", true: "commit"}[committed], func(t *testing.T) {
							f := newActivationPassFixture(t, role)
							sent := 0
							if stage == "observed" {
								if state, err := f.run(t.Context()); err != nil || state != directReconcileActivationRequested {
									t.Fatal("activation setup failed")
								}
								sent = 1
							}
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
										attempt, exists := row.Attempts["activation"]
										switch stage {
										case "absence":
											pending = exists && attempt.Count == attempt.Recovered
										case "dispatch":
											pending = attempt.Count > attempt.Recovered
										case "observed":
											pending = len(row.Activation) > 0
										}
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
									return nil, errors.New("lost activation acknowledgement")
								}
								return next.ExecContext(ctx, query, args)
							}
							state, err := f.run(t.Context())
							connector.exec = nil
							if err == nil || state != "" || !injected || len(f.client.activations) != sent {
								t.Fatal("uncertain activation COMMIT reached HTTP")
							}
							state, err = f.run(t.Context())
							if err != nil {
								t.Fatal(err)
							}
							if stage == "observed" {
								if state != directReconcileActivationObserved || len(f.client.activations) != 1 {
									t.Fatal("activation observation was not recovered")
								}
							} else if state != directReconcileActivationRequested || len(f.client.activations) != 1 {
								t.Fatal("fresh absence did not recover activation dispatch")
							}
						})
					}
				})
			}
		})
	}
}

func TestDirectReconcileActivationMutationAcceptance(t *testing.T) {
	for _, role := range []string{"S", "P"} {
		t.Run(role, func(t *testing.T) {
			for _, kind := range []string{"channel", "before receipt", "future", "expiry", "offset", "opaque", "cancel", "abort", "revoke"} {
				t.Run(kind, func(t *testing.T) {
					f := newActivationPassFixture(t, role)
					ctx, cancel := context.WithCancel(t.Context())
					defer cancel()
					f.client.rejectActivation = true
					switch kind {
					case "channel":
						f.client.activationResponse = func(v directhttp.Activation) directhttp.Activation {
							v.ChannelID = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32))
							return v
						}
					case "before receipt":
						f.client.activationResponse = func(v directhttp.Activation) directhttp.Activation {
							v.ActivatedAt = f.client.enrollment.Proof.ReceivedAt.Add(-time.Nanosecond)
							return v
						}
					case "future":
						f.client.activationResponse = func(v directhttp.Activation) directhttp.Activation {
							v.ActivatedAt = time.Now().UTC().Add(time.Second)
							return v
						}
					case "expiry":
						f.client.activationResponse = func(v directhttp.Activation) directhttp.Activation {
							v.ExpiresAt = v.ExpiresAt.Add(-time.Nanosecond)
							return v
						}
					case "offset":
						f.client.activationResponse = func(v directhttp.Activation) directhttp.Activation {
							v.ActivatedAt = v.ActivatedAt.In(time.FixedZone("offset", 3600))
							return v
						}
					case "opaque":
						f.client.activationErr = errors.New("untrusted activation details")
					case "cancel":
						f.client.onActivate = func(context.Context) { cancel() }
						f.client.activationErr = &directhttp.Error{Kind: directhttp.Conflict, Status: 409}
					case "abort":
						f.client.onActivate = func(context.Context) { f.f.token.proxy.abort() }
						f.client.activationErr = &directhttp.Error{Kind: directhttp.Conflict, Status: 409}
					case "revoke":
						f.client.onActivate = func(context.Context) { f.f.s.Remove() }
						f.client.activationErr = &directhttp.Error{Kind: directhttp.Conflict, Status: 409}
					}
					state, err := f.run(ctx)
					if state != "" || len(f.client.activations) != 1 {
						t.Fatal("activation mutation did not end pass")
					}
					var wire *directhttp.Error
					switch kind {
					case "channel", "before receipt", "future", "expiry", "offset":
						if !errors.As(err, &wire) || wire.Kind != directhttp.Protocol || !wire.UnknownCommit {
							t.Fatal("invalid activation response accepted")
						}
					default:
						if err != errDirectEndpointOperationUnknown || errors.As(err, &wire) {
							t.Fatal("uncertain activation exposed known rollback")
						}
					}
				})
			}
		})
	}
}
func TestDirectReconcileActivationCommitBoundary(t *testing.T) {
	for _, role := range []string{"S", "P"} {
		t.Run(role, func(t *testing.T) {
			for _, kind := range []string{"expiry", "cancel", "abort", "revoke"} {
				t.Run(kind, func(t *testing.T) {
					f := newActivationPassFixture(t, role)
					expires, _ := time.Parse(time.RFC3339Nano, f.binding.Descriptor.ExpiresAt)
					var expired atomic.Bool
					setProofPassClock(t, f, func() time.Time {
						if expired.Load() {
							return expires.Add(time.Nanosecond)
						}
						return time.Now()
					})
					journal, err := newDirectEnrollmentJournal(f.f.d.nativeRegistry)
					if err != nil {
						t.Fatal(err)
					}
					connector := enrollmentContextWrap(t, journal)
					ctx, cancel := context.WithCancel(t.Context())
					defer cancel()
					pending, triggered := false, false
					connector.exec = func(ctx context.Context, query string, args []driver.NamedValue, next driver.ExecerContext) (driver.Result, error) {
						if strings.HasPrefix(query, "INSERT INTO native_direct_enrollment_v1 VALUES") {
							var row directEnrollmentRecord
							if json.Unmarshal(args[3].Value.([]byte), &row) == nil {
								pending = row.Attempts["activation"].Count > row.Attempts["activation"].Recovered
							}
							clear(row.Root)
						}
						if query == "COMMIT" && pending && !triggered {
							if _, err := next.ExecContext(ctx, query, args); err != nil {
								return nil, err
							}
							triggered = true
							switch kind {
							case "expiry":
								expired.Store(true)
							case "cancel":
								cancel()
							case "abort":
								f.f.token.proxy.abort()
							case "revoke":
								f.f.s.Remove()
							}
							return nil, nil
						}
						return next.ExecContext(ctx, query, args)
					}
					state, err := f.run(ctx)
					connector.exec = nil
					want := errDirectEndpointOperationUnknown
					if kind == "expiry" {
						want = errDirectEndpointReconcileBinding
					}
					if err != want || state != "" || !triggered || len(f.client.activations) != 0 {
						t.Fatalf("activation dispatch crossed boundary: %s %v", state, err)
					}
					row, err := readPassJournal(f.f.d.nativeRegistry)
					if err != nil {
						t.Fatal(err)
					}
					clear(row.Root)
					if row.Attempts["activation"].Count != 1 || row.ProofReceivedAt == "" || len(row.Activation) != 0 {
						t.Fatal("committed activation attempt not retained")
					}
				})
			}
		})
	}
}
func TestDirectReconcileActivationDeadlineAndGate(t *testing.T) {
	for _, role := range []string{"S", "P"} {
		t.Run(role, func(t *testing.T) {
			f := newActivationPassFixture(t, role)
			expired, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
			defer cancel()
			if state, err := f.run(expired); state != "" || err != context.DeadlineExceeded || len(f.client.activations) != 0 {
				t.Fatal("expired caller deadline reached activation")
			}
			entered, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			defer unblock()
			var reentrant error
			f.client.onActivate = func(ctx context.Context) { _, reentrant = f.run(ctx); close(entered); <-release }
			type passResult struct {
				state directEndpointReconcilePassState
				err   error
			}
			finished := make(chan passResult, 1)
			go func() { state, err := f.run(t.Context()); finished <- passResult{state, err} }()
			select {
			case <-entered:
			case result := <-finished:
				t.Fatalf("activation POST missing: %s %v", result.state, result.err)
			case <-time.After(10 * time.Second):
				t.Fatal("activation POST not reached")
			}
			if state, err := f.run(t.Context()); state != "" || err != errDirectEndpointLocalBusy {
				t.Error("concurrent activation bypassed gate")
			}
			unblock()
			result := <-finished
			if result.err != nil || result.state != directReconcileActivationRequested || reentrant != errDirectEndpointLocalBusy || len(f.client.activations) != 1 {
				t.Fatal("activation single mutation gate failed")
			}
		})
	}
}
