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
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/internal/directchannelcrypto"
	"github.com/pagnet-code/pagnet/internal/directhttp"
	"github.com/pagnet-code/pagnet/transport"
)

func newProofPassFixture(t *testing.T, role string) *reconcilePassFixture {
	t.Helper()
	f := newReadinessPassFixture(t, role)
	publication, _ := f.client.publication.CanonicalBytes()
	setReadinessGET(t, f, passReadinessChallenge(f.binding, publication, role, time.Now().Add(-time.Second)))
	return f
}
func setProofPassClock(t *testing.T, f *reconcilePassFixture, now func() time.Time) {
	t.Helper()
	var err error
	if f.f.role == "S" {
		f.run, err = newDirectSourceReconcilePassWithClient(f.f.d, f.f.captured, f.f.s, f.f.source, f.client, now)
	} else {
		f.run, err = newDirectTargetReconcilePassWithClient(f.f.d, f.f.captured, f.f.s, f.f.target, f.client, now)
	}
	if err != nil {
		t.Fatal(err)
	}
}
func passMaterial(t *testing.T, f *reconcilePassFixture) *directchannelcrypto.Material {
	t.Helper()
	operation, err := f.f.factory()
	if err != nil {
		t.Fatal(err)
	}
	var material *directchannelcrypto.Material
	if f.f.role == "S" {
		material, _, err = acquireDirectSourceReconcileMaterial(t.Context(), f.f.s, f.binding, f.client.enrollment, f.f.d.nativeRegistry, time.Now, operation)
	} else {
		wire, _ := f.client.publication.CanonicalBytes()
		material, _, err = acquireDirectTargetReconcileMaterial(t.Context(), f.f.s, f.binding, f.client.enrollment, wire, f.f.d.nativeRegistry, time.Now, operation)
	}
	if err != nil {
		t.Fatal(err)
	}
	return material
}
func TestDirectReconcileProofSubmitAndReceipt(t *testing.T) {
	for _, role := range []string{"S", "P"} {
		t.Run(role, func(t *testing.T) {
			f := newProofPassFixture(t, role)
			state, err := f.run(t.Context())
			if err != nil || state != directReconcileProofSubmitted || len(f.client.proofs) != 1 || len(f.client.challenges) != 0 {
				t.Fatalf("proof submit: %s %v", state, err)
			}
			row, err := readPassJournal(f.f.d.nativeRegistry)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(row.Root)
			if !bytes.Equal(row.Proof, f.client.proofs[0]) || row.ProofReceivedAt != "" || len(row.Activation) != 0 {
				t.Fatal("PUT response was treated as authenticated receipt")
			}
			state, err = f.run(t.Context())
			if err != nil || state != directReconcileProofObserved || len(f.client.proofs) != 1 {
				t.Fatalf("proof receipt: %s %v", state, err)
			}
			observed, err := readPassJournal(f.f.d.nativeRegistry)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(observed.Root)
			if observed.ProofReceivedAt != f.client.enrollment.Proof.ReceivedAt.UTC().Format(time.RFC3339Nano) || !bytes.Equal(row.Proof, observed.Proof) || !bytes.Equal(row.Root, observed.Root) || len(observed.Activation) != 0 {
				t.Fatal("receipt changed immutable state or activated")
			}
		})
	}
}
func TestDirectReconcileProofUnknownHTTP(t *testing.T) {
	for _, role := range []string{"S", "P"} {
		t.Run(role, func(t *testing.T) {
			for _, accepted := range []bool{false, true} {
				t.Run(map[bool]string{false: "not accepted", true: "accepted"}[accepted], func(t *testing.T) {
					f := newProofPassFixture(t, role)
					f.client.rejectProof = !accepted
					f.client.proveErr = &directhttp.Error{Kind: directhttp.Transport, UnknownCommit: true}
					state, err := f.run(t.Context())
					var wire *directhttp.Error
					if state != "" || !errors.As(err, &wire) || !wire.UnknownCommit || len(f.client.proofs) != 1 {
						t.Fatal("proof mutation uncertainty lost")
					}
					original := bytes.Clone(f.client.proofs[0])
					f.client.rejectProof = false
					f.client.proveErr = nil
					state, err = f.run(t.Context())
					if err != nil {
						t.Fatal(err)
					}
					if accepted {
						if state != directReconcileProofObserved || len(f.client.proofs) != 1 {
							t.Fatal("accepted proof resent")
						}
					} else if state != directReconcileProofSubmitted || len(f.client.proofs) != 2 || !bytes.Equal(original, f.client.proofs[1]) {
						t.Fatal("proof retry changed exact bytes")
					}
				})
			}
		})
	}
}
func seedRetainedProof(t *testing.T, f *reconcilePassFixture, challenge transport.DirectChannelReadinessChallengeV2, received time.Time) []byte {
	t.Helper()
	setReadinessGET(t, f, challenge)
	raw, _ := challenge.CanonicalBytes()
	material := passMaterial(t, f)
	defer material.Clear()
	proof, err := material.ReadinessProof(raw, string(f.f.s.binding.metadata.CredentialID), received)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := enrollmentBinding(f.f.s, f.binding.Protocol, f.binding.DescriptorBytes, f.binding.LocalFingerprint, f.binding.PeerFingerprint)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := newDirectEnrollmentJournal(f.f.d.nativeRegistry)
	if err != nil {
		t.Fatal(err)
	}
	row, err := journal.bindProofContext(t.Context(), f.f.s, binding, raw, proof)
	clear(row.Root)
	if err != nil {
		t.Fatal(err)
	}
	row, err = journal.observeAbsentContext(t.Context(), f.f.s, binding, "proof")
	clear(row.Root)
	if err != nil {
		t.Fatal(err)
	}
	row, err = journal.markDispatchContext(t.Context(), f.f.s, binding, "proof")
	clear(row.Root)
	if err != nil {
		t.Fatal(err)
	}
	return proof
}
func TestDirectReconcileProofExpiredChallengeReceipt(t *testing.T) {
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
						if err != nil || state != directReconcileProofObserved {
							t.Fatalf("historical receipt rejected: %s %v", state, err)
						}
					} else if err != errDirectEndpointReconcileChallengeExpired || state != "" {
						t.Fatal("expired challenge generated proof")
					}
					if len(f.client.proofs) != 0 || len(f.client.challenges) != 0 {
						t.Fatal("expired challenge sent a mutation")
					}
					row, err := readPassJournal(f.f.d.nativeRegistry)
					if err != nil {
						t.Fatal(err)
					}
					clear(row.Root)
					if !bytes.Equal(row.Proof, proof) || len(row.Activation) != 0 {
						t.Fatal("expired proof receipt changed state")
					}
				})
			}
		})
	}
}
func TestDirectReconcileProofReceiptFailClosed(t *testing.T) {
	for _, role := range []string{"S", "P"} {
		t.Run(role, func(t *testing.T) {
			for _, kind := range []string{"missing local proof", "digest", "received time", "disappeared receipt", "changed receipt", "challenge binding"} {
				t.Run(kind, func(t *testing.T) {
					f := newProofPassFixture(t, role)
					if kind == "missing local proof" {
						raw, _ := f.client.enrollment.Challenge.Challenge.CanonicalBytes()
						material := passMaterial(t, f)
						proof, err := material.ReadinessProof(raw, string(f.f.s.binding.metadata.CredentialID), time.Now())
						material.Clear()
						if err != nil {
							t.Fatal(err)
						}
						digest := sha256.Sum256(proof)
						f.client.enrollment.Proof = &directhttp.EnrollmentProof{Digest: base64.RawURLEncoding.EncodeToString(digest[:]), ReceivedAt: time.Now().UTC()}
						f.client.enrollment.ObservedAt = time.Now().UTC()
					} else {
						if state, err := f.run(t.Context()); err != nil || state != directReconcileProofSubmitted {
							t.Fatal("proof setup failed")
						}
						if state, err := f.run(t.Context()); err != nil || state != directReconcileProofObserved {
							t.Fatal("receipt setup failed")
						}
						switch kind {
						case "digest":
							f.client.enrollment.Proof.Digest = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
						case "received time":
							f.client.enrollment.Proof.ReceivedAt = time.Now().Add(time.Hour)
						case "disappeared receipt":
							f.client.enrollment.Proof = nil
						case "changed receipt":
							f.client.enrollment.Proof.ReceivedAt = f.client.enrollment.Proof.ReceivedAt.Add(time.Nanosecond)
						case "challenge binding":
							c := f.client.enrollment.Challenge.Challenge
							c.EndpointID = string(f.f.s.binding.metadata.IntentID)
							setReadinessGET(t, f, c)
						}
						f.client.enrollment.ObservedAt = time.Now().UTC()
					}
					sent := len(f.client.proofs)
					state, err := f.run(t.Context())
					if err == nil || state != "" || len(f.client.proofs) != sent {
						t.Fatal("invalid receipt authorized resend")
					}
					if kind == "missing local proof" && err != errDirectEndpointReconcileProofMissing {
						t.Fatalf("missing proof not distinguished: %v", err)
					}
					if kind == "missing local proof" {
						row, readErr := readPassJournal(f.f.d.nativeRegistry)
						clear(row.Root)
						if readErr != nil || len(row.Proof) != 0 || row.ProofReceivedAt != "" {
							t.Fatal("missing local proof was reconstructed from receipt")
						}
					}

				})
			}
		})
	}
}
func TestDirectReconcileProofUnknownCommit(t *testing.T) {
	for _, role := range []string{"S", "P"} {
		t.Run(role, func(t *testing.T) {
			for _, stage := range []string{"challenge", "proof", "dispatch"} {
				t.Run(stage, func(t *testing.T) {
					for _, committed := range []bool{false, true} {
						t.Run(map[bool]string{false: "rollback", true: "commit"}[committed], func(t *testing.T) {
							f := newProofPassFixture(t, role)
							journal, err := newDirectEnrollmentJournal(f.f.d.nativeRegistry)
							if err != nil {
								t.Fatal(err)
							}
							connector := enrollmentContextWrap(t, journal)
							pending, injected := false, false
							var selected []byte
							connector.exec = func(ctx context.Context, query string, args []driver.NamedValue, next driver.ExecerContext) (driver.Result, error) {
								if strings.HasPrefix(query, "INSERT INTO native_direct_enrollment_v1 VALUES") {
									var row directEnrollmentRecord
									if json.Unmarshal(args[3].Value.([]byte), &row) == nil {
										attempt := row.Attempts["proof"]
										switch stage {
										case "challenge":
											pending = len(row.Challenge) > 0 && len(row.Proof) == 0
										case "proof":
											pending = len(row.Proof) > 0 && attempt.Count == 0
										case "dispatch":
											pending = attempt.Count > attempt.Recovered
										}
										if len(row.Proof) > 0 {
											selected = bytes.Clone(row.Proof)
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
									return nil, errors.New("lost proof stage acknowledgement")
								}
								return next.ExecContext(ctx, query, args)
							}
							state, err := f.run(t.Context())
							connector.exec = nil
							if err == nil || state != "" || !injected || len(f.client.proofs) != 0 {
								t.Fatal("uncertain local COMMIT reached proof HTTP")
							}
							state, err = f.run(t.Context())
							if err != nil || state != directReconcileProofSubmitted || len(f.client.proofs) != 1 {
								t.Fatalf("fresh proof recovery failed: %s %v", state, err)
							}
							if len(selected) > 0 && !bytes.Equal(selected, f.client.proofs[0]) {
								t.Fatal("unknown COMMIT regenerated proof bytes")
							}
						})
					}
				})
			}
		})
	}
}

func TestDirectReconcileProofMutationAcceptance(t *testing.T) {
	for _, role := range []string{"S", "P"} {
		t.Run(role, func(t *testing.T) {
			for _, kind := range []string{"response mismatch", "known rollback", "opaque", "cancel", "abort"} {
				t.Run(kind, func(t *testing.T) {
					f := newProofPassFixture(t, role)
					ctx, cancel := context.WithCancel(t.Context())
					defer cancel()
					f.client.rejectProof = true
					switch kind {
					case "response mismatch":
						f.client.proofResponse = func(p transport.DirectChannelReadinessProofV2) transport.DirectChannelReadinessProofV2 {
							p.Confirmation = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32))
							return p
						}
					case "known rollback":
						f.client.proveErr = &directhttp.Error{Kind: directhttp.Conflict, Status: 409, UnknownCommit: false}
					case "opaque":
						f.client.proveErr = errors.New("untrusted writer details")
					case "cancel":
						f.client.onProve = func(context.Context) { cancel() }
						f.client.proveErr = &directhttp.Error{Kind: directhttp.Conflict, Status: 409}
					case "abort":
						f.client.onProve = func(context.Context) { f.f.token.proxy.abort() }
						f.client.proveErr = &directhttp.Error{Kind: directhttp.Conflict, Status: 409}
					}
					state, err := f.run(ctx)
					if state != "" || len(f.client.proofs) != 1 {
						t.Fatal("proof mutation did not end pass")
					}
					var mutation *directhttp.Error
					switch kind {
					case "response mismatch":
						if !errors.As(err, &mutation) || mutation.Kind != directhttp.Protocol || !mutation.UnknownCommit {
							t.Fatal("changed proof response was accepted")
						}
					case "known rollback":
						if !errors.As(err, &mutation) || mutation.UnknownCommit || mutation.Status != 409 {
							t.Fatal("known rollback disposition changed")
						}
					default:
						if err != errDirectEndpointOperationUnknown || errors.As(err, &mutation) {
							t.Fatal("uncertain proof exposed known rollback")
						}
					}
				})
			}
		})
	}
}
func TestDirectReconcileProofCommitBoundary(t *testing.T) {
	for _, role := range []string{"S", "P"} {
		t.Run(role, func(t *testing.T) {
			for _, kind := range []string{"expiry", "cancel", "abort"} {
				t.Run(kind, func(t *testing.T) {
					f := newProofPassFixture(t, role)
					expiry, _ := time.Parse(time.RFC3339Nano, f.client.enrollment.Challenge.Challenge.ExpiresAt)
					var expired atomic.Bool
					setProofPassClock(t, f, func() time.Time {
						if expired.Load() {
							return expiry.Add(time.Nanosecond)
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
								pending = row.Attempts["proof"].Count > row.Attempts["proof"].Recovered
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
							}
							return nil, nil
						}
						return next.ExecContext(ctx, query, args)
					}
					state, err := f.run(ctx)
					connector.exec = nil
					want := errDirectEndpointOperationUnknown
					if kind == "expiry" {
						want = errDirectEndpointReconcileChallengeExpired
					}
					if err != want || state != "" || !triggered || len(f.client.proofs) != 0 {
						t.Fatalf("proof dispatch crossed boundary: %s %v", state, err)
					}
					row, err := readPassJournal(f.f.d.nativeRegistry)
					if err != nil {
						t.Fatal(err)
					}
					clear(row.Root)
					if len(row.Proof) == 0 || row.Attempts["proof"].Count != 1 || row.ProofReceivedAt != "" {
						t.Fatal("committed exact proof attempt not retained")
					}
				})
			}
		})
	}
}
func TestDirectReconcileProofConcurrency(t *testing.T) {
	for _, role := range []string{"S", "P"} {
		t.Run(role, func(t *testing.T) {
			f := newProofPassFixture(t, role)
			entered, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			defer unblock()
			var reentrant error
			f.client.onProve = func(ctx context.Context) { _, reentrant = f.run(ctx); close(entered); <-release }
			type passResult struct {
				state directEndpointReconcilePassState
				err   error
			}
			finished := make(chan passResult, 1)
			go func() { state, err := f.run(t.Context()); finished <- passResult{state, err} }()
			select {
			case <-entered:
			case result := <-finished:
				t.Fatalf("proof PUT missing: %s %v", result.state, result.err)
			case <-time.After(10 * time.Second):
				t.Fatal("proof PUT not reached")
			}
			if state, err := f.run(t.Context()); state != "" || err != errDirectEndpointLocalBusy {
				t.Error("concurrent proof bypassed gate")
			}
			unblock()
			result := <-finished
			if result.err != nil || result.state != directReconcileProofSubmitted || reentrant != errDirectEndpointLocalBusy || len(f.client.proofs) != 1 {
				t.Fatal("proof single mutation gate failed")
			}
		})
	}
}

func TestDirectReconcileProofReceiptRejectsRetainedMAC(t *testing.T) {
	for _, role := range []string{"S", "P"} {
		t.Run(role, func(t *testing.T) {
			f := newProofPassFixture(t, role)
			raw, _ := f.client.enrollment.Challenge.Challenge.CanonicalBytes()
			material := passMaterial(t, f)
			proof, err := material.ReadinessProof(raw, string(f.f.s.binding.metadata.CredentialID), time.Now())
			material.Clear()
			if err != nil {
				t.Fatal(err)
			}
			value, err := transport.DecodeDirectChannelReadinessProofV2(proof)
			if err != nil {
				t.Fatal(err)
			}
			value.Confirmation = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
			bad, _ := value.CanonicalBytes()
			binding, err := enrollmentBinding(f.f.s, f.binding.Protocol, f.binding.DescriptorBytes, f.binding.LocalFingerprint, f.binding.PeerFingerprint)
			if err != nil {
				t.Fatal(err)
			}
			journal, err := newDirectEnrollmentJournal(f.f.d.nativeRegistry)
			if err != nil {
				t.Fatal(err)
			}
			row, err := journal.bindProofContext(t.Context(), f.f.s, binding, raw, bad)
			clear(row.Root)
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(bad)
			received := time.Now().UTC()
			f.client.enrollment.Proof = &directhttp.EnrollmentProof{Digest: base64.RawURLEncoding.EncodeToString(digest[:]), ReceivedAt: received}
			f.client.enrollment.ObservedAt = received
			state, err := f.run(t.Context())
			if err != errDirectEndpointReconcileBinding || state != "" || len(f.client.proofs) != 0 {
				t.Fatal("retained proof accepted by digest without readiness MAC verification")
			}
			row, err = readPassJournal(f.f.d.nativeRegistry)
			if err != nil {
				t.Fatal(err)
			}
			clear(row.Root)
			if row.ProofReceivedAt != "" || !bytes.Equal(row.Proof, bad) {
				t.Fatal("invalid retained proof was repaired or acknowledged")
			}
		})
	}
}
func TestDirectReconcileProofReceiptUnknownCommit(t *testing.T) {
	for _, role := range []string{"S", "P"} {
		t.Run(role, func(t *testing.T) {
			for _, committed := range []bool{false, true} {
				t.Run(map[bool]string{false: "rollback", true: "commit"}[committed], func(t *testing.T) {
					f := newProofPassFixture(t, role)
					if state, err := f.run(t.Context()); err != nil || state != directReconcileProofSubmitted {
						t.Fatal("proof setup failed")
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
								pending = row.ProofReceivedAt != ""
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
							return nil, errors.New("lost proof receipt acknowledgement")
						}
						return next.ExecContext(ctx, query, args)
					}
					state, err := f.run(t.Context())
					connector.exec = nil
					if err == nil || state != "" || !injected || len(f.client.proofs) != 1 {
						t.Fatal("uncertain receipt COMMIT resent proof")
					}
					state, err = f.run(t.Context())
					if err != nil || state != directReconcileProofObserved || len(f.client.proofs) != 1 {
						t.Fatal("fresh GET failed receipt COMMIT recovery")
					}
				})
			}
		})
	}
}
