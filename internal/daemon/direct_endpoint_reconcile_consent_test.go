//go:build linux || darwin

package daemon

import (
	"reflect"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/transport"
)

func reconcilePassConsent(t *testing.T, f *reconcilePassFixture) (string, directChannelConsentRecord) {
	t.Helper()
	installation := string(f.f.s.binding.metadata.InstallationID)
	binding, err := deriveDirectChannelConsentBinding(f.f.s, f.f.captured, installation, f.binding, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return installation, directChannelConsentRecord{Key: binding.Key, Revision: 7, Enabled: true, Binding: &binding}
}

func consentPass(t *testing.T, f *reconcilePassFixture, installation string, record directChannelConsentRecord, revision int64) directEndpointReconcilePass {
	t.Helper()
	var run directEndpointReconcilePass
	var err error
	if f.f.role == "S" {
		run, err = newDirectSourceReconcilePassWithConsentAndClient(f.f.d, f.f.captured, f.f.s, f.f.source, installation, record, revision, f.client, time.Now)
	} else {
		run, err = newDirectTargetReconcilePassWithConsentAndClient(f.f.d, f.f.captured, f.f.s, f.f.target, installation, record, revision, f.client, time.Now)
	}
	if err != nil {
		t.Fatal(err)
	}
	return run
}

func assertConsentPassRejected(t *testing.T, f *reconcilePassFixture, run directEndpointReconcilePass) {
	t.Helper()
	state, err := run(t.Context())
	if state != "" || err == nil {
		t.Fatalf("consent accepted: %s %v", state, err)
	}
	if f.f.role == "S" && err != errDirectChannelConsent {
		t.Fatalf("source evidence did not reach consent gate: %v", err)
	}
	if len(f.client.publications)+len(f.client.challenges)+len(f.client.proofs)+len(f.client.activations) != 0 || passJournalTableCount(t, f.f.d.nativeRegistry) != 0 {
		t.Fatal("rejected consent reached mutation or journal material")
	}
	if !reflect.DeepEqual(f.client.calls, []string{"descriptor", "enrollment"}) {
		t.Fatalf("unexpected reads: %v", f.client.calls)
	}
}

func TestDirectReconcileConsentPassRolesAndSnapshots(t *testing.T) {
	for _, role := range []string{"S", "P"} {
		t.Run(role, func(t *testing.T) {
			f := newReconcilePassFixture(t, role)
			installation, record := reconcilePassConsent(t, f)
			run := consentPass(t, f, installation, record, 7)
			record.Binding.Epoch = "caller mutation"
			record.Enabled = false
			f.f.captured.Session.ProtocolFeatures[0] = "caller mutation"
			f.f.source = transport.DirectManagedSourceCredentialIssueV2{}
			f.f.target = transport.ManagedDirectCredentialIssue{}
			state, err := run(t.Context())
			want := directReconcilePublicationPublished
			calls := []string{"descriptor", "enrollment", "publish"}
			if role == "P" {
				want = directReconcileAwaitingPublication
				calls = calls[:2]
			}
			if err != nil || state != want {
				t.Fatalf("matching consent: %s %v", state, err)
			}
			if !reflect.DeepEqual(f.client.calls, calls) {
				t.Fatalf("extra observation: %v", f.client.calls)
			}
		})
	}
}

func TestDirectReconcileConsentPassRejects(t *testing.T) {
	for _, role := range []string{"S", "P"} {
		for _, kind := range []string{"missing", "disabled", "stale", "foreign key", "foreign installation", "revoked", "epoch", "digest", "expiry"} {
			t.Run(role+"/"+kind, func(t *testing.T) {
				f := newReconcilePassFixture(t, role)
				installation, record := reconcilePassConsent(t, f)
				switch kind {
				case "missing":
					record = directChannelConsentRecord{}
				case "disabled":
					record.Enabled = false
				case "stale":
					record.Revision++
				case "foreign key":
					record.Key.Host = "foreign"
				case "foreign installation":
					installation = "foreign"
				case "revoked":
					record.Enabled = false
					record.Revision++
				case "epoch":
					record.Binding.Epoch = "foreign"
				case "digest":
					record.Binding.AuthorizationSnapshotDigest = "foreign"
				case "expiry":
					record.Binding.ExpiresAt = time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano)
				}
				assertConsentPassRejected(t, f, consentPass(t, f, installation, record, 7))
			})
		}
	}
}

func TestDirectReconcileConsentPassLaterObservationDrift(t *testing.T) {
	for _, role := range []string{"S", "P"} {
		for _, kind := range []string{"epoch", "digest", "expiry"} {
			t.Run(role+"/"+kind, func(t *testing.T) {
				f := newReconcilePassFixture(t, role)
				installation, record := reconcilePassConsent(t, f)
				run := consentPass(t, f, installation, record, 7)
				d := f.client.descriptor
				switch kind {
				case "epoch":
					d.EpochID = "01900000-0000-7000-8000-000000000098"
				case "digest":
					d.AuthorizationDigest = "abababababababababababababababababababababababababababababababab"
				case "expiry":
					expiry, _ := time.Parse(time.RFC3339Nano, d.ExpiresAt)
					d.ExpiresAt = expiry.Add(-time.Second).UTC().Format(time.RFC3339Nano)
				}
				// Keep the GET descriptor and enrollment internally consistent, so the
				// consent gate compares the new evidence with its captured opt-in binding.
				f.client.descriptor = d
				f.client.enrollment = reconcileEnrollment(t, d, time.Now())
				assertConsentPassRejected(t, f, run)
			})
		}
	}
}

func TestDirectReconcileConsentObserverReturnsNoRejectedObservation(t *testing.T) {
	f := newReconcilePassFixture(t, "S")
	installation, record := reconcilePassConsent(t, f)
	record.Enabled = false
	observe, err := newDirectSourceReconcileObserverWithReader(f.f.d, f.f.captured, f.f.s, f.f.source, f.client, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	wrap, err := directReconcileConsentObserverWrapper(f.f.captured, f.f.s, installation, record, 7, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	result, err := wrap(observe)(t.Context())
	if err != errDirectChannelConsent {
		t.Fatal("consent rejection lost")
	}
	assertZeroObservation(t, result)
	for _, revision := range []int64{0, -1} {
		if _, err := directReconcileConsentObserverWrapper(f.f.captured, f.f.s, installation, record, revision, time.Now); err != errDirectChannelConsent {
			t.Fatal("nonpositive revision accepted")
		}
	}
}

func TestDirectReconcileConsentPassRechecksEveryInvocation(t *testing.T) {
	for _, role := range []string{"S", "P"} {
		t.Run(role, func(t *testing.T) {
			f := newReconcilePassFixture(t, role)
			installation, record := reconcilePassConsent(t, f)
			run := consentPass(t, f, installation, record, 7)
			if _, err := run(t.Context()); err != nil {
				t.Fatal(err)
			}
			var before directEnrollmentRecord
			if role == "S" {
				var err error
				before, err = readPassJournal(f.f.d.nativeRegistry)
				if err != nil {
					t.Fatal(err)
				}
				defer clear(before.Root)
			}
			mutations := len(f.client.publications) + len(f.client.challenges) + len(f.client.proofs) + len(f.client.activations)
			f.client.calls = nil
			d := f.client.descriptor
			expiry, _ := time.Parse(time.RFC3339Nano, d.ExpiresAt)
			d.ExpiresAt = expiry.Add(-time.Second).UTC().Format(time.RFC3339Nano)
			f.client.descriptor = d
			f.client.enrollment = reconcileEnrollment(t, d, time.Now())
			state, err := run(t.Context())
			if state != "" || err != errDirectChannelConsent {
				t.Fatalf("later evidence accepted: %s %v", state, err)
			}
			if mutations != len(f.client.publications)+len(f.client.challenges)+len(f.client.proofs)+len(f.client.activations) {
				t.Fatal("rejected later evidence reached remote mutation")
			}
			if !reflect.DeepEqual(f.client.calls, []string{"descriptor", "enrollment"}) {
				t.Fatalf("extra reads: %v", f.client.calls)
			}
			if role == "S" {
				after, err := readPassJournal(f.f.d.nativeRegistry)
				if err != nil {
					t.Fatal(err)
				}
				defer clear(after.Root)
				if !reflect.DeepEqual(before, after) {
					t.Fatal("rejected later evidence changed material or journal")
				}
			} else if passJournalTableCount(t, f.f.d.nativeRegistry) != 0 {
				t.Fatal("rejected later evidence created journal")
			}
		})
	}
}
